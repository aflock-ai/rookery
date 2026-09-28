// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"context"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/standards"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	alpsevidence "github.com/aflock-ai/rookery/plugins/attestors/alps-evidence"
	"github.com/spf13/viper"
)

// slsaProvenancePrefix is the predicate-type prefix of SLSA provenance.
const slsaProvenancePrefix = "https://slsa.dev/provenance/"

// detectInvokingAgent reports whether a coding agent is in cilock's process
// ancestry, using the same walk the alps-evidence attestor signs. It is used
// only to choose how next steps are phrased; it never reaches evidence. A
// package var so tests pin the audience without a real process tree.
var detectInvokingAgent = func() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d := alpsevidence.NewDetector(alpsevidence.NewOSProcessSource(), alpsevidence.DefaultProviders())
	d.DigestSizeLimit = 0 // the verdict is all we need; never hash a 300MB agent binary for it
	wd, _ := os.Getwd()
	det, err := d.Detect(ctx, os.Getpid(), wd)
	return err == nil && det.Status == alpsevidence.StatusDetected
}

// runAudience picks agent phrasing when an enrolled agent signed, when the
// run's own alps-evidence attestor detected an agent, or, when that attestor
// was not selected, when a fresh ancestry walk finds one. An alps-evidence
// verdict of not-detected is final: the walk is not repeated to overrule it.
func runAudience(s *options.RunSummary, attestors []attestation.Attestor) string {
	if s.AgentPrincipal != "" {
		return standards.AudienceAgent
	}
	for _, a := range attestors {
		if ae, ok := a.(*alpsevidence.Attestor); ok {
			if ae.Status == alpsevidence.StatusDetected {
				return standards.AudienceAgent
			}
			return standards.AudienceHuman
		}
	}
	if detectInvokingAgent() {
		return standards.AudienceAgent
	}
	return standards.AudienceHuman
}

// runObservations collects what this run actually showed: the signed
// collection's envelope (its leaf and timestamps), the attestor outcomes, and
// the signing path. getenv is consulted for two facts only: whether this is
// CI (which chooses CI-shaped steps) and, when the leaf carries no
// runner-environment extension, whether GitHub reports a hosted runner.
//
// Each signature is its own observation: a timestamp over one signature says
// nothing about when another existed, so a signature's timestamp and leaf are
// never combined with another's. It returns the observation with the highest
// SLSA ceiling and the one with the highest ALPS ceiling, which can differ.
func runObservations(s *options.RunSummary, results []workflow.RunResult, runFailed bool, getenv func(string) string) (slsa, alps standards.Observations) {
	facts := signedCollectionFacts(results)
	cands := make([]standards.Observations, 0, len(facts))
	for _, env := range facts {
		// A certificate names its own principal (the leaf's SANs and
		// issuer), so the run's summary-wide identity never overrides it.
		// The summary identity stands in only for the run's single
		// signature when that signature carries no certificate; beside
		// others, a signature with no certificate is a key's.
		env.runSigner = len(facts) == 1
		cands = append(cands, runObservation(s, env, runFailed, getenv))
	}
	return bestPerStandard(cands)
}

func runObservation(s *options.RunSummary, env envelopeFacts, runFailed bool, getenv func(string) string) standards.Observations {
	var o standards.Observations
	o.Signed = !runFailed && env.signed
	o.Timestamped = env.timestamped
	leaf, hasLeaf := env.leaf, env.hasLeaf
	for _, a := range s.Attestors {
		if a.Name == "slsa" && a.Status == options.AttestorStatusRan {
			o.Provenance = true
		}
	}
	o.Principal = runPrincipal(s, leaf, hasLeaf, env.runSigner)
	gha := getenv("GITHUB_ACTIONS") == envTrue
	// The leaf is the authority on the runner; the GitHub job environment is a
	// fallback only for a workflow signature whose leaf carries no
	// runner-environment at all. A human's or a key's signature is not the
	// runner's, whatever the job environment says.
	o.HostedRunner = standards.IsProviderHostedRunner(leaf.RunnerEnvironment) ||
		(o.Principal == standards.PrincipalWorkflow && leaf.RunnerEnvironment == "" && gha &&
			getenv("RUNNER_ENVIRONMENT") == standards.RunnerGitHubHosted)
	o.TrustedBuilder = leaf.IsTrustedBuilder()
	o.CIPlatform = leaf.CI
	if o.CIPlatform == "" {
		o.CIPlatform = ciFromEnv(getenv)
	}
	o.CI = o.CIPlatform != "" || getenv("CI") == envTrue || o.Principal == standards.PrincipalWorkflow
	return o
}

// bestPerStandard picks, from per-signer observations, the one supporting the
// highest SLSA ceiling (ALPS breaking ties) and the one supporting the highest
// ALPS ceiling (SLSA breaking ties). A ceiling is an upper bound per standard,
// so each standard is maximised on its own evidence. No candidates gives the
// zero observation (unsigned) for both.
func bestPerStandard(cands []standards.Observations) (slsa, alps standards.Observations) {
	for i, o := range cands {
		if i == 0 || betterSLSA(o, slsa) {
			slsa = o
		}
		if i == 0 || betterALPS(o, alps) {
			alps = o
		}
	}
	return slsa, alps
}

func betterSLSA(a, b standards.Observations) bool {
	sa, sb := standards.DeriveSLSA(a.SLSAEvidence()), standards.DeriveSLSA(b.SLSAEvidence())
	if sa != sb {
		return sa > sb
	}
	return standards.DeriveALPS(a.ALPSEvidence()) > standards.DeriveALPS(b.ALPSEvidence())
}

func betterALPS(a, b standards.Observations) bool {
	aa, ab := standards.DeriveALPS(a.ALPSEvidence()), standards.DeriveALPS(b.ALPSEvidence())
	if aa != ab {
		return aa > ab
	}
	return standards.DeriveSLSA(a.SLSAEvidence()) > standards.DeriveSLSA(b.SLSAEvidence())
}

// ciEnvKeys are the environment variables the guidance reads, each bound to a
// Viper key (the variable's lower-cased name) so they are read through Viper
// and named in code, like GITHUB_ACTIONS in evidenceloss.go.
var ciEnvKeys = []string{"GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "GITLAB_CI", "BUILDKITE", "CIRCLECI",
	"KUBERNETES_SERVICE_HOST", "CI"}

func init() {
	for _, k := range ciEnvKeys {
		// BindEnv only errors on an empty key list, which this call cannot be.
		_ = viper.BindEnv(strings.ToLower(k), k)
	}
}

// viperEnv reads one of ciEnvKeys through its Viper binding. Viper resolves a
// bound variable at read time, so t.Setenv is observed.
func viperEnv(k string) string { return viper.GetString(strings.ToLower(k)) }

// ciFromEnv names the CI platform from the variables each one sets on every
// job. It only selects which steps apply; it never raises a ceiling.
func ciFromEnv(getenv func(string) string) string {
	switch {
	case getenv("GITHUB_ACTIONS") == envTrue:
		return standards.CIGitHub
	case getenv("GITLAB_CI") == envTrue:
		return standards.CIGitLab
	case getenv("BUILDKITE") == envTrue:
		return standards.CIBuildkite
	case getenv("CIRCLECI") == envTrue:
		return standards.CICircleCI
	case getenv("KUBERNETES_SERVICE_HOST") != "":
		return standards.CIKubernetes
	}
	return ""
}

// runPrincipal is who made one signature: a certificate's own SANs and
// issuer; for the run's single certificate-less signature, the
// server-confirmed agent or workflow identity; otherwise a key. The run's
// identity never overrides what a certificate says.
func runPrincipal(s *options.RunSummary, leaf standards.Leaf, hasLeaf, runSigner bool) string {
	switch {
	case hasLeaf:
		return leaf.Principal
	case !runSigner:
		return standards.PrincipalKey
	case s.AgentPrincipal != "":
		return standards.PrincipalAgent
	case s.WorkflowIdentity:
		return standards.PrincipalWorkflow
	case s.Signer != "" && !strings.Contains(s.Signer, "fulcio"):
		return standards.PrincipalKey
	}
	return standards.PrincipalUnknown
}

// envTrue is the value CI systems set boolean environment variables to.
const envTrue = "true"

// envelopeFacts is what one signature on the signed collection's envelope
// shows: that it exists, whether it carries a timestamp, and its signing leaf.
type envelopeFacts struct {
	signed, timestamped, hasLeaf bool
	leaf                         standards.Leaf
	// runSigner: this signature is the run's own, so the run's confirmed
	// identity applies to it (set by runObservations).
	runSigner bool
}

// signedCollectionFacts reads the collection result (empty AttestorName); the
// per-attestor sidecar results are not the collection that was signed. It
// returns one entry per signature, and one unsigned entry when the collection
// carries none (or there is no collection).
func signedCollectionFacts(results []workflow.RunResult) []envelopeFacts {
	for _, r := range results {
		if r.AttestorName != "" {
			continue
		}
		var out []envelopeFacts
		for _, sig := range r.SignedEnvelope.Signatures {
			f := envelopeFacts{signed: true, timestamped: len(sig.Timestamps) > 0}
			if len(sig.Certificate) > 0 {
				f.leaf, f.hasLeaf = standards.LeafFromPEM(sig.Certificate)
			}
			out = append(out, f)
		}
		if len(out) > 0 {
			return out
		}
		break
	}
	return []envelopeFacts{{}}
}

// verifyObservations reads the same facts from what `cilock verify` actually
// verified, never from this machine's environment: each passed collection's
// signature-checked functionaries, the TSA-verified timestamps of that same
// functionary's key, and the collection's attestation types. It returns the
// observation supporting the highest SLSA ceiling and the one supporting the
// highest ALPS ceiling, which may come from different collections or signers.
func verifyObservations(results map[string]policy.StepResult) (slsa, alps standards.Observations, ok bool) {
	var cands []standards.Observations
	steps := make([]string, 0, len(results))
	for step := range results {
		steps = append(steps, step)
	}
	sort.Strings(steps) // deterministic choice among equal ceilings
	for _, step := range steps {
		for _, pc := range results[step].Passed {
			cands = append(cands, passedCollectionObservations(pc)...)
		}
	}
	if len(cands) == 0 {
		return slsa, alps, false
	}
	slsa, alps = bestPerStandard(cands)
	return slsa, alps, true
}

// passedCollectionObservations is one observation per verified functionary:
// its own principal and leaf, timestamped only when a verified timestamp
// covers that functionary's key. A collection with no functionary to name is
// a key-signed observation with no timestamp attributed to it.
func passedCollectionObservations(pc policy.PassedCollection) []standards.Observations {
	base := standards.Observations{Signed: true, Principal: standards.PrincipalKey}
	if coll, err := pc.HydratedCollection(); err == nil {
		for _, a := range coll.Attestations {
			if strings.HasPrefix(a.Type, slsaProvenancePrefix) {
				base.Provenance = true
			}
		}
	}
	var out []standards.Observations
	for _, v := range pc.Collection.ValidFunctionaries {
		o := base
		if kid, err := v.KeyID(); err == nil && len(pc.Collection.VerifiedTimestampsByKeyID[kid]) > 0 {
			o.Timestamped = true
		}
		if x, isX509 := v.(*cryptoutil.X509Verifier); isX509 {
			leaf := standards.LeafFromCertificate(x.Certificate())
			o.Principal = leaf.Principal
			o.HostedRunner = standards.IsProviderHostedRunner(leaf.RunnerEnvironment)
			o.TrustedBuilder = leaf.IsTrustedBuilder()
			o.CIPlatform = leaf.CI
		}
		o.CI = o.CIPlatform != "" || o.Principal == standards.PrincipalWorkflow
		out = append(out, o)
	}
	if len(out) == 0 {
		out = append(out, base)
	}
	return out
}

// verifyGuidance is the ceiling and next steps for the evidence a passing
// `cilock verify` actually verified, or nil when nothing passed. The VSA this
// verify emits carries no verifiedLevels, and this guidance keeps it that way:
// both standards report `verified_level: null`.
func verifyGuidance(results map[string]policy.StepResult) *standards.Guidance {
	so, ao, ok := verifyObservations(results)
	if !ok {
		return nil
	}
	audience := standards.AudienceHuman
	if detectInvokingAgent() {
		audience = standards.AudienceAgent
	}
	return standards.ComputeSplit(so, ao, standards.ScopeVerify, audience)
}
