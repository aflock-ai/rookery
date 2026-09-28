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

package standards

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// GuidanceSchema versions the Guidance JSON object. Agents branch on it; bump
// it on any change that removes or renames a field or changes a meaning.
const GuidanceSchema = "cilock.standards-guidance/v1"

// CeilingNotice is printed and serialized with every Guidance.
const CeilingNotice = "A ceiling is the highest level this evidence could support. It is not a verified level: " +
	"a SLSA Build level needs an assessment of the build platform, and an ALPS level needs an independent verifier."

// Observation names. They are the catalog's `closes` vocabulary and the keys
// of StandardCeiling.Observed.
const (
	ObsSigned             = "signed"
	ObsProvenance         = "provenance"
	ObsTimestamped        = "timestamped"
	ObsHostedRunner       = "hosted_runner"
	ObsWorkflowSigner     = "workflow_signer"
	ObsTrustedBuilder     = "trusted_builder"
	ObsPrincipalIssued    = "principal_issued"
	ObsBoundaryByObserver = "boundary_by_observer"
	ObsIsolated           = "isolated"
)

// Principal kinds: who the signing identity names.
const (
	PrincipalUnknown  = ""
	PrincipalKey      = "key"
	PrincipalHuman    = "human"
	PrincipalAgent    = "agent"
	PrincipalWorkflow = "workflow"
)

// Audience selects the phrasing of next steps.
const (
	AudienceHuman = "human"
	AudienceAgent = "agent"
)

// Scope says what the observations were taken from.
const (
	ScopeRun    = "run"
	ScopeVerify = "verify"
)

// Observations are the facts cilock saw. Every field is an observation, never
// a claim someone made to cilock: an unobserved fact is false.
type Observations struct {
	// Signed: the run produced a signed collection (verify: a passed,
	// signature-verified collection).
	Signed bool
	// Provenance: the collection carries SLSA provenance (`-a slsa`).
	Provenance bool
	// Timestamped: the envelope carries an RFC 3161 timestamp.
	Timestamped bool
	// HostedRunner: the build ran on a GitHub-hosted runner, as the signing
	// leaf's runner-environment extension (or, on the run side only when the
	// leaf lacks it, the runner's own environment) reports.
	HostedRunner bool
	// TrustedBuilder: the signing leaf's Build Signer URI names the isolated
	// provenance workflow, not the tenant's own workflow.
	TrustedBuilder bool
	// Principal is who the signing identity names.
	Principal string
	// BoundaryByObserver: a non-agent observer signed the boundary the run
	// happened inside. No cilock evidence carries this today.
	BoundaryByObserver bool
	// Isolated: a node-signed execution statement from cilockd. Not built.
	Isolated bool
	// CI selects the CI-shaped steps over the local ones.
	CI bool
	// CIPlatform is the recognized CI platform (a CI* constant), from the
	// signing leaf's issuer or, on the run side, the job environment. Empty
	// when not recognized.
	CIPlatform string
}

func (o Observations) workflowSigner() bool { return o.Principal == PrincipalWorkflow }

// principalIssued is always false in this release. A workflow or SPIFFE name
// on a leaf is not platform issuance: the name is the same under public
// Sigstore or a BYO CA, and deciding which root counts as the platform's is
// an authentication boundary with its own design (docs/design/
// formal-slsa-tracks.md, "Known gaps"). Until that lands, cilock reports no
// ALPS ceiling above ALPS-0; it never over-reports one.
func (o Observations) principalIssued() bool { return false }

// namesNonHumanPrincipal: the leaf names a workflow or an agent, which a
// platform could have issued; whether it did is not assessed yet.
func (o Observations) namesNonHumanPrincipal() bool {
	return o.Principal == PrincipalWorkflow || o.Principal == PrincipalAgent
}

// SLSAEvidence maps the observations onto the model's ProvEvidence.
// GitHub-hosted runners are single-use VMs, so a hosted runner is also the
// ephemeral one; a self-hosted runner is neither.
func (o Observations) SLSAEvidence() SLSAEvidence {
	return SLSAEvidence{
		Present:              o.Signed && o.Provenance,
		HostedWorkflowSigner: o.HostedRunner && o.workflowSigner(),
		TrustedBuilderSigner: o.TrustedBuilder,
		Timestamped:          o.Timestamped,
		EphemeralRunner:      o.HostedRunner,
	}
}

// ALPSEvidence maps the observations onto the model's Evidence. A boundary is
// "claimed" only when an observer signed it: cilock has no path that records
// an agent-signed boundary, and the strict verifier ignores that field.
func (o Observations) ALPSEvidence() ALPSEvidence {
	return ALPSEvidence{
		Signed:             o.Signed,
		Issued:             o.principalIssued(),
		Timestamped:        o.Timestamped,
		BoundaryClaimed:    o.BoundaryByObserver,
		BoundaryByObserver: o.BoundaryByObserver,
		Isolated:           o.Isolated,
	}
}

func (o Observations) observed(std string) map[string]bool {
	all := map[string]bool{
		ObsSigned:             o.Signed,
		ObsProvenance:         o.Signed && o.Provenance,
		ObsTimestamped:        o.Timestamped,
		ObsHostedRunner:       o.HostedRunner,
		ObsWorkflowSigner:     o.workflowSigner(),
		ObsTrustedBuilder:     o.TrustedBuilder,
		ObsPrincipalIssued:    o.principalIssued(),
		ObsBoundaryByObserver: o.BoundaryByObserver,
		ObsIsolated:           o.Isolated,
	}
	out := map[string]bool{}
	for _, k := range observationNames[std] {
		out[k] = all[k]
	}
	return out
}

// Guidance is the typed `standards` object in `cilock run --json` and
// `cilock verify --format json`.
type Guidance struct {
	Schema    string          `json:"schema"`
	Scope     string          `json:"scope"`
	Audience  string          `json:"audience"`
	Notice    string          `json:"notice"`
	SLSABuild StandardCeiling `json:"slsa_build"`
	ALPS      StandardCeiling `json:"alps"`
	NextSteps []NextStep      `json:"next_steps"`
}

// StandardCeiling is one standard's observed ceiling. VerifiedLevel is always
// null: this producer never assigns one, and the field exists so a consumer
// reads that explicitly instead of inferring it from an absence.
type StandardCeiling struct {
	Spec          string             `json:"spec"`
	Ceiling       string             `json:"ceiling"`
	Basis         string             `json:"basis"`
	VerifiedLevel *string            `json:"verified_level"`
	Observed      map[string]bool    `json:"observed"`
	Unavailable   []UnavailableLevel `json:"unavailable,omitempty"`
}

// UnavailableLevel is a level no run can reach today, with its requirement.
type UnavailableLevel struct {
	Level    string `json:"level"`
	Status   string `json:"status"`
	Requires string `json:"requires"`
}

// NextStep is one ordered action toward a higher ceiling. A planned step has
// no command or snippet: it names what is coming, not a file to point at.
type NextStep struct {
	ID          string `json:"id"`
	Standard    string `json:"standard"`
	TargetLevel string `json:"target_level"`
	Status      string `json:"status"`
	Why         string `json:"why"`
	Action      string `json:"action"`
	Command     string `json:"command,omitempty"`
	Snippet     string `json:"snippet,omitempty"`
	Docs        string `json:"docs,omitempty"`
}

// Compute builds the guidance for a set of observations. It is pure: the same
// observations always give the same guidance. A catalog error yields nil,
// which callers render as no guidance rather than as any level.
func Compute(o Observations, scope, audience string) *Guidance {
	return ComputeSplit(o, o, scope, audience)
}

// ComputeSplit builds the guidance when the strongest SLSA evidence and the
// strongest ALPS evidence are different observations (two collections, or two
// signers): each standard's ceiling, basis, observed facts and next steps come
// from its own observation, never from a mix of the two.
func ComputeSplit(so, ao Observations, scope, audience string) *Guidance {
	cats, err := Catalogs()
	if err != nil {
		return nil
	}
	if audience != AudienceAgent {
		audience = AudienceHuman
	}
	slsa := DeriveSLSA(so.SLSAEvidence())
	alps := DeriveALPS(ao.ALPSEvidence())
	g := &Guidance{
		Schema:   GuidanceSchema,
		Scope:    scope,
		Audience: audience,
		Notice:   CeilingNotice,
		SLSABuild: StandardCeiling{
			Spec: cats[StandardSLSABuild].Spec, Ceiling: slsa.String(),
			Basis: slsaBasis(so, scope), Observed: so.observed(StandardSLSABuild),
		},
		ALPS: StandardCeiling{
			Spec: cats[StandardALPS].Spec, Ceiling: alps.String(),
			Basis: alpsBasis(ao), Observed: ao.observed(StandardALPS),
			Unavailable: unavailable(cats[StandardALPS], ao),
		},
		NextSteps: []NextStep{},
	}
	g.SLSABuild.Unavailable = unavailable(cats[StandardSLSABuild], so)
	if !so.Signed && !ao.Signed {
		// Nothing was signed, so no action here raises anything: the first
		// step is making the run complete, which the run's own error names.
		return g
	}
	g.NextSteps = append(g.NextSteps, nextSteps(cats[StandardSLSABuild], so, int(slsa), audience)...)
	g.NextSteps = append(g.NextSteps, nextSteps(cats[StandardALPS], ao, int(alps), audience)...)
	return g
}

// unavailable lists the levels no run can reach today (status future) and
// the levels this run's CI platform cannot reach (catalog limits).
func unavailable(c Catalog, o Observations) []UnavailableLevel {
	var out []UnavailableLevel
	for _, l := range c.Levels {
		if l.Status == StatusFuture {
			out = append(out, UnavailableLevel{Level: l.Level, Status: l.Status, Requires: l.Requires})
		}
	}
	p := o.platform()
	for _, l := range c.Limits {
		if contains(l.CI, p) {
			out = append(out, UnavailableLevel{Level: l.Level, Status: l.Status, Requires: l.Requires})
		}
	}
	return out
}

// platform is the CI platform steps and limits match on: the observed
// platform, CINone outside CI, and "" for a CI cilock does not recognize,
// which matches no platform-restricted entry.
func (o Observations) platform() string {
	switch {
	case o.CIPlatform != "":
		return o.CIPlatform
	case !o.CI:
		return CINone
	default:
		return ""
	}
}

func ciLabel(p string) string {
	switch p {
	case CIGitHub:
		return "GitHub Actions"
	case CIGitLab:
		return "GitLab CI"
	case CIBuildkite:
		return "Buildkite"
	case CICircleCI:
		return "CircleCI"
	case CIKubernetes:
		return "Kubernetes"
	default:
		return "CI"
	}
}

// nextSteps returns, in target-level order and then catalog order, every step
// that closes an observation this run lacks, above the current ceiling.
// stepApplies reports whether a step fits this run's shape: its CI/local
// scope and CI platform. A workflow or agent signer already did what the
// principal-issued steps ask; only the platform-issuance check it cannot pass
// yet is missing, so those steps would send it round in a loop.
func (o Observations) stepApplies(s Step) bool {
	if s.Closes == ObsPrincipalIssued && o.namesNonHumanPrincipal() {
		return false
	}
	if (s.When == WhenCI && !o.CI) || (s.When == WhenLocal && o.CI) {
		return false
	}
	return len(s.CI) == 0 || contains(s.CI, o.platform())
}

func nextSteps(c Catalog, o Observations, ceiling int, audience string) []NextStep {
	rank := levelNames[c.Standard]
	obs := o.observed(c.Standard)
	type ranked struct {
		r int
		i int
		s Step
	}
	var picked []ranked
	for i, s := range c.Steps {
		r, _ := rank(s.TargetLevel)
		if r <= ceiling || obs[s.Closes] || !o.stepApplies(s) {
			continue
		}
		picked = append(picked, ranked{r, i, s})
	}
	sort.SliceStable(picked, func(a, b int) bool {
		if picked[a].r != picked[b].r {
			return picked[a].r < picked[b].r
		}
		return picked[a].i < picked[b].i
	})
	out := make([]NextStep, 0, len(picked))
	for _, p := range picked {
		s := p.s
		ns := NextStep{
			ID: s.ID, Standard: c.Standard, TargetLevel: s.TargetLevel, Status: s.Status,
			Why: s.Why, Action: s.Action, Docs: s.Docs,
		}
		if audience == AudienceAgent {
			ns.Action = s.AgentAction
		}
		if s.Status == StatusAvailable {
			ns.Command = s.Command
			ns.Snippet = s.RenderedSnippet()
		}
		out = append(out, ns)
	}
	return out
}

func slsaBasis(o Observations, scope string) string {
	subject := "this run"
	if scope == ScopeVerify {
		subject = "the verified evidence"
	}
	switch {
	case !o.Signed:
		return subject + " has no signed collection"
	case !o.Provenance:
		return subject + " carries no SLSA provenance"
	}
	var b string
	switch {
	case o.TrustedBuilder && o.HostedRunner && o.workflowSigner():
		b = "signed by the isolated provenance workflow on a GitHub-hosted runner"
	case o.HostedRunner && o.workflowSigner():
		b = "inline in " + ciLabel(o.CIPlatform) + ": signed by the build job's own workflow identity on a provider-hosted runner"
	case o.workflowSigner():
		b = "signed by a keyless workflow identity on a runner not observed to be provider-hosted; a higher level " +
			"depends on whether you treat your runner operator as the build platform"
	default:
		b = "signed by " + principalLabel(o.Principal) + ", not a hosted build platform"
	}
	if !o.Timestamped {
		b += "; no trusted timestamp"
	}
	if scope == ScopeVerify {
		return "verified provenance is " + b
	}
	return b
}

func alpsBasis(o Observations) string {
	if !o.Signed {
		return "no signed collection"
	}
	if !o.principalIssued() {
		if o.namesNonHumanPrincipal() {
			return "signed by " + principalLabel(o.Principal) + "; platform issuance is not assessed yet, so ALPS-1 is not reported"
		}
		return "signed by " + principalLabel(o.Principal) + ", not a platform-issued non-human principal"
	}
	b := "signed by " + principalLabel(o.Principal)
	if !o.Timestamped {
		return b + "; no trusted timestamp"
	}
	if !o.BoundaryByObserver {
		return b + ", timestamped; no observer-signed boundary"
	}
	return b + ", timestamped, observer-signed boundary"
}

func principalLabel(p string) string {
	switch p {
	case PrincipalKey:
		return "a signing key"
	case PrincipalHuman:
		return "a human session"
	case PrincipalAgent:
		return "an enrolled agent principal"
	case PrincipalWorkflow:
		return "a CI workflow identity"
	default:
		return "an unidentified signer"
	}
}

// WriteHuman renders the guidance block for the stderr summary. Every line
// that names a level names it as a ceiling; the header carries the notice.
func (g *Guidance) WriteHuman(w io.Writer, indent string) {
	if g == nil {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%sstandards: observed ceilings, NOT verified levels (a ceiling is the most a verifier could grant)\n", indent)
	g.writeStandard(&b, indent, "SLSA Build", StandardSLSABuild, g.SLSABuild)
	g.writeStandard(&b, indent, g.ALPS.Spec, StandardALPS, g.ALPS)
	_, _ = io.WriteString(w, b.String())
}

func (g *Guidance) writeStandard(b *strings.Builder, indent, label, std string, c StandardCeiling) {
	fmt.Fprintf(b, "%s  %s: ceiling %s (%s)\n", indent, label, c.Ceiling, c.Basis)
	var target string
	for _, s := range g.NextSteps {
		if s.Standard != std {
			continue
		}
		if s.TargetLevel != target {
			target = s.TargetLevel
			fmt.Fprintf(b, "%s    to reach %s:\n", indent, target)
		}
		fmt.Fprintf(b, "%s      - %s\n", indent, s.Action)
		if s.Command != "" {
			fmt.Fprintf(b, "%s        $ %s\n", indent, s.Command)
		}
		if s.Snippet != "" {
			for _, line := range strings.Split(strings.TrimRight(s.Snippet, "\n"), "\n") {
				fmt.Fprintf(b, "%s        | %s\n", indent, line)
			}
		}
		if s.Docs != "" {
			fmt.Fprintf(b, "%s        docs: %s\n", indent, s.Docs)
		}
	}
	for _, u := range c.Unavailable {
		fmt.Fprintf(b, "%s    %s: %s\n", indent, u.Level, u.Requires)
	}
}
