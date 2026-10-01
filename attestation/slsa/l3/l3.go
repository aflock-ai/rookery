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

// Package l3 is `cilock verify --slsa-level 3`: SLSA Build L3 for provenance
// signed by the isolated provenance workflow
// (aflock-ai/cilock-action/.github/workflows/provenance.yml).
//
// Accept is the decision function. It is the Go side of `l3Accept` in the
// Lean model formal/ci-provenance/CiProvenance/SlsaL3Workflow.lean, and
// TestL3AcceptMatchesLeanModel diffs the two. Theorem `l3_sound` there says
// what an accepted verdict guarantees and under which assumptions.
//
// Every comparison is an exact, literal string equality. None goes through the
// policy functionary matcher (attestation/policy/constraints.go), which reads
// an empty constraint as allow-all and a constraint holding a glob
// metacharacter as a glob.
package l3

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	"github.com/aflock-ai/rookery/attestation/slsa"
)

// Root names the CA whose chain verified a certificate.
type Root string

const (
	// RootPlatform is the TestifySec platform's Fulcio: the default.
	RootPlatform Root = "platform"
	// RootPublicSigstore is the public Sigstore Fulcio: opt-in.
	RootPublicSigstore Root = "public-sigstore"
)

// WorkflowPath is the reusable workflow that signs L3 provenance, as the
// path part of GitHub's job_workflow_ref claim.
const WorkflowPath = "aflock-ai/cilock-action/.github/workflows/provenance.yml"

// Ext is what the verifier reads from a Fulcio certificate: the extensions
// Fulcio's GitHub principal copies from the job's OIDC claims.
type Ext struct {
	// SignerPath and SignerRef split the Build Signer URI
	// (1.3.6.1.4.1.57264.1.9, job_workflow_ref) at its "@".
	SignerPath string `json:"buildSignerPath"`
	SignerRef  string `json:"buildSignerRef"`
	// SignerDigest is Build Signer Digest (job_workflow_sha).
	SignerDigest string `json:"buildSignerDigest"`
	// SourceRepo is Source Repository URI without https://github.com/.
	SourceRepo string `json:"sourceRepository"`
	// SourceDigest is Source Repository Digest (the sha claim).
	SourceDigest string `json:"sourceDigest"`
	// RunID is the run id from Run Invocation URI, without the attempt.
	RunID string `json:"runId"`
	// Trigger is Build Trigger (event_name).
	Trigger string `json:"trigger"`
	// Hosted is Runner Environment == "github-hosted".
	Hosted bool `json:"hosted"`
}

// Cert is a certificate the verifier trusts, labelled with the root whose
// chain verified it.
type Cert struct {
	Root Root `json:"root"`
	Ext  Ext  `json:"ext"`
	// ConfigURI is Build Config URI (workflow_ref): the caller workflow the
	// job ran under. Outside the Lean model; Verify checks externalParameters
	// against it.
	ConfigURI string `json:"buildConfigUri,omitempty"`
}

// Statement is the part of a SLSA v1 provenance statement the verifier checks.
type Statement struct {
	// BuilderPath and BuilderRef split runDetails.builder.id
	// ("https://github.com/<path>@<ref>").
	BuilderPath string `json:"builderPath"`
	BuilderRef  string `json:"builderRef"`
	Repo        string `json:"repo"`
	Commit      string `json:"commit"`
	RunID       string `json:"runId"`
	// Subjects are "sha256:<hex>" keys.
	Subjects []string `json:"subjects"`
	// BuilderID, BuildType and ExternalParameters are read as written, for
	// the checks Verify adds outside the Lean model.
	BuilderID          string          `json:"builderId,omitempty"`
	BuildType          string          `json:"buildType,omitempty"`
	ExternalParameters json.RawMessage `json:"externalParameters,omitempty"`
}

// Collection is a build-step attestation collection: its signer and the
// "sha256:<hex>" keys of its subjects.
type Collection struct {
	Cert     Cert     `json:"cert"`
	Subjects []string `json:"subjects"`
}

// Evidence is one provenance statement, its signer and every candidate build
// collection.
type Evidence struct {
	Signer    Cert         `json:"signer"`
	Statement Statement    `json:"statement"`
	Builds    []Collection `json:"builds"`
}

// Policy is the built-in L3 policy: the roots trusted, the provenance
// workflow and the commit it is pinned at.
type Policy struct {
	Roots []Root `json:"roots"`
	Path  string `json:"path"`
	SHA   string `json:"sha"`
	// Repo is the expected source repository, "<owner>/<name>": SLSA
	// verifying-artifacts step 2, the canonical source repo.
	Repo string `json:"repo"`
}

var commitSHA = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)

// Validate refuses a policy Accept cannot enforce as written: no root, an
// unknown root, an empty path, or a pin that is not a full commit SHA. An
// empty pin would equal an empty extension.
func (p Policy) Validate() error {
	if len(p.Roots) == 0 {
		return fmt.Errorf("slsa l3 policy: no trusted root")
	}
	for _, r := range p.Roots {
		if r != RootPlatform && r != RootPublicSigstore {
			return fmt.Errorf("slsa l3 policy: unknown root %q (want %q or %q)", r, RootPlatform, RootPublicSigstore)
		}
	}
	if p.Path == "" {
		return fmt.Errorf("slsa l3 policy: empty provenance workflow path")
	}
	if !repoName.MatchString(p.Repo) {
		return fmt.Errorf("slsa l3 policy: expected source repository %q is not <owner>/<name>", p.Repo)
	}
	if !commitSHA.MatchString(p.SHA) {
		return fmt.Errorf("slsa l3 policy: provenance workflow pin %q is not a full lowercase commit SHA", p.SHA)
	}
	return nil
}

// Requirement names one check of the L3 policy.
type Requirement string

const (
	ReqTrustedRoot    Requirement = "trusted-root"
	ReqSignerWorkflow Requirement = "signer-is-provenance-workflow"
	ReqExpectedRepo   Requirement = "source-repository-is-expected"
	ReqSignerDigest   Requirement = "signer-digest-is-pinned-commit"
	ReqSignerRef      Requirement = "signer-ref-is-pinned-commit"
	ReqHostedRunner   Requirement = "github-hosted-runner"
	ReqTrigger        Requirement = "writer-only-trigger"
	ReqBuilderID      Requirement = "builder-id-matches-certificate"
	ReqRepo           Requirement = "repository-matches-certificate"
	ReqCommit         Requirement = "commit-matches-certificate"
	ReqRun            Requirement = "run-matches-certificate"
	ReqSubjects       Requirement = "has-subjects"
	ReqLinked         Requirement = "subjects-linked-to-same-run-build"
	// ReqCallerSubjects and ReqProvenance are checked by Verify, outside
	// the Lean model: the artifacts asked about are among the accepted
	// statement's subjects, and a provenance statement is present at all.
	ReqCallerSubjects Requirement = "caller-subjects-covered"
	ReqProvenance     Requirement = "provenance-present"
	// ReqPolicy is a policy Validate refuses.
	ReqPolicy Requirement = "valid-policy"
	// ReqBuildType, ReqExternalParameters and ReqTrustedBuilder are SLSA
	// verifying-artifacts checks Verify adds outside the Lean model: the
	// buildType is provenance.yml's, externalParameters holds only known
	// fields and each equals the signer certificate's, and the builder.id is
	// trusted to L3 by the trusted-builder catalog (attestation/slsa).
	ReqBuildType          Requirement = "build-type-is-expected"
	ReqExternalParameters Requirement = "external-parameters-are-expected"
	ReqTrustedBuilder     Requirement = "builder-trusted-to-level-3"
)

// Failure is one requirement the evidence does not meet.
type Failure struct {
	Requirement Requirement `json:"requirement"`
	Detail      string      `json:"detail"`
}

// Verdict lists every failed requirement; it accepts when there are none.
type Verdict struct {
	Failures []Failure `json:"failures,omitempty"`
}

// Accepted reports whether no requirement failed.
func (v Verdict) Accepted() bool { return len(v.Failures) == 0 }

func (v *Verdict) require(ok bool, r Requirement, format string, args ...any) {
	if !ok {
		v.Failures = append(v.Failures, Failure{Requirement: r, Detail: fmt.Sprintf(format, args...)})
	}
}

// TriggerAllowed reports whether only a repository writer can cause event:
// push, release and workflow_dispatch. Fork pull requests,
// pull_request_target and workflow_run are refused.
func TriggerAllowed(event string) bool {
	return event == "push" || event == "release" || event == "workflow_dispatch"
}

// Accept is `l3Accept`: the provenance signer is the pinned workflow commit on
// a GitHub-hosted runner for a writer-only event; builder.id, repository,
// commit and run in the statement are the signer certificate's; and every
// subject is carried by a build collection of the same run, repository and
// commit under a trusted root. It evaluates every check and reports each
// failure.
func Accept(pol Policy, e Evidence) Verdict {
	var v Verdict
	x, s := e.Signer.Ext, e.Statement
	v.require(slices.Contains(pol.Roots, e.Signer.Root), ReqTrustedRoot, "signer certificate root %q is not trusted (trusted: %v)", e.Signer.Root, pol.Roots)
	v.require(x.SignerPath == pol.Path, ReqSignerWorkflow, "signer workflow %q is not %q", x.SignerPath, pol.Path)
	v.require(x.SignerDigest == pol.SHA, ReqSignerDigest, "signer workflow digest %q is not the pinned commit %q", x.SignerDigest, pol.SHA)
	v.require(x.SignerRef == pol.SHA, ReqSignerRef, "signer workflow ref %q is not the pinned commit %q (pin the workflow by SHA)", x.SignerRef, pol.SHA)
	v.require(x.Hosted, ReqHostedRunner, "signer ran on a runner that is not github-hosted")
	v.require(TriggerAllowed(x.Trigger), ReqTrigger, "signer run was triggered by %q; only push, release and workflow_dispatch are accepted", x.Trigger)
	v.require(x.SourceRepo == pol.Repo, ReqExpectedRepo, "signer ran for repository %q, not the expected %q", x.SourceRepo, pol.Repo)
	v.require(s.BuilderPath == x.SignerPath, ReqBuilderID, "builder.id path %q is not the certificate's %q", s.BuilderPath, x.SignerPath)
	v.require(s.BuilderRef == x.SignerRef, ReqBuilderID, "builder.id ref %q is not the certificate's %q", s.BuilderRef, x.SignerRef)
	v.require(s.Repo == x.SourceRepo, ReqRepo, "statement repository %q is not the certificate's %q", s.Repo, x.SourceRepo)
	v.require(s.Commit == x.SourceDigest, ReqCommit, "statement commit %q is not the certificate's %q", s.Commit, x.SourceDigest)
	v.require(s.RunID == x.RunID, ReqRun, "statement run %q is not the certificate's %q", s.RunID, x.RunID)
	v.require(len(s.Subjects) > 0, ReqSubjects, "statement has no subjects")
	for _, subject := range s.Subjects {
		v.require(linked(pol, e, subject), ReqLinked, "no build collection of %s run %s at %s carries %s", x.SourceRepo, x.RunID, x.SourceDigest, subject)
	}
	return v
}

// linked is `linked`: some build collection signed under a trusted root, for
// the signer's repository, commit and run, carries subject.
func linked(pol Policy, e Evidence, subject string) bool {
	x := e.Signer.Ext
	for _, b := range e.Builds {
		trusted := slices.Contains(pol.Roots, b.Cert.Root)
		sameRun := b.Cert.Ext.RunID == x.RunID
		sameRepo := b.Cert.Ext.SourceRepo == x.SourceRepo
		sameCommit := b.Cert.Ext.SourceDigest == x.SourceDigest
		carries := slices.Contains(b.Subjects, subject)
		if trusted && sameRun && sameRepo && sameCommit && carries {
			return true
		}
	}
	return false
}

// ObservedBuildLevel is the SLSA Build level this evidence demonstrates under
// pol: 3 when Accept holds and the trusted-builder catalog (attestation/slsa)
// trusts the signer's builder identity to L3, otherwise 0. Zero means "L3 not
// observed", not "L0": this verifier assesses L3 only and never grades L1 or
// L2. Verify's Result.ObservedLevel adds the checks outside the Lean model.
func ObservedBuildLevel(pol Policy, e Evidence) int {
	id := githubURL + e.Signer.Ext.SignerPath + "@" + e.Signer.Ext.SignerRef
	if Accept(pol, e).Accepted() && slsa.BuilderMaxLevel(id) >= 3 {
		return 3
	}
	return 0
}
