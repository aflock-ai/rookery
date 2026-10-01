// jade:ring local

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

package l3

import (
	"slices"
	"testing"
)

// The shared scene mirrors SlsaL3Workflow.lean: repository acme/app, commit
// c1, run 1, the provenance workflow pinned at commit `pinned`.
const (
	pinned  = "0123456789abcdef0123456789abcdef01234567"
	other   = "fedcba9876543210fedcba9876543210fedcba98"
	commit  = "1111111111111111111111111111111111111111"
	subject = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func honestPolicy() Policy {
	return Policy{Roots: []Root{RootPlatform}, Path: WorkflowPath, SHA: pinned, Repo: "acme/app"}
}

func provExt() Ext {
	return Ext{
		SignerPath: WorkflowPath, SignerRef: pinned, SignerDigest: pinned,
		SourceRepo: "acme/app", SourceDigest: commit, RunID: "1", Trigger: "push", Hosted: true,
	}
}

func buildExt() Ext {
	return Ext{
		SignerPath: "acme/app/.github/workflows/release.yml", SignerRef: "refs/heads/main", SignerDigest: commit,
		SourceRepo: "acme/app", SourceDigest: commit, RunID: "1", Trigger: "push", Hosted: true,
	}
}

func honestEvidence() Evidence {
	return Evidence{
		Signer:    Cert{Root: RootPlatform, Ext: provExt()},
		Statement: Statement{BuilderPath: WorkflowPath, BuilderRef: pinned, Repo: "acme/app", Commit: commit, RunID: "1", Subjects: []string{subject}},
		Builds:    []Collection{{Cert: Cert{Root: RootPlatform, Ext: buildExt()}, Subjects: []string{subject}}},
	}
}

func requireRejectedFor(t *testing.T, v Verdict, want Requirement) {
	t.Helper()
	if v.Accepted() {
		t.Fatalf("accepted; want rejection for %s", want)
	}
	if !slices.ContainsFunc(v.Failures, func(f Failure) bool { return f.Requirement == want }) {
		t.Fatalf("rejected for %v; want %s among them", v.Failures, want)
	}
}

func TestL3AcceptsHonestEvidence(t *testing.T) {
	v := Accept(honestPolicy(), honestEvidence())
	if !v.Accepted() {
		t.Fatalf("honest evidence rejected: %v", v.Failures)
	}
	if got := ObservedBuildLevel(honestPolicy(), honestEvidence()); got != 3 {
		t.Fatalf("ObservedBuildLevel = %d, want 3", got)
	}
}

// Requirement 1: builder.id, repository, commit and run are compared with the
// signer's certificate extensions, never taken from the statement alone.
func TestReq1StatementFieldsMustMatchCertificate(t *testing.T) {
	cases := map[Requirement]func(*Statement){
		ReqBuilderID: func(s *Statement) { s.BuilderRef = "v1" },
		ReqRepo:      func(s *Statement) { s.Repo = "mallory/tool" },
		ReqCommit:    func(s *Statement) { s.Commit = "2222222222222222222222222222222222222222" },
		ReqRun:       func(s *Statement) { s.RunID = "2" },
	}
	for req, mutate := range cases {
		t.Run(string(req), func(t *testing.T) {
			e := honestEvidence()
			mutate(&e.Statement)
			requireRejectedFor(t, Accept(honestPolicy(), e), req)
		})
	}
	t.Run("builder path", func(t *testing.T) {
		e := honestEvidence()
		e.Statement.BuilderPath = "acme/app/.github/workflows/release.yml"
		requireRejectedFor(t, Accept(honestPolicy(), e), ReqBuilderID)
	})
	// Lean `builder_id_without_extension`: the caller's own build job writes
	// the pinned builder id into a statement it signs.
	t.Run("pinned builder id from the build job's certificate", func(t *testing.T) {
		e := honestEvidence()
		e.Signer.Ext = buildExt()
		requireRejectedFor(t, Accept(honestPolicy(), e), ReqSignerWorkflow)
	})
}

// Requirement 2: the Build Signer Digest is the pinned commit, and the ref in
// the Build Signer URI is that same commit (a SHA pin, not a tag).
func TestReq2SignerPinnedByCommit(t *testing.T) {
	t.Run("digest of a moved tag", func(t *testing.T) {
		e := honestEvidence()
		e.Signer.Ext.SignerDigest = other
		requireRejectedFor(t, Accept(honestPolicy(), e), ReqSignerDigest)
	})
	// Lean `tag_pinned_swapped`: the job ran the pinned workflow through a tag.
	t.Run("tag ref", func(t *testing.T) {
		e := honestEvidence()
		e.Signer.Ext.SignerRef = "refs/tags/v1"
		e.Statement.BuilderRef = "refs/tags/v1"
		requireRejectedFor(t, Accept(honestPolicy(), e), ReqSignerRef)
	})
}

// Requirement 3: exact literal comparison. A glob metacharacter in the policy
// matches only itself, and the parsers refuse empty values (the functionary
// matcher reads empty as allow-all).
func TestReq3ExactLiteralMatch(t *testing.T) {
	for name, pol := range map[string]Policy{
		"glob path": {Roots: []Root{RootPlatform}, Path: "aflock-ai/*", SHA: pinned, Repo: "acme/app"},
		"glob sha":  {Roots: []Root{RootPlatform}, Path: WorkflowPath, SHA: "*", Repo: "acme/app"},
		"prefix":    {Roots: []Root{RootPlatform}, Path: WorkflowPath, SHA: pinned[:7], Repo: "acme/app"},
	} {
		t.Run(name, func(t *testing.T) {
			if Accept(pol, honestEvidence()).Accepted() {
				t.Fatal("a non-literal policy value accepted the honest signer")
			}
		})
	}
	t.Run("policy refuses empty and non-commit values", func(t *testing.T) {
		for _, p := range []Policy{
			{Roots: []Root{RootPlatform}, Path: WorkflowPath, SHA: "", Repo: "acme/app"},
			{Roots: []Root{RootPlatform}, Path: WorkflowPath, SHA: "v1", Repo: "acme/app"},
			{Roots: []Root{RootPlatform}, Path: "", SHA: pinned, Repo: "acme/app"},
			{Roots: nil, Path: WorkflowPath, SHA: pinned, Repo: "acme/app"},
			{Roots: []Root{"elsewhere"}, Path: WorkflowPath, SHA: pinned, Repo: "acme/app"},
			{Roots: []Root{RootPlatform}, Path: WorkflowPath, SHA: pinned, Repo: ""},
			{Roots: []Root{RootPlatform}, Path: WorkflowPath, SHA: pinned, Repo: "acme/*"},
			{Roots: []Root{RootPlatform}, Path: WorkflowPath, SHA: pinned, Repo: "https://github.com/acme/app"},
		} {
			if err := p.Validate(); err == nil {
				t.Errorf("Validate(%+v) = nil, want an error", p)
			}
		}
		if err := honestPolicy().Validate(); err != nil {
			t.Fatalf("honest policy: %v", err)
		}
	})
}

// The expected source repository (SLSA verifying-artifacts step 2): a fork or
// any other repository that calls the pinned workflow is refused. Lean
// `other_repo_reaches_l3`.
func TestExpectedSourceRepository(t *testing.T) {
	e := honestEvidence()
	e.Signer.Ext.SourceRepo = "mallory/app"
	e.Statement.Repo = "mallory/app"
	e.Builds[0].Cert.Ext.SourceRepo = "mallory/app"
	v := Accept(honestPolicy(), e)
	requireRejectedFor(t, v, ReqExpectedRepo)
	if len(v.Failures) != 1 {
		t.Fatalf("a self-consistent fork must fail only the expected-repo check, got %v", v.Failures)
	}
	pol := honestPolicy()
	pol.Repo = "mallory/app"
	if v := Accept(pol, e); !v.Accepted() {
		t.Fatalf("expecting mallory/app: %v", v.Failures)
	}
}

// Requirement 4: RunnerEnvironment must be github-hosted.
func TestReq4GitHubHostedRunner(t *testing.T) {
	// Lean `self_hosted_runner_accepted`.
	e := honestEvidence()
	e.Signer.Ext.Hosted = false
	requireRejectedFor(t, Accept(honestPolicy(), e), ReqHostedRunner)
}

// Requirement 5: only events a repository writer can cause.
func TestReq5TriggerAllowlist(t *testing.T) {
	for trigger, ok := range map[string]bool{
		"push": true, "release": true, "workflow_dispatch": true,
		"pull_request": false, "pull_request_target": false, "workflow_run": false,
		"schedule": false, "": false, "Push": false,
	} {
		t.Run(trigger, func(t *testing.T) {
			e := honestEvidence()
			e.Signer.Ext.Trigger = trigger
			v := Accept(honestPolicy(), e)
			if ok && !v.Accepted() {
				t.Fatalf("%q rejected: %v", trigger, v.Failures)
			}
			if !ok {
				requireRejectedFor(t, v, ReqTrigger)
			}
		})
	}
}

// Requirement 6: subjects link to a build collection of the same run id,
// repository and commit. The attempt number is not part of the run.
func TestReq6LinkByRunRepoCommit(t *testing.T) {
	cases := map[string]func(*Ext){
		"other run":    func(x *Ext) { x.RunID = "2" },
		"other repo":   func(x *Ext) { x.SourceRepo = "mallory/tool" },
		"other commit": func(x *Ext) { x.SourceDigest = "2222222222222222222222222222222222222222" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := honestEvidence()
			mutate(&e.Builds[0].Cert.Ext)
			requireRejectedFor(t, Accept(honestPolicy(), e), ReqLinked)
		})
	}
	t.Run("build from an untrusted root", func(t *testing.T) {
		e := honestEvidence()
		e.Builds[0].Cert.Root = RootPublicSigstore
		requireRejectedFor(t, Accept(honestPolicy(), e), ReqLinked)
	})
	t.Run("subject no build carries", func(t *testing.T) {
		e := honestEvidence()
		e.Statement.Subjects = append(e.Statement.Subjects, "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
		requireRejectedFor(t, Accept(honestPolicy(), e), ReqLinked)
	})
	t.Run("no subjects", func(t *testing.T) {
		e := honestEvidence()
		e.Statement.Subjects = nil
		requireRejectedFor(t, Accept(honestPolicy(), e), ReqSubjects)
	})
	t.Run("a rerun attempt still links", func(t *testing.T) {
		b, err := parseRunURI("https://github.com/acme/app/actions/runs/1/attempts/2")
		if err != nil {
			t.Fatal(err)
		}
		if b.repo != "acme/app" || b.id != "1" {
			t.Fatalf("parsed %+v", b)
		}
	})
}

func TestTrustedRootRequired(t *testing.T) {
	e := honestEvidence()
	e.Signer.Root = RootPublicSigstore
	requireRejectedFor(t, Accept(honestPolicy(), e), ReqTrustedRoot)
	pol := honestPolicy()
	pol.Roots = []Root{RootPlatform, RootPublicSigstore}
	e.Builds[0].Cert.Root = RootPublicSigstore
	if v := Accept(pol, e); !v.Accepted() {
		t.Fatalf("both roots trusted: %v", v.Failures)
	}
}

// Every failing requirement is reported, not only the first.
func TestVerdictListsEveryFailure(t *testing.T) {
	e := honestEvidence()
	e.Signer.Ext.Hosted = false
	e.Signer.Ext.Trigger = "pull_request_target"
	v := Accept(honestPolicy(), e)
	requireRejectedFor(t, v, ReqHostedRunner)
	requireRejectedFor(t, v, ReqTrigger)
	if ObservedBuildLevel(honestPolicy(), e) != 0 {
		t.Fatal("a rejected verdict observed L3")
	}
}
