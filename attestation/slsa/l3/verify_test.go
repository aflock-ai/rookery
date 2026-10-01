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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// scene signs a build collection and a provenance statement for the same run
// under one CA, the way a caller workflow plus provenance.yml would.
type scene struct {
	ca         testCA
	build      dsse.Envelope
	provenance dsse.Envelope
}

func newScene(t *testing.T, provExt, buildExt func(e *sceneExt)) scene {
	t.Helper()
	return newSceneWithPredicate(t, provExt, buildExt, nil)
}

func newSceneWithPredicate(t *testing.T, provExt, buildExt func(e *sceneExt), predicate func(p map[string]any)) scene {
	t.Helper()
	ca := newTestCA(t, "platform")
	p := sceneExt{ref: WorkflowPath + "@" + pinned, sha: pinned, repo: "acme/app", commit: commit, run: "7", attempt: "1", event: "push", runner: "github-hosted"}
	b := sceneExt{ref: "acme/app/.github/workflows/release.yml@refs/heads/main", sha: commit, repo: "acme/app", commit: commit, run: "7", attempt: "1", event: "push", runner: "github-hosted"}
	if provExt != nil {
		provExt(&p)
	}
	if buildExt != nil {
		buildExt(&b)
	}
	subjects := []testSubject{{Name: "file:app", Digest: map[string]string{"sha256": subjectHex}}}
	build := ca.sign(t, b.extensions(), statementJSON(t, attestation.CollectionType, subjects, map[string]any{"name": "build"}))
	pred := provenancePredicate("https://github.com/"+p.ref, "https://github.com/"+p.repo+"/actions/runs/"+p.run, p.repo, p.commit)
	if predicate != nil {
		predicate(pred)
	}
	prov := ca.sign(t, p.extensions(), statementJSON(t, ProvenancePredicateType, subjects, pred))
	return scene{ca: ca, build: build, provenance: prov}
}

type sceneExt struct{ ref, sha, repo, commit, run, attempt, event, runner string }

func (s sceneExt) extensions() certificateExtensions {
	return githubExtensions(s.ref, s.sha, s.repo, s.commit, s.run, s.attempt, s.event, s.runner)
}

func TestVerifyAcceptsHonestRun(t *testing.T) {
	s := newScene(t, nil, nil)
	r := Verify(honestPolicy(), []Trust{s.ca.trust(RootPlatform)}, []dsse.Envelope{s.build, s.provenance}, []string{"sha256:" + subjectHex})
	if r.ObservedLevel != 3 || !r.Verdict.Accepted() {
		t.Fatalf("level %d, failures %v, problems %v", r.ObservedLevel, r.Verdict.Failures, r.Problems)
	}
	if r.Statement == nil || r.Statement.RunID != "7" || r.Signer == nil || r.Signer.Ext.SignerRef != pinned {
		t.Fatalf("result does not name the accepted statement: %+v", r)
	}
}

// Requirement 6 end to end: a rerun (attempt 2) of the provenance job links to
// the build job's attempt 1 of the same run.
func TestVerifyLinksAcrossAttempts(t *testing.T) {
	s := newScene(t, func(e *sceneExt) { e.attempt = "2" }, nil)
	r := Verify(honestPolicy(), []Trust{s.ca.trust(RootPlatform)}, []dsse.Envelope{s.build, s.provenance}, []string{"sha256:" + subjectHex})
	if r.ObservedLevel != 3 {
		t.Fatalf("level %d: %v %v", r.ObservedLevel, r.Verdict.Failures, r.Problems)
	}
}

// Lean `other_run_outputs_mixed_in`: a build collection of another run does
// not carry subjects for this one.
func TestVerifyRefusesAnotherRunsBuild(t *testing.T) {
	s := newScene(t, nil, func(e *sceneExt) { e.run = "8" })
	r := Verify(honestPolicy(), []Trust{s.ca.trust(RootPlatform)}, []dsse.Envelope{s.build, s.provenance}, []string{"sha256:" + subjectHex})
	if r.ObservedLevel != 0 {
		t.Fatal("accepted a subject built by another run")
	}
	requireRejectedFor(t, r.Verdict, ReqLinked)
}

// Requirement 7: caller-supplied subjects are lookup keys. One the accepted
// statement does not carry is refused, even when the statement itself passes.
func TestReq7CallerSubjectsMustBeCovered(t *testing.T) {
	s := newScene(t, nil, nil)
	r := Verify(honestPolicy(), []Trust{s.ca.trust(RootPlatform)}, []dsse.Envelope{s.build, s.provenance},
		[]string{"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"})
	if r.ObservedLevel != 0 {
		t.Fatal("accepted an artifact the provenance does not name")
	}
	requireRejectedFor(t, r.Verdict, ReqCallerSubjects)
	if r := Verify(honestPolicy(), []Trust{s.ca.trust(RootPlatform)}, []dsse.Envelope{s.build, s.provenance}, nil); r.ObservedLevel != 0 {
		t.Fatal("accepted with no caller subject to look up")
	}
}

// The provenance statement cannot link its own subjects: only attestation
// collections count as build evidence.
func TestVerifyProvenanceIsNotItsOwnBuild(t *testing.T) {
	s := newScene(t, nil, nil)
	r := Verify(honestPolicy(), []Trust{s.ca.trust(RootPlatform)}, []dsse.Envelope{s.provenance}, []string{"sha256:" + subjectHex})
	if r.ObservedLevel != 0 {
		t.Fatal("provenance linked its own subjects")
	}
	requireRejectedFor(t, r.Verdict, ReqLinked)
}

// Signatures verify under the configured roots only; a CA the verifier does
// not trust yields no evidence at all.
func TestVerifyUntrustedCA(t *testing.T) {
	s := newScene(t, nil, nil)
	stranger := newTestCA(t, "stranger")
	r := Verify(honestPolicy(), []Trust{stranger.trust(RootPlatform)}, []dsse.Envelope{s.build, s.provenance}, []string{"sha256:" + subjectHex})
	if r.ObservedLevel != 0 {
		t.Fatal("accepted evidence signed by an untrusted CA")
	}
	requireRejectedFor(t, r.Verdict, ReqProvenance)
}

// The root label is the trust that verified the chain: public Sigstore
// evidence is refused unless the policy trusts that root.
func TestVerifyRootLabelComesFromTrust(t *testing.T) {
	s := newScene(t, nil, nil)
	envs := []dsse.Envelope{s.build, s.provenance}
	if r := Verify(honestPolicy(), []Trust{s.ca.trust(RootPublicSigstore)}, envs, []string{"sha256:" + subjectHex}); r.ObservedLevel != 0 {
		t.Fatal("platform-only policy accepted public Sigstore evidence")
	}
	pol := honestPolicy()
	pol.Roots = []Root{RootPublicSigstore}
	if r := Verify(pol, []Trust{s.ca.trust(RootPublicSigstore)}, envs, []string{"sha256:" + subjectHex}); r.ObservedLevel != 3 {
		t.Fatalf("public Sigstore policy: %v %v", r.Verdict.Failures, r.Problems)
	}
}

// Lean `pull_request_target_accepted` and `self_hosted_runner_accepted`, end
// to end through real certificates.
func TestVerifyRefusesOutsiderTriggerAndSelfHostedRunner(t *testing.T) {
	for name, c := range map[string]struct {
		mut  func(*sceneExt)
		want Requirement
	}{
		"pull_request_target": {func(e *sceneExt) { e.event = "pull_request_target" }, ReqTrigger},
		"pull_request":        {func(e *sceneExt) { e.event = "pull_request" }, ReqTrigger},
		"workflow_run":        {func(e *sceneExt) { e.event = "workflow_run" }, ReqTrigger},
		"self-hosted":         {func(e *sceneExt) { e.runner = "self-hosted" }, ReqHostedRunner},
		"tag pin":             {func(e *sceneExt) { e.ref = WorkflowPath + "@refs/tags/v1" }, ReqSignerRef},
		"moved tag":           {func(e *sceneExt) { e.ref = WorkflowPath + "@refs/tags/v1"; e.sha = other }, ReqSignerDigest},
	} {
		t.Run(name, func(t *testing.T) {
			s := newScene(t, c.mut, nil)
			r := Verify(honestPolicy(), []Trust{s.ca.trust(RootPlatform)}, []dsse.Envelope{s.build, s.provenance}, []string{"sha256:" + subjectHex})
			requireRejectedFor(t, r.Verdict, c.want)
		})
	}
}

// Lean `inline_l2_accepted_as_l3`: inline provenance from the build job is
// not L3, whatever its statement says.
func TestVerifyRefusesInlineProvenance(t *testing.T) {
	ca := newTestCA(t, "platform")
	b := sceneExt{ref: "acme/app/.github/workflows/release.yml@refs/heads/main", sha: commit, repo: "acme/app", commit: commit, run: "7", attempt: "1", event: "push", runner: "github-hosted"}
	subjects := []testSubject{{Name: "file:app", Digest: map[string]string{"sha256": subjectHex}}}
	build := ca.sign(t, b.extensions(), statementJSON(t, attestation.CollectionType, subjects, map[string]any{"name": "build"}))
	// The build job writes the PINNED builder id into provenance it signs.
	inline := ca.sign(t, b.extensions(), statementJSON(t, ProvenancePredicateType, subjects,
		provenancePredicate("https://github.com/"+WorkflowPath+"@"+pinned, "https://github.com/acme/app/actions/runs/7", "acme/app", commit)))
	r := Verify(honestPolicy(), []Trust{ca.trust(RootPlatform)}, []dsse.Envelope{build, inline}, []string{"sha256:" + subjectHex})
	requireRejectedFor(t, r.Verdict, ReqSignerWorkflow)
	requireRejectedFor(t, r.Verdict, ReqBuilderID)
}

// SLSA verifying-artifacts step 2: buildType must be the one provenance.yml
// writes, so its externalParameters are read as intended.
func TestVerifyBuildTypeMustBeExpected(t *testing.T) {
	s := newSceneWithPredicate(t, nil, nil, func(p map[string]any) {
		p["buildDefinition"].(map[string]any)["buildType"] = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
	})
	r := Verify(honestPolicy(), []Trust{s.ca.trust(RootPlatform)}, []dsse.Envelope{s.build, s.provenance}, []string{"sha256:" + subjectHex})
	requireRejectedFor(t, r.Verdict, ReqBuildType)
	if len(r.Verdict.Failures) != 1 {
		t.Fatalf("want only the buildType failure, got %v", r.Verdict.Failures)
	}
}

// SLSA verifying-artifacts step 2: unknown externalParameters are rejected,
// and the known ones must equal the signer certificate's Build Config URI.
func TestVerifyExternalParameters(t *testing.T) {
	workflow := func(p map[string]any) map[string]any {
		return p["buildDefinition"].(map[string]any)["externalParameters"].(map[string]any)["workflow"].(map[string]any)
	}
	for name, mutate := range map[string]func(p map[string]any){
		"unknown top-level key": func(p map[string]any) {
			p["buildDefinition"].(map[string]any)["externalParameters"].(map[string]any)["inputs"] = map[string]any{"cmd": "make"}
		},
		"unknown workflow key": func(p map[string]any) { workflow(p)["script"] = "make" },
		"missing ref":          func(p map[string]any) { delete(workflow(p), "ref") },
		"ref not the cert's":   func(p map[string]any) { workflow(p)["ref"] = "refs/heads/feature" },
		"path not the cert's":  func(p map[string]any) { workflow(p)["path"] = ".github/workflows/other.yml" },
		"repository not the cert's": func(p map[string]any) {
			workflow(p)["repository"] = "https://github.com/mallory/app"
		},
		"non-string value": func(p map[string]any) { workflow(p)["ref"] = 7 },
		"absent":           func(p map[string]any) { delete(p["buildDefinition"].(map[string]any), "externalParameters") },
	} {
		t.Run(name, func(t *testing.T) {
			s := newSceneWithPredicate(t, nil, nil, mutate)
			r := Verify(honestPolicy(), []Trust{s.ca.trust(RootPlatform)}, []dsse.Envelope{s.build, s.provenance}, []string{"sha256:" + subjectHex})
			requireRejectedFor(t, r.Verdict, ReqExternalParameters)
		})
	}
}

// The level comes from the trusted-builder catalog keyed by builder.id: a
// policy pinning some other provenance workflow observes nothing, even when
// every Accept check passes for it.
func TestVerifyLevelComesFromTrustedBuilderCatalog(t *testing.T) {
	const otherPath = "acme/tools/.github/workflows/provenance.yml"
	s := newScene(t, func(e *sceneExt) { e.ref = otherPath + "@" + pinned }, nil)
	pol := honestPolicy()
	pol.Path = otherPath
	r := Verify(pol, []Trust{s.ca.trust(RootPlatform)}, []dsse.Envelope{s.build, s.provenance}, []string{"sha256:" + subjectHex})
	if r.ObservedLevel != 0 {
		t.Fatal("an uncatalogued builder reached L3")
	}
	requireRejectedFor(t, r.Verdict, ReqTrustedBuilder)
	if len(r.Verdict.Failures) != 1 {
		t.Fatalf("want only the catalog failure, got %v", r.Verdict.Failures)
	}
}

// A provenance envelope signed with a bare key (no Fulcio certificate) that
// claims the isolated workflow's builder.id carries no signer identity and
// is not evidence at all.
func TestVerifyRefusesKeySignedProvenance(t *testing.T) {
	s := newScene(t, nil, nil)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptoutil.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	subjects := []testSubject{{Name: "file:app", Digest: map[string]string{"sha256": subjectHex}}}
	fake, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(statementJSON(t, ProvenancePredicateType, subjects,
		provenancePredicate("https://github.com/"+WorkflowPath+"@"+pinned, "https://github.com/acme/app/actions/runs/7", "acme/app", commit))),
		dsse.SignWithSigners(signer))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := signer.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	trust := s.ca.trust(RootPlatform)
	trust.Options = append(trust.Options, dsse.VerifyWithVerifiers(verifier))
	r := Verify(honestPolicy(), []Trust{trust}, []dsse.Envelope{s.build, fake}, []string{"sha256:" + subjectHex})
	if r.ObservedLevel != 0 {
		t.Fatal("key-signed provenance reached L3")
	}
	requireRejectedFor(t, r.Verdict, ReqProvenance)
}
