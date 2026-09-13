// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyVerdict_DigestAlgorithms(t *testing.T) {
	const name = "https://aflock.ai/attestations/git/v0.1/commithash:" + gitSHA1Hex
	for _, tc := range []struct {
		name      string
		supplied  string
		algorithm string
		digest    string
		matched   bool
	}{
		{"sha1 commit", "sha1:" + gitSHA1Hex, "sha1", gitSHA1Hex, true},
		{"unmatched sha1", "sha1:" + gitSHA1Hex, "sha1", strings.Repeat("a", 40), false},
		{"sha1 must not bind sha256 with same hex", "sha1:" + gitSHA1Hex, "sha256", gitSHA1Hex, false},
		{"sha256 must not bind sha1 with same hex", "sha256:" + gitSHA1Hex, "sha1", gitSHA1Hex, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			results := map[string]policy.StepResult{
				"source": passedStep("source", intoto.Subject{Name: name, Digest: map[string]string{tc.algorithm: tc.digest}}),
			}
			var jsonOut, stderr bytes.Buffer
			require.NoError(t, writeVerifyVerdictJSON(&jsonOut, buildVerifyVerdict([]string{tc.supplied}, results, nil)))
			var verdict VerifyVerdict
			require.NoError(t, json.Unmarshal(jsonOut.Bytes(), &verdict))
			assert.True(t, verdict.Passed, "rendering must not change the policy result")
			writeVerifyBindingLines(&stderr, []string{tc.supplied}, results, nil)
			if tc.matched {
				assert.Equal(t, "source", verdict.Step)
				assert.Equal(t, tc.supplied, verdict.MatchedSubject)
				assert.Equal(t, name, verdict.ObservedSubjectName)
				assert.Contains(t, stderr.String(), "verified: "+tc.supplied+` bound to step "source" subject "git/v0.1/commithash:`+gitSHA1Hex+`"`)
				assert.NotContains(t, stderr.String(), "did NOT match")
			} else {
				assert.Empty(t, verdict.Step)
				assert.Empty(t, verdict.MatchedSubject)
				assert.Empty(t, verdict.ObservedSubjectName)
				assert.NotContains(t, stderr.String(), "verified:")
				assert.Contains(t, stderr.String(), "supplied artifact "+tc.supplied+" did NOT match")
			}
		})
	}
}

func TestVerifyVerdict_SameHexDifferentAlgorithmsRemainDistinct(t *testing.T) {
	results := map[string]policy.StepResult{
		"source": passedStep("source", intoto.Subject{
			Name: "commithash:" + gitSHA1Hex, Digest: map[string]string{"sha1": gitSHA1Hex},
		}),
	}
	var stderr bytes.Buffer
	writeVerifyBindingLines(&stderr, []string{"sha1:" + gitSHA1Hex, "sha256:" + gitSHA1Hex}, results, nil)
	assert.Contains(t, stderr.String(), "verified: sha1:"+gitSHA1Hex)
	assert.Contains(t, stderr.String(), "supplied artifact sha256:"+gitSHA1Hex+" did NOT match")
	assert.NotContains(t, stderr.String(), "verified: sha256:")

	results["source"] = passedStep("source", intoto.Subject{
		Name: "both", Digest: map[string]string{"sha1": gitSHA1Hex, "sha256": gitSHA1Hex},
	})
	stderr.Reset()
	writeVerifyBindingLines(&stderr, []string{"sha1:" + gitSHA1Hex, "sha256:" + gitSHA1Hex}, results, nil)
	assert.Contains(t, stderr.String(), "verified: sha1:"+gitSHA1Hex)
	assert.Contains(t, stderr.String(), "verified: sha256:"+gitSHA1Hex)
	assert.NotContains(t, stderr.String(), "did NOT match")
}

// passedStep builds a StepResult with one passing collection carrying the given
// in-toto subjects, for verdict-binding tests.
func passedStep(step string, subjects ...intoto.Subject) policy.StepResult {
	return policy.StepResult{
		Step: step,
		Passed: []policy.PassedCollection{{
			Collection: source.CollectionVerificationResult{
				CollectionEnvelope: source.CollectionEnvelope{
					Statement: intoto.Statement{Subject: subjects},
				},
			},
		}},
	}
}

// passedStepWithProducts builds a StepResult whose passing collection carries a
// real product v0.3 attestation with inline Merkle leaves over `digests`. With
// rootOverride == "" the root is computed canonically (VerifyInlineLeaves
// passes); a non-empty rootOverride ships leaves that do NOT fold to the
// committed root (a forged/tampered attestation). The top-level subject is only
// the tree root — the individual file digests live as leaves, exactly the shape
// that exposed the false-positive binding bug.
func passedStepWithProducts(t *testing.T, step string, digests map[string]string, rootOverride string) policy.StepResult {
	t.Helper()
	env := productCollectionEnvelope(t, digests, true, rootOverride)
	var stmt struct {
		Subject   []intoto.Subject `json:"subject"`
		Predicate json.RawMessage  `json:"predicate"`
	}
	if err := json.Unmarshal(env.Payload, &stmt); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	var coll attestation.Collection
	if err := json.Unmarshal(stmt.Predicate, &coll); err != nil {
		t.Fatalf("unmarshal collection: %v", err)
	}
	return policy.StepResult{
		Step: step,
		Passed: []policy.PassedCollection{{
			Collection: source.CollectionVerificationResult{
				CollectionEnvelope: source.CollectionEnvelope{
					Statement:  intoto.Statement{Subject: stmt.Subject},
					Collection: coll,
				},
			},
		}},
	}
}

// TestVerifyVerdict_DirectSubjectBinding proves a supplied digest that matches a
// top-level subject is reported with the step + observed subject name (rec #2).
func TestVerifyVerdict_DirectSubjectBinding(t *testing.T) {
	const digest = "6f42fdfbd2689cc842513fd88e27161d9b4fc765e5d0e291edc6483a50222720"
	results := map[string]policy.StepResult{
		"build": passedStep("build", intoto.Subject{
			Name:   "https://aflock.ai/attestations/git/v0.1/remote:git@github.com:acme/widget.git",
			Digest: map[string]string{"sha256": digest},
		}),
	}

	v := buildVerifyVerdict([]string{"sha256:" + digest}, results, nil)
	if !v.Passed {
		t.Fatal("verdict should be passed")
	}
	if v.Step != "build" {
		t.Errorf("step should be build, got %q", v.Step)
	}
	if v.MatchedSubject != "sha256:"+digest {
		t.Errorf("matchedSubject mismatch: %q", v.MatchedSubject)
	}
	if !strings.Contains(v.ObservedSubjectName, "remote:git@github.com:acme/widget.git") {
		t.Errorf("observedSubjectName mismatch: %q", v.ObservedSubjectName)
	}

	var buf bytes.Buffer
	writeVerifyBindingLines(&buf, []string{"sha256:" + digest}, results, nil)
	out := buf.String()
	if !strings.Contains(out, "verified: sha256:"+digest) {
		t.Errorf("binding line missing supplied digest:\n%s", out)
	}
	if !strings.Contains(out, `step "build"`) {
		t.Errorf("binding line missing step name:\n%s", out)
	}
	// The predicate-URI prefix is trimmed for readability.
	if !strings.Contains(out, `subject "git/v0.1/remote:`) {
		t.Errorf("binding line should carry the trimmed subject name:\n%s", out)
	}
}

// TestVerifyVerdict_UnboundArtifactMakesNoFalseClaim is the regression guard for
// a critical false-positive a code review caught: when the supplied digest
// matches NO top-level subject AND is NOT a verified leaf, the verdict must NOT
// fabricate a binding just because some step passed. The old code reported
// Passed:true with the passing step named and a "via its Merkle product tree
// (inclusion proof)" line — falsely asserting the operator's artifact was part
// of verified evidence when it was not.
func TestVerifyVerdict_UnboundArtifactMakesNoFalseClaim(t *testing.T) {
	const unboundDigest = "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888"
	results := map[string]policy.StepResult{
		"build": passedStep("build", intoto.Subject{
			// Only a tree-root subject is present — the supplied digest won't match
			// it, and the collection carries no inline leaves to bind it either.
			Name:   "https://aflock.ai/attestations/product/v0.3/tree:products",
			Digest: map[string]string{"sha256": "deadbeef00000000000000000000000000000000000000000000000000000000"},
		}),
	}

	v := buildVerifyVerdict([]string{"sha256:" + unboundDigest}, results, nil)
	if !v.Passed {
		t.Fatal("policy still passed on its own subjects; Passed must stay true")
	}
	if v.Step != "" || v.MatchedSubject != "" || v.ObservedSubjectName != "" {
		t.Errorf("unbound artifact must NOT be reported as bound, got step=%q subject=%q name=%q",
			v.Step, v.MatchedSubject, v.ObservedSubjectName)
	}

	var buf bytes.Buffer
	writeVerifyBindingLines(&buf, []string{"sha256:" + unboundDigest}, results, nil)
	out := buf.String()
	if strings.Contains(out, "verified:") || strings.Contains(out, "inclusion proof") {
		t.Errorf("must not print a fabricated binding line for an unbound artifact:\n%s", out)
	}
	if !strings.Contains(out, "did NOT match") {
		t.Errorf("should surface an honest 'did NOT match' note:\n%s", out)
	}
}

// TestVerifyVerdict_VerifiedLeafBinding proves the legitimate inclusion case: a
// supplied digest that is a real product leaf (verified to reconstruct the
// signed Merkle root) DOES bind, and is reported as a root-verified leaf.
func TestVerifyVerdict_VerifiedLeafBinding(t *testing.T) {
	const leafDigest = "1111111111111111111111111111111111111111111111111111111111111111"
	digests := map[string]string{
		"bin/app":   leafDigest,
		"bin/other": "2222222222222222222222222222222222222222222222222222222222222222",
	}
	results := map[string]policy.StepResult{
		"build": passedStepWithProducts(t, "build", digests, ""),
	}

	v := buildVerifyVerdict([]string{"sha256:" + leafDigest}, results, nil)
	if v.Step != "build" {
		t.Errorf("verified leaf should bind to its step, got %q", v.Step)
	}
	if v.MatchedSubject != "sha256:"+leafDigest {
		t.Errorf("matchedSubject should be the leaf digest, got %q", v.MatchedSubject)
	}

	var buf bytes.Buffer
	writeVerifyBindingLines(&buf, []string{"sha256:" + leafDigest}, results, nil)
	out := buf.String()
	if !strings.Contains(out, "verified: sha256:"+leafDigest) {
		t.Errorf("should print a verified binding line for the real leaf:\n%s", out)
	}
	if !strings.Contains(out, "root-verified") {
		t.Errorf("leaf binding line should flag it was root-verified:\n%s", out)
	}
	// Identical hex under another algorithm must not inherit the SHA-256 leaf
	// binding. This deliberately bypasses CLI length validation to test the renderer.
	assert.Empty(t, buildVerifyVerdict([]string{"sha1:" + leafDigest}, results, nil).MatchedSubject)
	buf.Reset()
	writeVerifyBindingLines(&buf, []string{"sha1:" + leafDigest}, results, nil)
	assert.NotContains(t, buf.String(), "verified:")
	assert.Contains(t, buf.String(), "supplied artifact sha1:"+leafDigest+" did NOT match")
}

// TestVerifyVerdict_TamperedLeafDoesNotBind proves a leaf set that does NOT
// reconstruct to the signed Merkle root (a forged/inconsistent attestation)
// never produces a binding — VerifyInlineLeaves fails closed.
func TestVerifyVerdict_TamperedLeafDoesNotBind(t *testing.T) {
	const leafDigest = "1111111111111111111111111111111111111111111111111111111111111111"
	digests := map[string]string{"bin/app": leafDigest}
	// Ship the real leaves under a bogus committed root so VerifyInlineLeaves fails.
	const bogusRoot = "deadbeef00000000000000000000000000000000000000000000000000000000"
	results := map[string]policy.StepResult{"build": passedStepWithProducts(t, "build", digests, bogusRoot)}

	v := buildVerifyVerdict([]string{"sha256:" + leafDigest}, results, nil)
	if v.Step != "" || v.MatchedSubject != "" {
		t.Errorf("a leaf that fails root verification must NOT bind, got step=%q subject=%q", v.Step, v.MatchedSubject)
	}
	var stderr bytes.Buffer
	writeVerifyBindingLines(&stderr, []string{"sha256:" + leafDigest}, results, nil)
	assert.NotContains(t, stderr.String(), "verified:")
	assert.Contains(t, stderr.String(), "supplied artifact sha256:"+leafDigest+" did NOT match")
}

// TestVerifyVerdict_JSONShape proves the JSON verdict serializes the keys the
// rec calls for (rec #9), with passed as a bool.
func TestVerifyVerdict_JSONShape(t *testing.T) {
	const digest = "6f42fdfbd2689cc842513fd88e27161d9b4fc765e5d0e291edc6483a50222720"
	results := map[string]policy.StepResult{
		"build": passedStep("build", intoto.Subject{
			Name:   "https://aflock.ai/attestations/git/v0.1/remote:x",
			Digest: map[string]string{"sha256": digest},
		}),
	}
	var buf bytes.Buffer
	if err := writeVerifyVerdictJSON(&buf, buildVerifyVerdict([]string{"sha256:" + digest}, results, nil)); err != nil {
		t.Fatalf("writeVerifyVerdictJSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf.String())
	}
	if got["passed"] != true {
		t.Errorf("passed should be true, got %#v", got["passed"])
	}
	for _, k := range []string{"step", "matchedSubject"} {
		if _, ok := got[k]; !ok {
			t.Errorf("JSON missing key %q:\n%s", k, buf.String())
		}
	}
	if !strings.HasSuffix(buf.String(), "}\n") {
		t.Errorf("JSON output should end with }\\n")
	}
}

// TestVerifyVerdict_FailedShape proves a failed verdict serializes passed:false
// and carries no binding fields.
func TestVerifyVerdict_FailedShape(t *testing.T) {
	var buf bytes.Buffer
	if err := writeVerifyVerdictJSON(&buf, VerifyVerdict{Passed: false}); err != nil {
		t.Fatalf("writeVerifyVerdictJSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if got["passed"] != false {
		t.Errorf("passed should be false, got %#v", got["passed"])
	}
	if _, ok := got["step"]; ok {
		t.Errorf("failed verdict should omit step, got %#v", got["step"])
	}
}

// TestVerifyVerdict_NoSuppliedDigestsNoOp proves the binding writer is a no-op
// when no artifact digest was supplied (e.g. policy-only checks).
func TestVerifyVerdict_NoSuppliedDigestsNoOp(t *testing.T) {
	var buf bytes.Buffer
	writeVerifyBindingLines(&buf, nil, map[string]policy.StepResult{"build": passedStep("build")}, nil)
	if buf.Len() != 0 {
		t.Errorf("expected no output with no supplied digests, got:\n%s", buf.String())
	}
}
