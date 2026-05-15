// Copyright 2024 The Witness Contributors
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

package workflow

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

func TestValidateRunOpts_NoStepName(t *testing.T) {
	ro := runOptions{}
	err := validateRunOpts(ro)
	if err == nil {
		t.Fatal("expected error for empty step name")
	}
	if err.Error() != "step name is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateRunOpts_NoSignersNotInsecure(t *testing.T) {
	ro := runOptions{stepName: "build"}
	err := validateRunOpts(ro)
	if err == nil {
		t.Fatal("expected error when no signers and not insecure")
	}
}

func TestValidateRunOpts_InsecureNoSigners(t *testing.T) {
	ro := runOptions{stepName: "build", insecure: true}
	err := validateRunOpts(ro)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunWithInsecure(t *testing.T) {
	ro := runOptions{}
	RunWithInsecure(true)(&ro)
	if !ro.insecure {
		t.Error("insecure should be true")
	}
	RunWithInsecure(false)(&ro)
	if ro.insecure {
		t.Error("insecure should be false")
	}
}

func TestRunWithIgnoreErrors(t *testing.T) {
	ro := runOptions{}
	RunWithIgnoreErrors(true)(&ro)
	if !ro.ignoreErrors {
		t.Error("ignoreErrors should be true")
	}
}

func TestRun_EmptyStepName(t *testing.T) {
	_, err := Run("", RunWithInsecure(true))
	if err == nil {
		t.Fatal("expected error for empty step name")
	}
}

func TestRun_InsecureNoAttestors(t *testing.T) {
	result, err := Run("test-step", RunWithInsecure(true))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Collection.Name != "test-step" {
		t.Errorf("Collection.Name = %q, want %q", result.Collection.Name, "test-step")
	}
}

func TestRunWithExports_InsecureNoAttestors(t *testing.T) {
	results, err := RunWithExports("test-step", RunWithInsecure(true))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	// The last result should be the collection
	last := results[len(results)-1]
	if last.Collection.Name != "test-step" {
		t.Errorf("Collection.Name = %q, want %q", last.Collection.Name, "test-step")
	}
}

// TestRun_InsecureAdditionalSubjectsAppliedToCollection guards the Gemini/Codex
// critical (PR #4119): additional subjects supplied via RunWithAdditionalSubjects
// MUST land on the collection's subject set in insecure mode too. The original
// implementation gated the merge inside `if !ro.insecure`, which silently
// dropped user-supplied --subjects whenever cilock was invoked without a
// signer — a correctness bug with no error signal. We verify the merged set is
// exposed on RunResult.CollectionSubjects so unsigned-envelope callers can use
// the same subjects the signed path would have used.
func TestRun_InsecureAdditionalSubjectsAppliedToCollection(t *testing.T) {
	sha256Hex := strings.Repeat("ab", 32)

	extra := map[string]cryptoutil.DigestSet{
		"injected-subject": {
			cryptoutil.DigestValue{Hash: crypto.SHA256}: sha256Hex,
		},
		"external-id:deadbeef-1234-5678-9abc-000000000001": {},
	}

	results, err := RunWithExports(
		"insecure-step",
		RunWithInsecure(true),
		RunWithAdditionalSubjects(extra),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least the collection result")
	}

	// Collection result is the last element.
	collection := results[len(results)-1]
	if collection.Collection.Name != "insecure-step" {
		t.Fatalf("unexpected Collection.Name=%q", collection.Collection.Name)
	}

	// The critical assertion: insecure mode must still carry the user's
	// subjects on RunResult so unsigned-envelope callers can emit them.
	if collection.CollectionSubjects == nil {
		t.Fatal("expected CollectionSubjects populated in insecure mode, got nil " +
			"(regression of Gemini critical in PR #4119: --subjects silently dropped)")
	}
	for name := range extra {
		if _, ok := collection.CollectionSubjects[name]; !ok {
			t.Errorf("CollectionSubjects missing user-supplied key %q; got keys=%v",
				name, keysOf(collection.CollectionSubjects))
		}
	}

	// Sanity: insecure mode still produces an unsigned envelope with no sigs.
	if len(collection.SignedEnvelope.Signatures) != 0 {
		t.Errorf("insecure mode should produce an unsigned envelope; got %d signatures",
			len(collection.SignedEnvelope.Signatures))
	}
}

// TestRun_SignedAdditionalSubjectsInStatementPayload verifies the pre-existing
// signed-path contract still holds: additional subjects are written to the
// in-toto statement payload when a signer is configured. This is the companion
// check to TestRun_InsecureAdditionalSubjectsAppliedToCollection and guards
// against the refactor silently dropping the signed case.
func TestRun_SignedAdditionalSubjectsInStatementPayload(t *testing.T) {
	signer := newTestSigner(t)

	sha256Hex := strings.Repeat("cd", 32)
	extra := map[string]cryptoutil.DigestSet{
		"signed-subject": {
			cryptoutil.DigestValue{Hash: crypto.SHA256}: sha256Hex,
		},
	}

	results, err := RunWithExports(
		"signed-step",
		RunWithSigners(signer),
		RunWithAdditionalSubjects(extra),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least the collection result")
	}
	collection := results[len(results)-1]

	if _, ok := collection.CollectionSubjects["signed-subject"]; !ok {
		t.Errorf("CollectionSubjects missing user-supplied key in signed mode; got=%v",
			keysOf(collection.CollectionSubjects))
	}

	// Decode the DSSE payload (in-memory it's raw JSON bytes of the
	// in-toto Statement; base64 encoding is applied only at marshal time).
	if len(collection.SignedEnvelope.Payload) == 0 {
		t.Fatal("signed envelope has empty payload")
	}
	var stmt intoto.Statement
	if err := json.Unmarshal(collection.SignedEnvelope.Payload, &stmt); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}

	found := false
	for _, s := range stmt.Subject {
		if s.Name == "signed-subject" {
			found = true
			break
		}
	}
	if !found {
		names := make([]string, 0, len(stmt.Subject))
		for _, s := range stmt.Subject {
			names = append(names, s.Name)
		}
		t.Errorf("signed in-toto statement missing user-supplied subject; got names=%v", names)
	}
}

// keysOf is a small helper used by the subject-merge tests to produce stable
// failure output.
func keysOf(m map[string]cryptoutil.DigestSet) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
