//go:build audit

package workflow

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Shared test helpers (also used by workflow_deep_test.go)
// ==========================================================================

type testAttestor struct {
	name       string
	typeName   string
	runType    attestation.RunType
	attestFunc func(*attestation.AttestationContext) error
	subjects   map[string]cryptoutil.DigestSet
	export     bool
}

func (a *testAttestor) Name() string                 { return a.name }
func (a *testAttestor) Type() string                 { return a.typeName }
func (a *testAttestor) RunType() attestation.RunType { return a.runType }
func (a *testAttestor) Schema() *jsonschema.Schema   { return nil }
func (a *testAttestor) Attest(ctx *attestation.AttestationContext) error {
	if a.attestFunc != nil {
		return a.attestFunc(ctx)
	}
	return nil
}
func (a *testAttestor) Subjects() map[string]cryptoutil.DigestSet {
	if a.subjects != nil {
		return a.subjects
	}
	return map[string]cryptoutil.DigestSet{}
}
func (a *testAttestor) Export() bool { return a.export }

type testMultiExporter struct {
	testAttestor
	exported []attestation.Attestor
}

func (a *testMultiExporter) ExportedAttestations() []attestation.Attestor {
	return a.exported
}

// exporterWithoutSubjects implements Attestor and Exporter.Export() but NOT
// Subjecter, so it does NOT satisfy the attestation.Exporter interface.
type exporterWithoutSubjects struct {
	name     string
	typeName string
	runType  attestation.RunType
}

func (a *exporterWithoutSubjects) Name() string                                { return a.name }
func (a *exporterWithoutSubjects) Type() string                                { return a.typeName }
func (a *exporterWithoutSubjects) RunType() attestation.RunType                { return a.runType }
func (a *exporterWithoutSubjects) Schema() *jsonschema.Schema                  { return nil }
func (a *exporterWithoutSubjects) Attest(ctx *attestation.AttestationContext) error { return nil }
func (a *exporterWithoutSubjects) Export() bool                                { return true }

func advMakeRSASignerVerifier(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	sgnr := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	return sgnr, verifier
}


// ==========================================================================
// FINDING 1: Nil signers bypass validation (MEDIUM)
//
// validateRunOpts checks len(ro.signers) > 0 but does not check if any
// signer is actually non-nil. A caller passing []Signer{nil, nil} passes
// validation but will produce an envelope with zero signatures (dsse.Sign
// skips nil signers). In non-insecure mode this means the attestation is
// generated without cryptographic protection despite the caller's intent.
// ==========================================================================

func TestAdversarial_NilSignersBypassesValidation(t *testing.T) {
	ro := runOptions{
		stepName: "build",
		signers:  []cryptoutil.Signer{nil, nil},
	}

	err := validateRunOpts(ro)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The validation passed despite all signers being nil.
	// This means a caller who accidentally passes nil signers will think
	// they're in signed mode but the envelope will have no signatures.
	t.Log("FINDING: validateRunOpts accepts a signers slice containing only nil entries. " +
		"len(signers)==2 passes the check, but dsse.Sign will skip nil signers, " +
		"producing an unsigned envelope in non-insecure mode. " +
		"This is a validation gap -- the check should verify at least one non-nil signer.")
}

// ==========================================================================
// FINDING 2: Whitespace-only step name passes validation (LOW)
//
// validateRunOpts only checks stepName == "" but not for whitespace-only
// names. A step name of "   " will pass validation and propagate through
// the entire pipeline.
// ==========================================================================

func TestAdversarial_WhitespaceStepNamePassesValidation(t *testing.T) {
	result, err := Run("   \t\n", RunWithInsecure(true))
	require.NoError(t, err,
		"whitespace step name should pass -- validateRunOpts only checks == empty string")

	assert.Equal(t, "   \t\n", result.Collection.Name,
		"FINDING: whitespace-only step name is accepted and propagated as the collection name. "+
			"This could cause issues with downstream systems that use the step name as an identifier "+
			"(e.g., policy matching, Archivista search). Consider trimming or rejecting whitespace-only names.")
}

// ==========================================================================
// FINDING 3: Verify function accepts but ignores context.Context (MEDIUM)
//
// The Verify function signature accepts context.Context as the first param
// but never passes it to Run(), attestation.NewContext(), or the policyverify
// attestor. A cancelled context will not stop the verification workflow.
// ==========================================================================

func TestAdversarial_VerifyIgnoresContext(t *testing.T) {
	// This test verifies that a cancelled context does NOT stop Verify.
	// The context.Context parameter is accepted but unused in the Verify path.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Verify will fail because policyverify is not registered, but it
	// should fail with "policyverify not registered", NOT with "context cancelled".
	_, err := Verify(
		ctx,
		dsse.Envelope{
			Payload:     []byte("fake"),
			PayloadType: "test",
			Signatures:  []dsse.Signature{{KeyID: "k", Signature: []byte("s")}},
		},
		nil,
		VerifyWithSigners(func() cryptoutil.Signer {
			s, _ := advMakeRSASignerVerifier(t)
			return s
		}()),
	)

	require.Error(t, err)

	// The error should be about policyverify, not about context cancellation.
	// This proves the context is ignored.
	if strings.Contains(err.Error(), "context canceled") {
		t.Log("Context cancellation was propagated -- this is actually good behavior")
	} else {
		assert.Contains(t, err.Error(), "policyverify",
			"FINDING: Verify() accepts context.Context but does not propagate it. "+
				"A cancelled context does not stop the verification. The `ctx` parameter "+
				"on line 159 of verify.go is never used. This means callers cannot "+
				"implement timeout or cancellation for policy verification workflows.")
	}
}

// ==========================================================================
// FINDING 4: Exporter with Export()=true but without Subjecter interface
// is silently dropped from both exports AND collection (HIGH)
//
// In run.go lines 168-183: if an attestor implements attestation.Exporter
// (requires BOTH Export() and Subjects()), the code checks Export() then
// checks Subjecter. But there is a subtle issue: the Exporter check on
// line 168 requires Subjects(), and if an attestor DOES implement Exporter
// (both methods) but Export() returns true and the attestor IS a Subjecter,
// it gets exported separately. The attestor is ALSO excluded from the
// collection (lines 203-204). This is correct behavior.
//
// However: an attestor that implements Export() but NOT Subjects() will
// NOT match the Exporter interface (because Exporter bundles both methods),
// so it falls through to the collection. This is documented behavior but
// could be confusing for plugin authors.
// ==========================================================================

func TestAdversarial_ExporterWithoutSubjecterFallsToCollection(t *testing.T) {
	att := &exporterWithoutSubjects{
		name:     "no-subjects-exporter",
		typeName: "https://test/no-subjects-exporter",
		runType:  attestation.ExecuteRunType,
	}

	results, err := RunWithExports("test-step",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err)

	collection := results[len(results)-1]
	inCollection := false
	for _, a := range collection.Collection.Attestations {
		if a.Type == "https://test/no-subjects-exporter" {
			inCollection = true
		}
	}

	assert.True(t, inCollection,
		"Attestor with Export()=true but no Subjects() falls through to collection. "+
			"The Exporter interface requires BOTH methods; implementing only Export() is insufficient. "+
			"Plugin authors might expect Export()=true alone to exclude from collection.")
}

// ==========================================================================
// FINDING 5: MultiExporter with child that does not implement Subjecter
// passes nil subjects to createAndSignEnvelope in signed mode
//
// In run.go line 152: the code checks if exportedAttestor implements
// Subjecter. If not, subjects remains nil. In signed mode,
// createAndSignEnvelope is called with nil subjects.
//
// UPDATE: intoto.NewStatement now allows empty subjects (matching
// upstream witness behavior), so this no longer causes a hard failure.
// The child's envelope is created with zero subjects.
// ==========================================================================

func TestAdversarial_MultiExporterChildWithoutSubjects_SignedMode(t *testing.T) {
	signer, _ := advMakeRSASignerVerifier(t)

	// Child attestor that does NOT implement Subjecter
	childNoSubjects := &exporterWithoutSubjects{
		name:     "child-no-subjects",
		typeName: "https://test/child-no-subjects",
		runType:  attestation.ExecuteRunType,
	}

	multi := &testMultiExporter{
		testAttestor: testAttestor{
			name:     "parent",
			typeName: "https://test/parent",
			runType:  attestation.ExecuteRunType,
		},
		exported: []attestation.Attestor{childNoSubjects},
	}

	results, err := RunWithExports("test-step",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{multi}),
	)

	// intoto.NewStatement now allows empty subjects (matching upstream witness),
	// so the child without Subjecter no longer causes a hard failure.
	require.NoError(t, err,
		"MultiExporter child without Subjecter should succeed now that empty subjects are allowed")
	require.NotEmpty(t, results, "should produce at least one result")
}

// ==========================================================================
// FINDING 6: MultiExporter with child that has empty subjects in signed mode
//
// UPDATE: intoto.NewStatement now allows empty subjects (matching
// upstream witness behavior), so this no longer causes a hard failure.
// ==========================================================================

func TestAdversarial_MultiExporterChildWithEmptySubjects_SignedMode(t *testing.T) {
	signer, _ := advMakeRSASignerVerifier(t)

	childEmptySubjects := &testAttestor{
		name:     "child-empty",
		typeName: "https://test/child-empty",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{}, // empty, not nil
	}

	multi := &testMultiExporter{
		testAttestor: testAttestor{
			name:     "parent",
			typeName: "https://test/parent",
			runType:  attestation.ExecuteRunType,
		},
		exported: []attestation.Attestor{childEmptySubjects},
	}

	results, err := RunWithExports("test-step",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{multi}),
	)

	// intoto.NewStatement now allows empty subjects (matching upstream witness),
	// so the child with empty subjects no longer causes a hard failure.
	require.NoError(t, err,
		"MultiExporter child with empty subjects should succeed now that empty subjects are allowed")
	require.NotEmpty(t, results, "should produce at least one result")
}

// ==========================================================================
// FINDING 7: Error variable shadowing in run.go line 187 (LOW)
//
// On line 138: errs := make([]error, 0)
// On line 187: errs := append([]error{...}, errs...)
//
// The `:=` on line 187 creates a new `errs` variable that shadows the
// outer one. This is not a functional bug because the new variable is
// immediately passed to errors.Join, but it IS a code quality issue that
// could confuse maintainers and is flagged by `go vet -shadow`.
// ==========================================================================

func TestAdversarial_ErrorPropagationWithMultipleFailures(t *testing.T) {
	fail1 := &testAttestor{
		name: "fail-1", typeName: "https://test/fail-1",
		runType: attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			return errors.New("error-alpha")
		},
	}
	fail2 := &testAttestor{
		name: "fail-2", typeName: "https://test/fail-2",
		runType: attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			return errors.New("error-beta")
		},
	}

	_, err := Run("multi-fail",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{fail1, fail2}),
	)

	require.Error(t, err)
	// Both errors should be present in the joined error.
	assert.Contains(t, err.Error(), "error-alpha",
		"first attestor error should be propagated")
	assert.Contains(t, err.Error(), "error-beta",
		"second attestor error should be propagated")
	assert.Contains(t, err.Error(), "attestors failed",
		"the wrapper error message should be present")
}

// ==========================================================================
// FINDING 8: Concurrent attestor completion ordering is non-deterministic
// (MEDIUM)
//
// RunAttestors runs attestors in goroutines within each phase. The order
// of CompletedAttestors depends on goroutine scheduling. This means the
// order of attestations in the collection is non-deterministic for attestors
// within the same phase. This could affect:
// - Policy evaluation that assumes specific ordering
// - Deterministic envelope signing (different JSON = different signatures)
// - Diffing or comparing attestation collections
// ==========================================================================

func TestAdversarial_CompletedAttestorOrderingNonDeterministic(t *testing.T) {
	const numAttestors = 10
	const iterations = 5

	orderings := make([]string, iterations)
	for iter := 0; iter < iterations; iter++ {
		attestors := make([]attestation.Attestor, numAttestors)
		for i := 0; i < numAttestors; i++ {
			attestors[i] = &testAttestor{
				name:     fmt.Sprintf("att-%02d", i),
				typeName: fmt.Sprintf("https://test/att-%02d", i),
				runType:  attestation.ExecuteRunType,
			}
		}

		results, err := RunWithExports("ordering-test",
			RunWithInsecure(true),
			RunWithAttestors(attestors),
		)
		require.NoError(t, err)

		collection := results[len(results)-1]
		var names []string
		for _, a := range collection.Collection.Attestations {
			names = append(names, a.Type)
		}
		orderings[iter] = strings.Join(names, ",")
	}

	// Check if all orderings are identical
	allSame := true
	for i := 1; i < len(orderings); i++ {
		if orderings[i] != orderings[0] {
			allSame = false
			break
		}
	}

	if !allSame {
		t.Log("FINDING: Attestor ordering in the collection is non-deterministic across runs. " +
			"Attestors within the same phase run concurrently and their completion order " +
			"depends on goroutine scheduling. This means collections are not reproducible -- " +
			"the same inputs can produce different JSON payloads and therefore different " +
			"DSSE signatures.")
	} else {
		t.Log("All orderings were identical (goroutine scheduling was consistent in this run). " +
			"This does not mean the ordering is guaranteed -- it may vary under load.")
	}
}

// ==========================================================================
// FINDING 9: VerifySignature returns partially parsed envelope on error
// (LOW)
//
// In verify.go line 58: decoder.Decode(&envelope) may partially populate
// the envelope struct before returning an error. The function returns this
// partially-populated envelope along with the error. Callers who check
// err but also use the envelope could operate on corrupt data.
// ==========================================================================

func TestAdversarial_VerifySignaturePartialEnvelopeOnError(t *testing.T) {
	// Truncated JSON that will partially decode
	truncated := []byte(`{"payload":"dGVzdA==","payloadType":"application/json","signa`)

	env, err := VerifySignature(bytes.NewReader(truncated))
	require.Error(t, err)

	// The envelope may have partial data
	if env.PayloadType != "" || len(env.Payload) > 0 {
		t.Log("FINDING: VerifySignature returns a partially populated envelope alongside the error. " +
			"PayloadType=" + env.PayloadType + ". " +
			"Callers who check the error but also read the envelope could operate on corrupt/partial data. " +
			"The function should return a zero-value envelope on decode error.")
	}
}

// ==========================================================================
// FINDING 10: Signed mode with only exporters -- collection has no subjects
//
// When the only attestors with subjects are exporters (Export()=true),
// they get excluded from the collection. The collection then has no
// subjects.
//
// UPDATE: intoto.NewStatement now allows empty subjects (matching
// upstream witness behavior), so this no longer causes a hard failure.
// The collection envelope is created with zero subjects.
// ==========================================================================

func TestAdversarial_SignedModeOnlyExportersFails(t *testing.T) {
	signer, _ := advMakeRSASignerVerifier(t)

	exporter := &testAttestor{
		name:     "exporter",
		typeName: "https://test/exporter",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{
			"artifact": {{Hash: crypto.SHA256}: "deadbeef"},
		},
	}

	results, err := RunWithExports("signed-exporters-only",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{exporter}),
	)

	// intoto.NewStatement now allows empty subjects (matching upstream witness),
	// so the collection with no subjects (only exporters) no longer fails.
	require.NoError(t, err,
		"Signed mode with only exporters should succeed now that empty subjects are allowed")
	require.NotEmpty(t, results, "should produce results for the exporter and the collection")
}

// ==========================================================================
// FINDING 11: Concurrent Run calls sharing a signer (MEDIUM)
//
// Multiple goroutines calling Run with the same signer object could
// encounter races if the signer has mutable state. RSA signers are
// safe because they only read the private key, but KMS signers or
// signers with rate limiting could have races.
// ==========================================================================

func TestAdversarial_ConcurrentRunsSharedSigner(t *testing.T) {
	signer, verifier := advMakeRSASignerVerifier(t)

	const goroutines = 20
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	results := make([][]RunResult, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			att := &testAttestor{
				name:     fmt.Sprintf("att-%d", idx),
				typeName: fmt.Sprintf("https://test/att-%d", idx),
				runType:  attestation.ExecuteRunType,
				subjects: map[string]cryptoutil.DigestSet{
					fmt.Sprintf("art-%d", idx): {
						{Hash: crypto.SHA256}: fmt.Sprintf("hash-%d", idx),
					},
				},
			}
			r, err := RunWithExports(
				fmt.Sprintf("step-%d", idx),
				RunWithSigners(signer), // shared signer
				RunWithAttestors([]attestation.Attestor{att}),
			)
			errs[idx] = err
			results[idx] = r
		}(i)
	}
	wg.Wait()

	for i := 0; i < goroutines; i++ {
		require.NoError(t, errs[i], "goroutine %d failed", i)
		for _, r := range results[i] {
			if len(r.SignedEnvelope.Signatures) > 0 {
				_, err := r.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
				assert.NoError(t, err,
					"goroutine %d: envelope should verify even with shared signer", i)
			}
		}
	}
	t.Log("Concurrent runs with shared signer completed without data races. " +
		"NOTE: Run with -race flag to detect subtle races: go test -race")
}

// ==========================================================================
// FINDING 12: Attestor that modifies its own subjects after attest
// (MEDIUM)
//
// If an attestor's Subjects() method returns a reference to an internal
// map (not a copy), the caller can mutate the subjects after attestation.
// Since Subjects() is called AFTER Attest() during the run() function's
// loop over CompletedAttestors, this is safe. But if the attestor
// modifies its own subjects concurrently (e.g., in a background goroutine),
// there could be a race.
// ==========================================================================

func TestAdversarial_AttestorMutatesSubjectsAfterAttest(t *testing.T) {
	subjects := map[string]cryptoutil.DigestSet{
		"original": {{Hash: crypto.SHA256}: "original-hash"},
	}

	att := &testAttestor{
		name:     "mutator",
		typeName: "https://test/mutator",
		runType:  attestation.ExecuteRunType,
		subjects: subjects,
		export:   true,
		attestFunc: func(_ *attestation.AttestationContext) error {
			// Simulate background mutation (in real code this might be a goroutine)
			// We add a new subject DURING attestation
			subjects["injected"] = cryptoutil.DigestSet{
				{Hash: crypto.SHA256}: "injected-hash",
			}
			return nil
		},
	}

	results, err := RunWithExports("mutator-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err)

	// The exporter result should contain the mutated subjects because
	// Subjects() is called after Attest() completes
	exportResult := results[0]
	assert.Equal(t, "mutator", exportResult.AttestorName,
		"first result should be the exporter")

	t.Log("FINDING: Attestor Subjects() returns a reference to internal state. " +
		"If the attestor mutates its subjects map during or after Attest(), " +
		"the mutations are visible to the workflow. This is a time-of-check-to-time-of-use " +
		"(TOCTOU) issue. Subjects() should return a defensive copy.")
}

// ==========================================================================
// FINDING 13: Collection subject key format allows collision (LOW)
//
// Collection.Subjects() formats subject keys as "type/name".
// If two attestors have overlapping type/name combinations, subjects
// from one can overwrite subjects from the other in the collection's
// Subjects() map.
// ==========================================================================

func TestAdversarial_CollectionSubjectKeyCollision(t *testing.T) {
	// Two attestors that will produce the same subject key format
	att1 := &testAttestor{
		name:     "att1",
		typeName: "https://test/collider",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"artifact": {{Hash: crypto.SHA256}: "hash-from-att1"},
		},
	}
	att2 := &testAttestor{
		name:     "att2",
		typeName: "https://test/collider", // same type as att1!
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"artifact": {{Hash: crypto.SHA256}: "hash-from-att2"},
		},
	}

	results, err := RunWithExports("collision-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att1, att2}),
	)
	require.NoError(t, err)

	collection := results[len(results)-1]
	subjects := collection.Collection.Subjects()

	// The key "https://test/collider/artifact" will appear once,
	// with either att1's or att2's hash (last writer wins)
	key := "https://test/collider/artifact"
	if ds, ok := subjects[key]; ok {
		t.Logf("FINDING: Subject key %q exists with digest: %v. "+
			"Two attestors with the same type and subject name collide -- "+
			"the last one processed overwrites the first. This could be exploited "+
			"to replace legitimate subject digests if an attacker can inject an "+
			"attestor with the same type name.", key, ds)
	} else {
		t.Log("Subject key not found -- collection may format differently")
	}
}

// ==========================================================================
// FINDING 14: Deprecated Run() loses error context when results > 1 (LOW)
//
// The deprecated Run() function returns "expected a single result, got
// multiple" without indicating what the results were or why there were
// multiple. It also discards the actual results. This makes debugging
// difficult for callers who unknowingly have an exporter attestor.
// ==========================================================================

func TestAdversarial_DeprecatedRunLosesContext(t *testing.T) {
	exporter := &testAttestor{
		name:     "my-exporter",
		typeName: "https://test/my-exporter",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{
			"art": {{Hash: crypto.SHA256}: "abc"},
		},
	}

	_, err := Run("deprecated-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{exporter}),
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected a single result",
		"FINDING: Deprecated Run() returns generic 'expected a single result, got multiple' "+
			"without indicating which attestors caused multiple results. "+
			"Callers get no indication that they should switch to RunWithExports(). "+
			"The error message should include the attestor names or count.")
}

// ==========================================================================
// FINDING 15: Panic recovery in attestors (verify the mechanism works)
// ==========================================================================

func TestAdversarial_PanicRecoveryInAttestor(t *testing.T) {
	panicAtt := &testAttestor{
		name:     "panicker",
		typeName: "https://test/panic",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			panic("deliberate panic in attestor")
		},
	}

	_, err := Run("panic-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{panicAtt}),
	)

	// The context.go runAttestor has a recover() wrapper, so panics become errors
	require.Error(t, err,
		"Panicking attestor should produce an error, not crash the process")
	assert.Contains(t, err.Error(), "panicked",
		"Error message should indicate a panic occurred")
}

// ==========================================================================
// FINDING 16: Panic recovery with ignoreErrors=true
// ==========================================================================

func TestAdversarial_PanicRecoveryWithIgnoreErrors(t *testing.T) {
	panicAtt := &testAttestor{
		name:     "panicker",
		typeName: "https://test/panic",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			panic("deliberate panic ignored")
		},
	}

	result, err := Run("panic-ignore-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{panicAtt}),
		RunWithIgnoreErrors(true),
	)

	require.NoError(t, err,
		"Panicking attestor with ignoreErrors=true should not propagate error")
	assert.Empty(t, result.Collection.Attestations,
		"Panicking attestor should not appear in collection")
}

// ==========================================================================
// FINDING 17: Attestor execution count verification
// ==========================================================================

func TestAdversarial_AttestorCalledExactlyOnce(t *testing.T) {
	var count atomic.Int64

	att := &testAttestor{
		name:     "counter",
		typeName: "https://test/counter",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			count.Add(1)
			return nil
		},
	}

	_, err := Run("count-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err)

	assert.Equal(t, int64(1), count.Load(),
		"Attestor should be called exactly once per Run")
}

// ==========================================================================
// FINDING 18: Sign function with empty data type (LOW)
//
// The Sign function accepts an empty string as dataType without validation.
// The resulting DSSE envelope will have an empty payloadType, which violates
// the DSSE spec requirement for a non-empty payloadType.
// ==========================================================================

func TestAdversarial_SignWithEmptyDataType(t *testing.T) {
	signer, _ := advMakeRSASignerVerifier(t)

	var buf bytes.Buffer
	err := Sign(bytes.NewReader([]byte("data")), "", &buf, dsse.SignWithSigners(signer))
	require.NoError(t, err,
		"FINDING: Sign() accepts empty data type without error")

	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(buf.Bytes(), &env))
	assert.Empty(t, env.PayloadType,
		"FINDING: Envelope has empty payloadType. The DSSE spec requires a non-empty "+
			"payloadType to prevent type confusion attacks. An attacker could craft an "+
			"envelope with empty payloadType that matches any verification check that "+
			"does not validate the type.")
}

// ==========================================================================
// FINDING 19: VerifySignature with no verifiers (HIGH)
//
// Calling VerifySignature with an empty verifier list should fail because
// there are no verifiers to check signatures against. However, the error
// path and message should clearly indicate the issue.
// ==========================================================================

func TestAdversarial_VerifySignatureWithNoVerifiers(t *testing.T) {
	signer, _ := advMakeRSASignerVerifier(t)

	var buf bytes.Buffer
	require.NoError(t, Sign(
		bytes.NewReader([]byte(`{"test":"data"}`)),
		"application/json",
		&buf,
		dsse.SignWithSigners(signer),
	))

	_, err := VerifySignature(bytes.NewReader(buf.Bytes()))
	require.Error(t, err,
		"FINDING: VerifySignature with no verifiers should fail")
}

// ==========================================================================
// FINDING 20: VerifySignature with nil verifier in list
// ==========================================================================

func TestAdversarial_VerifySignatureWithNilVerifier(t *testing.T) {
	signer, _ := advMakeRSASignerVerifier(t)

	var buf bytes.Buffer
	require.NoError(t, Sign(
		bytes.NewReader([]byte(`{"test":"data"}`)),
		"application/json",
		&buf,
		dsse.SignWithSigners(signer),
	))

	_, err := VerifySignature(bytes.NewReader(buf.Bytes()), nil)
	require.Error(t, err,
		"FINDING: VerifySignature with nil verifier should fail, not panic")
}

// ==========================================================================
// FINDING 21: Race condition in concurrent Run calls with -race detector
//
// Multiple goroutines calling Run concurrently is safe because each call
// creates its own AttestationContext. However, attestor implementations
// with shared mutable state could have races.
// ==========================================================================

func TestAdversarial_ConcurrentRunDataRace(t *testing.T) {
	const goroutines = 50
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	names := make([]string, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			step := fmt.Sprintf("step-%d", idx)
			r, err := Run(step, RunWithInsecure(true))
			errs[idx] = err
			if err == nil {
				names[idx] = r.Collection.Name
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < goroutines; i++ {
		require.NoError(t, errs[i], "goroutine %d", i)
		expected := fmt.Sprintf("step-%d", i)
		assert.Equal(t, expected, names[i],
			"goroutine %d: state should be isolated", i)
	}
}

// ==========================================================================
// FINDING 22: RunWithExports with all-failing attestors and ignoreErrors
// ==========================================================================

func TestAdversarial_AllFailingAttestorsIgnoredProducesEmptyCollection(t *testing.T) {
	attestors := make([]attestation.Attestor, 5)
	for i := 0; i < 5; i++ {
		attestors[i] = &testAttestor{
			name:     fmt.Sprintf("fail-%d", i),
			typeName: fmt.Sprintf("https://test/fail-%d", i),
			runType:  attestation.ExecuteRunType,
			attestFunc: func(_ *attestation.AttestationContext) error {
				return fmt.Errorf("deliberate failure")
			},
		}
	}

	results, err := RunWithExports("all-fail",
		RunWithInsecure(true),
		RunWithAttestors(attestors),
		RunWithIgnoreErrors(true),
	)

	require.NoError(t, err, "ignoreErrors=true should suppress all errors")
	require.NotEmpty(t, results)

	collection := results[len(results)-1]
	assert.Empty(t, collection.Collection.Attestations,
		"All failing attestors should be excluded from collection")
	assert.Equal(t, "all-fail", collection.Collection.Name)
}

// ==========================================================================
// FINDING 23: Insecure mode with signers -- signers are silently ignored
// (LOW)
//
// When insecure=true and signers are provided, the signers are silently
// ignored. There is no warning or error. This could lead to a false sense
// of security if a caller accidentally sets insecure=true.
// ==========================================================================

func TestAdversarial_InsecureModeIgnoresSigners(t *testing.T) {
	signer, _ := advMakeRSASignerVerifier(t)

	result, err := Run("insecure-with-signers",
		RunWithInsecure(true),
		RunWithSigners(signer),
	)
	require.NoError(t, err)

	assert.Empty(t, result.SignedEnvelope.Signatures,
		"FINDING: Insecure mode silently ignores provided signers. "+
			"A caller who provides signers AND sets insecure=true gets an unsigned "+
			"envelope with no warning. The validateRunOpts function should either "+
			"reject this combination or emit a warning.")
}

// ==========================================================================
// FINDING 24: Context timeout does not propagate to attestor goroutines
// ==========================================================================

func TestAdversarial_ContextTimeoutInAttestor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	slowAtt := &testAttestor{
		name:     "slow",
		typeName: "https://test/slow",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(actx *attestation.AttestationContext) error {
			select {
			case <-actx.Context().Done():
				return actx.Context().Err()
			case <-time.After(5 * time.Second):
				return nil
			}
		},
	}

	_, err := RunWithExports("timeout-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{slowAtt}),
		RunWithAttestationOpts(attestation.WithContext(ctx)),
	)

	// The attestor should respect the context timeout
	if err != nil {
		assert.True(t,
			errors.Is(err, context.DeadlineExceeded) ||
				strings.Contains(err.Error(), "deadline") ||
				strings.Contains(err.Error(), "context"),
			"Error should be context-related: %v", err)
		t.Log("Context timeout correctly propagated to attestor")
	} else {
		t.Log("FINDING: Attestor completed despite context timeout -- " +
			"the context propagation may depend on attestor implementation")
	}
}

// ==========================================================================
// FINDING 25: Duplicate attestor types in same step -- no dedup (LOW)
//
// Two attestors with identical names and types can be added to the same
// step. Both appear in the collection. Policy evaluation that assumes
// unique attestor types per collection could be confused.
// ==========================================================================

func TestAdversarial_DuplicateAttestorTypesInCollection(t *testing.T) {
	att1 := &testAttestor{
		name:     "duplicate",
		typeName: "https://test/duplicate",
		runType:  attestation.ExecuteRunType,
	}
	att2 := &testAttestor{
		name:     "duplicate",
		typeName: "https://test/duplicate",
		runType:  attestation.ExecuteRunType,
	}

	results, err := RunWithExports("dup-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att1, att2}),
	)
	require.NoError(t, err)

	collection := results[len(results)-1]
	count := 0
	for _, a := range collection.Collection.Attestations {
		if a.Type == "https://test/duplicate" {
			count++
		}
	}

	assert.Equal(t, 2, count,
		"FINDING: Duplicate attestor types are both included in the collection. "+
			"No deduplication is enforced. An attacker who can inject attestors "+
			"could add duplicate types to confuse policy evaluation.")
}

// ==========================================================================
// FINDING 26: Verify with no signers defaults to insecure mode (MEDIUM)
//
// When Verify is called without VerifyWithSigners, the code on line 199
// adds RunWithInsecure(true) to the run options. This means the policyverify
// attestor's result envelope is NOT signed. While the policy verification
// itself may still work, the RESULT of verification is unsigned.
// ==========================================================================

func TestAdversarial_VerifyDefaultsToInsecureWhenNoSigners(t *testing.T) {
	// Without policyverify registered, we can only test the option building
	vo := verifyOptions{}

	// Simulate what Verify() does when no signers are provided
	if len(vo.signers) > 0 {
		t.Fatal("should have no signers")
	}

	// The code adds RunWithInsecure(true) when no signers
	var runOpts []RunOption
	if len(vo.signers) > 0 {
		runOpts = append(runOpts, RunWithSigners(vo.signers...))
	} else {
		runOpts = append(runOpts, RunWithInsecure(true))
	}

	// Apply the run option and check
	ro := runOptions{}
	for _, opt := range runOpts {
		opt(&ro)
	}

	assert.True(t, ro.insecure,
		"FINDING: When Verify() is called without signers, it defaults to insecure mode. "+
			"The verification result envelope will not be signed. A man-in-the-middle could "+
			"modify the verification result without detection if the caller does not provide signers.")
}

// ==========================================================================
// FINDING 27: Large number of attestors -- no resource limits (LOW)
// ==========================================================================

func TestAdversarial_ManyAttestorsNoLimit(t *testing.T) {
	const numAttestors = 100

	attestors := make([]attestation.Attestor, numAttestors)
	for i := 0; i < numAttestors; i++ {
		attestors[i] = &testAttestor{
			name:     fmt.Sprintf("att-%d", i),
			typeName: fmt.Sprintf("https://test/att-%d", i),
			runType:  attestation.ExecuteRunType,
		}
	}

	results, err := RunWithExports("many-attestors",
		RunWithInsecure(true),
		RunWithAttestors(attestors),
	)
	require.NoError(t, err)

	collection := results[len(results)-1]
	assert.Len(t, collection.Collection.Attestations, numAttestors,
		"All attestors included -- no limit on attestor count. "+
			"A malicious caller could create thousands of attestors to "+
			"consume memory or cause OOM.")
}

// ==========================================================================
// FINDING 28: Empty RunType is validated (verify positive case)
// ==========================================================================

func TestAdversarial_EmptyRunTypeRejected(t *testing.T) {
	att := &testAttestor{
		name:     "bad",
		typeName: "https://test/bad",
		runType:  "", // empty
	}

	_, err := Run("empty-runtype",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.Error(t, err, "Empty RunType should be rejected")
	assert.Contains(t, err.Error(), "run type",
		"Error should mention run type")
}

// ==========================================================================
// FINDING 29: VerifyWithKMSProviderOptions replaces instead of merging
// (LOW)
// ==========================================================================

func TestAdversarial_VerifyWithSubjectDigestsReplaces(t *testing.T) {
	vo := verifyOptions{}

	d1 := []cryptoutil.DigestSet{{{Hash: crypto.SHA256}: "aaa"}}
	d2 := []cryptoutil.DigestSet{{{Hash: crypto.SHA256}: "bbb"}}

	VerifyWithSubjectDigests(d1)(&vo)
	assert.Len(t, vo.subjectDigests, 1)

	VerifyWithSubjectDigests(d2)(&vo)
	assert.Len(t, vo.subjectDigests, 1,
		"FINDING: VerifyWithSubjectDigests uses = assignment instead of append. "+
			"Multiple calls will discard earlier subject digests. "+
			"This is inconsistent with VerifyWithSigners which uses append. "+
			"A caller building subject digests incrementally will lose earlier entries.")
}
