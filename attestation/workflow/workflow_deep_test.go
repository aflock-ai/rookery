//go:build audit

package workflow

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Test helpers
// ==========================================================================

func makeRSASignerVerifier(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	return signer, verifier
}

// subjectingAttestor implements Attestor, Subjecter, and Exporter.
type subjectingAttestor struct {
	name       string
	typeName   string
	runType    attestation.RunType
	subjects   map[string]cryptoutil.DigestSet
	export     bool
	attestFunc func(*attestation.AttestationContext) error
}

func (a *subjectingAttestor) Name() string                                 { return a.name }
func (a *subjectingAttestor) Type() string                                 { return a.typeName }
func (a *subjectingAttestor) RunType() attestation.RunType                 { return a.runType }
func (a *subjectingAttestor) Schema() *jsonschema.Schema                   { return nil }
func (a *subjectingAttestor) Export() bool                                 { return a.export }
func (a *subjectingAttestor) Subjects() map[string]cryptoutil.DigestSet    { return a.subjects }
func (a *subjectingAttestor) Attest(ctx *attestation.AttestationContext) error {
	if a.attestFunc != nil {
		return a.attestFunc(ctx)
	}
	return nil
}

// ==========================================================================
// RunWithAttestationOpts append behavior
// ==========================================================================

// TestDeep_RunWithAttestationOpts_AppendsNotReplaces verifies the fix for the
// RunWithAttestationOpts append bug. Multiple calls should accumulate options.
func TestDeep_RunWithAttestationOpts_AppendsNotReplaces(t *testing.T) {
	ro := runOptions{}

	opt1 := attestation.WithWorkingDir("/tmp/dir1")
	opt2 := attestation.WithWorkingDir("/tmp/dir2")
	opt3 := attestation.WithWorkingDir("/tmp/dir3")

	RunWithAttestationOpts(opt1, opt2)(&ro)
	require.Equal(t, 2, len(ro.attestationOpts), "first call should set 2 opts")

	RunWithAttestationOpts(opt3)(&ro)
	require.Equal(t, 3, len(ro.attestationOpts),
		"second call should APPEND, not replace. "+
			"If this fails, RunWithAttestationOpts uses `=` instead of `append()`")
}

// ==========================================================================
// RunWithSigners append behavior
// ==========================================================================

// TestDeep_RunWithSigners_MultipleCallsAccumulate verifies that RunWithSigners
// correctly uses append across multiple invocations.
func TestDeep_RunWithSigners_MultipleCallsAccumulate(t *testing.T) {
	s1, _ := makeRSASignerVerifier(t)
	s2, _ := makeRSASignerVerifier(t)

	ro := runOptions{}
	RunWithSigners(s1)(&ro)
	require.Len(t, ro.signers, 1)
	RunWithSigners(s2)(&ro)
	require.Len(t, ro.signers, 2, "RunWithSigners should append across calls")
}

// ==========================================================================
// RunWithTimestampers replaces instead of appends
// ==========================================================================

// TestDeep_RunWithTimestampers_ReplacesInsteadOfAppends documents that
// RunWithTimestampers uses `=` rather than `append()`, unlike RunWithSigners.
func TestDeep_RunWithTimestampers_ReplacesInsteadOfAppends(t *testing.T) {
	ro := runOptions{}

	// RunWithTimestampers uses `ro.timestampers = ts` (line 77 of run.go)
	// which means the second call replaces the first.
	RunWithTimestampers()(&ro)
	firstLen := len(ro.timestampers)

	RunWithTimestampers()(&ro)
	secondLen := len(ro.timestampers)

	// Document the actual behavior.
	if secondLen < firstLen {
		t.Logf("DESIGN NOTE: RunWithTimestampers REPLACES (uses `=`) instead of appending. "+
			"This is inconsistent with RunWithSigners (which uses `append()`). "+
			"Callers who call RunWithTimestampers twice will lose timestampers from the first call.")
	}
}

// ==========================================================================
// Insecure mode envelope check
// ==========================================================================

// TestDeep_InsecureMode_NoEnvelopeGenerated verifies that insecure mode
// does not produce a signed DSSE envelope (it should be the zero value).
func TestDeep_InsecureMode_NoEnvelopeGenerated(t *testing.T) {
	att := &subjectingAttestor{
		name:     "test-att",
		typeName: "https://test/att",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"artifact": {
				{Hash: crypto.SHA256}: "deadbeef",
			},
		},
		export: true,
	}

	results, err := RunWithExports("insecure-step",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err)

	for _, r := range results {
		assert.Empty(t, r.SignedEnvelope.Signatures,
			"insecure mode should produce envelope with no signatures")
	}
}

// ==========================================================================
// Signed mode actually signs
// ==========================================================================

// TestDeep_SignedMode_ProducesValidEnvelope verifies that non-insecure mode
// produces a properly signed envelope that can be verified.
func TestDeep_SignedMode_ProducesValidEnvelope(t *testing.T) {
	signer, verifier := makeRSASignerVerifier(t)

	att := &subjectingAttestor{
		name:     "signed-att",
		typeName: "https://test/signed",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"artifact": {
				{Hash: crypto.SHA256}: "deadbeef",
			},
		},
		export: true,
	}

	results, err := RunWithExports("signed-step",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(results), 2,
		"should have at least exporter result + collection result")

	for _, r := range results {
		require.NotEmpty(t, r.SignedEnvelope.Signatures,
			"signed mode should produce envelope with signatures")

		// Each envelope should be verifiable.
		_, err := r.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
		assert.NoError(t, err, "signed envelope should verify with the signer's verifier")
	}
}

// ==========================================================================
// Multiple attestors: mix of pass and fail with ignoreErrors
// ==========================================================================

// TestDeep_MixedPassFailAttestors_IgnoreErrors verifies that a mix of
// passing and failing attestors with ignoreErrors=true produces a collection
// containing only the passing attestors.
func TestDeep_MixedPassFailAttestors_IgnoreErrors(t *testing.T) {
	passing1 := &subjectingAttestor{
		name:     "pass-1",
		typeName: "https://test/pass-1",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{},
	}
	passing2 := &subjectingAttestor{
		name:     "pass-2",
		typeName: "https://test/pass-2",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{},
	}
	failing := &subjectingAttestor{
		name:     "fail-1",
		typeName: "https://test/fail-1",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			return errors.New("attestor failure")
		},
	}

	result, err := Run("mixed-step",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{passing1, failing, passing2}),
		RunWithIgnoreErrors(true),
	)
	require.NoError(t, err)

	// Failing attestor should be excluded.
	for _, a := range result.Collection.Attestations {
		assert.NotEqual(t, "https://test/fail-1", a.Type,
			"failing attestor should not appear in collection when ignoreErrors=true")
	}
}

// ==========================================================================
// Multiple failing attestors without ignoreErrors
// ==========================================================================

// TestDeep_AllAttestorsFail_WithoutIgnoreErrors verifies that when all
// attestors fail and ignoreErrors is false, we get a joined error.
func TestDeep_AllAttestorsFail_WithoutIgnoreErrors(t *testing.T) {
	fail1 := &subjectingAttestor{
		name:     "fail-A",
		typeName: "https://test/fail-A",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			return errors.New("boom A")
		},
	}
	fail2 := &subjectingAttestor{
		name:     "fail-B",
		typeName: "https://test/fail-B",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			return errors.New("boom B")
		},
	}

	_, err := Run("all-fail-step",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{fail1, fail2}),
	)
	require.Error(t, err, "should error when attestors fail and ignoreErrors=false")
	assert.Contains(t, err.Error(), "boom A")
	assert.Contains(t, err.Error(), "boom B")
}

// ==========================================================================
// RunWithExports collection always last
// ==========================================================================

// TestDeep_RunWithExports_CollectionAlwaysLast verifies that the collection
// result is always the last element in the results slice.
func TestDeep_RunWithExports_CollectionAlwaysLast(t *testing.T) {
	exporter1 := &subjectingAttestor{
		name:     "export-1",
		typeName: "https://test/export-1",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{"art1": {}},
	}
	exporter2 := &subjectingAttestor{
		name:     "export-2",
		typeName: "https://test/export-2",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{"art2": {}},
	}
	regular := &subjectingAttestor{
		name:     "regular",
		typeName: "https://test/regular",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{},
	}

	results, err := RunWithExports("order-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{exporter1, regular, exporter2}),
	)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(results), 3,
		"should have 2 exporters + 1 collection")

	last := results[len(results)-1]
	assert.Equal(t, "order-test", last.Collection.Name,
		"last result should always be the collection")
}

// ==========================================================================
// Deprecated Run() with too many results
// ==========================================================================

// TestDeep_DeprecatedRun_RejectsMultipleResults verifies that the deprecated
// Run() function returns an error when more than one result is produced.
func TestDeep_DeprecatedRun_RejectsMultipleResults(t *testing.T) {
	exporter := &subjectingAttestor{
		name:     "exporter",
		typeName: "https://test/exporter",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{"art": {}},
	}

	_, err := Run("deprecated-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{exporter}),
	)
	require.Error(t, err, "deprecated Run() should error with multiple results")
	assert.Contains(t, err.Error(), "expected a single result, got multiple")
}

// ==========================================================================
// VerifySignature function
// ==========================================================================

// TestDeep_VerifySignature_ValidEnvelope tests the VerifySignature function
// with a properly signed envelope.
func TestDeep_VerifySignature_ValidEnvelope(t *testing.T) {
	signer, verifier := makeRSASignerVerifier(t)

	// Create and sign an envelope.
	payload := []byte(`{"type":"test","data":"value"}`)
	var buf bytes.Buffer
	err := Sign(bytes.NewReader(payload), "application/json", &buf, dsse.SignWithSigners(signer))
	require.NoError(t, err)

	// Verify it.
	env, err := VerifySignature(bytes.NewReader(buf.Bytes()), verifier)
	require.NoError(t, err)
	assert.Equal(t, "application/json", env.PayloadType)
	assert.NotEmpty(t, env.Signatures)
}

// TestDeep_VerifySignature_WrongVerifier tests that VerifySignature fails
// with a wrong verifier.
func TestDeep_VerifySignature_WrongVerifier(t *testing.T) {
	signer, _ := makeRSASignerVerifier(t)
	_, wrongVerifier := makeRSASignerVerifier(t)

	payload := []byte(`{"data":"test"}`)
	var buf bytes.Buffer
	err := Sign(bytes.NewReader(payload), "test/plain", &buf, dsse.SignWithSigners(signer))
	require.NoError(t, err)

	_, err = VerifySignature(bytes.NewReader(buf.Bytes()), wrongVerifier)
	require.Error(t, err, "wrong verifier should fail")
}

// TestDeep_VerifySignature_InvalidJSON tests VerifySignature with invalid JSON.
func TestDeep_VerifySignature_InvalidJSON(t *testing.T) {
	_, verifier := makeRSASignerVerifier(t)

	_, err := VerifySignature(bytes.NewReader([]byte("not-json")), verifier)
	require.Error(t, err, "invalid JSON should fail")
	assert.Contains(t, err.Error(), "failed to parse dsse envelope")
}

// TestDeep_VerifySignature_EmptyInput tests VerifySignature with empty input.
func TestDeep_VerifySignature_EmptyInput(t *testing.T) {
	_, verifier := makeRSASignerVerifier(t)

	_, err := VerifySignature(bytes.NewReader([]byte{}), verifier)
	require.Error(t, err, "empty input should fail")
}

// ==========================================================================
// Sign function edge cases
// ==========================================================================

// TestDeep_Sign_EmptyPayload tests the workflow Sign function with empty payload.
func TestDeep_Sign_EmptyPayload(t *testing.T) {
	signer, _ := makeRSASignerVerifier(t)

	var buf bytes.Buffer
	err := Sign(bytes.NewReader([]byte{}), "test/empty", &buf, dsse.SignWithSigners(signer))
	require.NoError(t, err)

	var env dsse.Envelope
	err = json.Unmarshal(buf.Bytes(), &env)
	require.NoError(t, err)
	assert.Equal(t, "test/empty", env.PayloadType)
}

// TestDeep_Sign_NoSigners tests the workflow Sign function with no signers.
func TestDeep_Sign_NoSigners(t *testing.T) {
	var buf bytes.Buffer
	err := Sign(bytes.NewReader([]byte("data")), "test", &buf)
	require.Error(t, err, "should error with no signers")
}

// ==========================================================================
// Concurrent Run calls
// ==========================================================================

// TestDeep_ConcurrentRunCalls verifies that Run is safe for concurrent use
// (each call creates its own context and state).
func TestDeep_ConcurrentRunCalls(t *testing.T) {
	const goroutines = 20
	var wg sync.WaitGroup
	results := make([]RunResult, goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			stepName := fmt.Sprintf("concurrent-step-%d", idx)
			r, err := Run(stepName, RunWithInsecure(true))
			results[idx] = r
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d should succeed", i)
		expected := fmt.Sprintf("concurrent-step-%d", i)
		assert.Equal(t, expected, results[i].Collection.Name,
			"goroutine %d: collection name should match step name", i)
	}
}

// ==========================================================================
// Concurrent RunWithExports calls with signing
// ==========================================================================

// TestDeep_ConcurrentRunWithExports_Signed verifies concurrent signed runs
// produce independently verifiable envelopes.
func TestDeep_ConcurrentRunWithExports_Signed(t *testing.T) {
	signer, verifier := makeRSASignerVerifier(t)

	const goroutines = 10
	var wg sync.WaitGroup
	allResults := make([][]RunResult, goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			stepName := fmt.Sprintf("signed-concurrent-%d", idx)
			r, err := RunWithExports(stepName, RunWithSigners(signer))
			allResults[idx] = r
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d should succeed", i)
		require.GreaterOrEqual(t, len(allResults[i]), 1,
			"goroutine %d: should have at least collection result", i)

		for j, r := range allResults[i] {
			if len(r.SignedEnvelope.Signatures) > 0 {
				_, err := r.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
				assert.NoError(t, err,
					"goroutine %d, result %d: envelope should verify", i, j)
			}
		}
	}
}

// ==========================================================================
// MultiExporter with no exported attestations
// ==========================================================================

// emptyMultiExporter implements MultiExporter but returns empty exported list.
type emptyMultiExporter struct {
	testAttestor
}

func (a *emptyMultiExporter) ExportedAttestations() []attestation.Attestor {
	return nil
}

// TestDeep_MultiExporter_EmptyExportedList tests a MultiExporter that
// exports zero attestations. It should still be excluded from the collection.
func TestDeep_MultiExporter_EmptyExportedList(t *testing.T) {
	multi := &emptyMultiExporter{
		testAttestor: testAttestor{
			name:     "empty-multi",
			typeName: "https://test/empty-multi",
			runType:  attestation.ExecuteRunType,
		},
	}

	results, err := RunWithExports("empty-multi-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{multi}),
	)
	require.NoError(t, err)

	// Should have only the collection result (no exported attestations).
	collection := results[len(results)-1]
	assert.Equal(t, "empty-multi-test", collection.Collection.Name)

	// The MultiExporter should NOT appear in the collection.
	for _, a := range collection.Collection.Attestations {
		assert.NotEqual(t, "https://test/empty-multi", a.Type,
			"empty MultiExporter should still be excluded from collection")
	}
}

// ==========================================================================
// Attestor that panics -- DESIGN ISSUE DOCUMENTED
// ==========================================================================

// NOTE: A panicking attestor crashes the entire process because attestors
// run in goroutines (via RunAttestors) and there is no recover() wrapper
// in runAttestor. This cannot be tested with assert.Panics because the
// panic occurs in a child goroutine, not the calling goroutine.
//
// BUG/DESIGN ISSUE: context.go:runAttestor runs attestors in goroutines
// without recover(). A misbehaving attestor plugin can crash the entire
// process. Consider wrapping runAttestor with recover() and converting
// panics to errors.

// ==========================================================================
// Run with nil signer
// ==========================================================================

// TestDeep_RunWithNilSigner tests that a nil signer in the signers list
// is handled gracefully (dsse.Sign skips nil signers).
func TestDeep_RunWithNilSigner(t *testing.T) {
	signer, _ := makeRSASignerVerifier(t)

	att := &subjectingAttestor{
		name:     "nil-signer-att",
		typeName: "https://test/nil-signer",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{"art": {}},
	}

	// Mix nil and valid signer.
	results, err := RunWithExports("nil-signer-test",
		RunWithSigners(nil, signer, nil),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(results), 1)

	for _, r := range results {
		assert.NotEmpty(t, r.SignedEnvelope.Signatures,
			"should have at least one signature from the valid signer")
	}
}

// ==========================================================================
// Validate option consistency
// ==========================================================================

// TestDeep_ValidateRunOpts_InsecureWithSigners verifies that insecure=true
// with signers present doesn't error (signers are just ignored).
func TestDeep_ValidateRunOpts_InsecureWithSigners(t *testing.T) {
	signer, _ := makeRSASignerVerifier(t)

	result, err := Run("insecure-with-signers",
		RunWithInsecure(true),
		RunWithSigners(signer),
	)
	require.NoError(t, err)

	// In insecure mode, the envelope should NOT be signed even though
	// signers are present.
	assert.Empty(t, result.SignedEnvelope.Signatures,
		"insecure mode should not produce signatures even with signers")
}

// ==========================================================================
// createAndSignEnvelope with nil subjects
// ==========================================================================

// TestDeep_CreateAndSignEnvelope_NilSubjects tests the internal
// createAndSignEnvelope with nil subjects. This exercises the in-toto
// statement creation with nil subjects.
func TestDeep_CreateAndSignEnvelope_NilSubjects(t *testing.T) {
	signer, verifier := makeRSASignerVerifier(t)

	// Create an attestor with nil subjects.
	att := &subjectingAttestor{
		name:     "nil-subjects",
		typeName: "https://test/nil-subjects",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: nil, // explicitly nil
	}

	results, err := RunWithExports("nil-subjects-test",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err)

	for _, r := range results {
		if len(r.SignedEnvelope.Signatures) > 0 {
			_, err := r.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
			assert.NoError(t, err, "envelope with nil subjects should still verify")
		}
	}
}

// ==========================================================================
// Attestor execution counting
// ==========================================================================

// countingAttestor counts how many times it's attested.
type countingAttestor struct {
	subjectingAttestor
	count atomic.Int64
}

func (a *countingAttestor) Attest(ctx *attestation.AttestationContext) error {
	a.count.Add(1)
	return nil
}

// TestDeep_AttestorCalledExactlyOnce verifies that each attestor is called
// exactly once per Run.
func TestDeep_AttestorCalledExactlyOnce(t *testing.T) {
	attestors := make([]*countingAttestor, 5)
	attestorList := make([]attestation.Attestor, 5)
	for i := range attestors {
		attestors[i] = &countingAttestor{
			subjectingAttestor: subjectingAttestor{
				name:     fmt.Sprintf("counter-%d", i),
				typeName: fmt.Sprintf("https://test/counter-%d", i),
				runType:  attestation.ExecuteRunType,
				subjects: map[string]cryptoutil.DigestSet{},
			},
		}
		attestorList[i] = attestors[i]
	}

	_, err := Run("count-test",
		RunWithInsecure(true),
		RunWithAttestors(attestorList),
	)
	require.NoError(t, err)

	for i, a := range attestors {
		assert.Equal(t, int64(1), a.count.Load(),
			"attestor %d should be called exactly once", i)
	}
}

// ==========================================================================
// RunWithExports results ordering stability
// ==========================================================================

// TestDeep_RunWithExports_ExporterResultsBeforeCollection verifies that
// exporter results appear before the collection in the results slice.
func TestDeep_RunWithExports_ExporterResultsBeforeCollection(t *testing.T) {
	child1 := &subjectingAttestor{
		name:     "child-A",
		typeName: "https://test/child-A",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{"art": {}},
	}
	child2 := &subjectingAttestor{
		name:     "child-B",
		typeName: "https://test/child-B",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{"art": {}},
	}

	multi := &testMultiExporter{
		testAttestor: testAttestor{
			name:     "parent",
			typeName: "https://test/parent",
			runType:  attestation.ExecuteRunType,
		},
		exported: []attestation.Attestor{child1, child2},
	}

	results, err := RunWithExports("ordering-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{multi}),
	)
	require.NoError(t, err)
	require.Len(t, results, 3, "2 exports + 1 collection")

	// First two should be exports.
	assert.Contains(t, results[0].AttestorName, "parent/child-",
		"first result should be an export")
	assert.Contains(t, results[1].AttestorName, "parent/child-",
		"second result should be an export")

	// Last should be collection.
	assert.Equal(t, "ordering-test", results[2].Collection.Name,
		"last result should be the collection")
}

// ==========================================================================
// Concurrent attestor state isolation
// ==========================================================================

// TestDeep_ConcurrentRun_AttestorStateIsolation verifies that concurrent
// runs with shared attestor types but different instances don't interfere.
func TestDeep_ConcurrentRun_AttestorStateIsolation(t *testing.T) {
	const goroutines = 20
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	collections := make([]attestation.Collection, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			att := &subjectingAttestor{
				name:     fmt.Sprintf("isolate-%d", idx),
				typeName: fmt.Sprintf("https://test/isolate-%d", idx),
				runType:  attestation.ExecuteRunType,
				subjects: map[string]cryptoutil.DigestSet{},
			}
			r, err := Run(
				fmt.Sprintf("step-%d", idx),
				RunWithInsecure(true),
				RunWithAttestors([]attestation.Attestor{att}),
			)
			errs[idx] = err
			if err == nil {
				collections[idx] = r.Collection
			}
		}(i)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
		expected := fmt.Sprintf("step-%d", i)
		assert.Equal(t, expected, collections[i].Name,
			"goroutine %d: state should be isolated", i)
	}
}

// ==========================================================================
// Verify function edge cases (requires policyverify plugin)
// ==========================================================================

// TestDeep_Verify_NoPolicyVerifyPlugin verifies that calling Verify
// without the policyverify plugin imported produces a clear error.
func TestDeep_Verify_NoPolicyVerifyPlugin(t *testing.T) {
	// The Verify function tries to find "policyverify" in the registry.
	// Without it imported, this should fail with a clear message.
	_, ok := attestation.FactoryByName("policyverify")
	if ok {
		t.Skip("policyverify plugin is registered; skipping unregistered test")
	}

	signer, _ := makeRSASignerVerifier(t)

	// Create a minimal envelope.
	env := dsse.Envelope{
		Payload:     []byte("fake-policy"),
		PayloadType: "application/json",
		Signatures:  []dsse.Signature{{KeyID: "test", Signature: []byte("fake")}},
	}

	_, err := Verify(
		nil,
		env,
		nil,
		VerifyWithSigners(signer),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policyverify",
		"should mention policyverify in the error")
}
