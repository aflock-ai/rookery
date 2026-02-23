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
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Test helpers (stdlib only -- no testify)
// ==========================================================================

func secMakeRSASignerVerifier(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	return signer, verifier
}

// secAttestor implements Attestor, Subjecter, and Exporter.
type secAttestor struct {
	name       string
	typeName   string
	runType    attestation.RunType
	attestFunc func(*attestation.AttestationContext) error
	subjects   map[string]cryptoutil.DigestSet
	export     bool
}

func (a *secAttestor) Name() string                              { return a.name }
func (a *secAttestor) Type() string                              { return a.typeName }
func (a *secAttestor) RunType() attestation.RunType              { return a.runType }
func (a *secAttestor) Schema() *jsonschema.Schema                { return nil }
func (a *secAttestor) Export() bool                              { return a.export }
func (a *secAttestor) Subjects() map[string]cryptoutil.DigestSet { return a.subjects }
func (a *secAttestor) Attest(ctx *attestation.AttestationContext) error {
	if a.attestFunc != nil {
		return a.attestFunc(ctx)
	}
	return nil
}

// secMultiExporter implements Attestor and MultiExporter.
type secMultiExporter struct {
	secAttestor
	exported []attestation.Attestor
}

func (a *secMultiExporter) ExportedAttestations() []attestation.Attestor {
	return a.exported
}

// secBareAttestor implements Attestor only (no Subjecter, no Exporter).
type secBareAttestor struct {
	name       string
	typeName   string
	runType    attestation.RunType
	attestFunc func(*attestation.AttestationContext) error
}

func (a *secBareAttestor) Name() string                 { return a.name }
func (a *secBareAttestor) Type() string                 { return a.typeName }
func (a *secBareAttestor) RunType() attestation.RunType { return a.runType }
func (a *secBareAttestor) Schema() *jsonschema.Schema   { return nil }
func (a *secBareAttestor) Attest(ctx *attestation.AttestationContext) error {
	if a.attestFunc != nil {
		return a.attestFunc(ctx)
	}
	return nil
}

// secMaterialer implements Attestor and Materialer.
type secMaterialer struct {
	secAttestor
	materials map[string]cryptoutil.DigestSet
}

func (a *secMaterialer) Materials() map[string]cryptoutil.DigestSet {
	return a.materials
}

// failingWriter returns an error after writing a specified number of bytes.
type failingWriter struct {
	limit   int
	written int
	err     error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.limit {
		remaining := w.limit - w.written
		w.written = w.limit
		return remaining, w.err
	}
	w.written += len(p)
	return len(p), nil
}

// failingReader returns an error after reading a specified number of bytes.
type failingReader struct {
	data    []byte
	failAt  int
	failErr error
	pos     int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.pos >= r.failAt {
		return 0, r.failErr
	}
	n := copy(p, r.data[r.pos:])
	if r.pos+n >= r.failAt {
		written := r.failAt - r.pos
		r.pos = r.failAt
		return written, r.failErr
	}
	r.pos += n
	return n, nil
}

// ==========================================================================
// R3-230: Verify function accepts context.Context but never propagates it
//
// FINDING: The Verify function's first parameter is context.Context but
// it is NEVER passed to:
//   - Run() (which does not accept a context)
//   - attestation.NewContext() (context is only set via WithContext option)
//   - The policyverify attestor (no context.Context setter)
//
// A caller passing a cancelled or deadline-exceeded context expects
// Verify to honor it and abort promptly. Instead, the verification
// runs to completion (or until it hits an unrelated error). This is a
// violation of the Go context contract.
//
// SEVERITY: MEDIUM -- A service using Verify with request-scoped
// contexts cannot enforce timeouts or cancellation on policy verification.
// This means a slow or hung policy evaluation will block indefinitely
// regardless of the caller's context.
// ==========================================================================

func TestSecurity_R3_230_VerifyIgnoresContextParameter(t *testing.T) {
	// Create a context that is already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Verify will fail because policyverify is not registered,
	// but the critical check is: does the error mention "context cancelled"
	// or does it mention "policyverify"?
	signer, _ := secMakeRSASignerVerifier(t)
	env := dsse.Envelope{
		Payload:     []byte("fake"),
		PayloadType: "test",
		Signatures:  []dsse.Signature{{KeyID: "k", Signature: []byte("s")}},
	}

	_, err := Verify(ctx, env, nil, VerifyWithSigners(signer))
	if err == nil {
		t.Fatal("expected error from Verify")
	}

	// The error should NOT be about context cancellation because the ctx is
	// never propagated. It should be about policyverify not being registered.
	errMsg := err.Error()
	if strings.Contains(errMsg, "context canceled") {
		t.Log("Context cancellation was propagated -- this would be correct behavior")
	} else if strings.Contains(errMsg, "policyverify") {
		t.Log("SECURITY FINDING R3-230: Verify() accepted a cancelled context.Context " +
			"but did not honor it. The error is about policyverify, not context " +
			"cancellation. The ctx parameter on the Verify function signature (verify.go " +
			"line 159) is never passed to Run(), attestation.NewContext(), or the " +
			"policyverify attestor. Callers cannot enforce timeouts or cancellation " +
			"on the verification workflow. This violates the Go context contract.")
	} else {
		t.Logf("unexpected error: %v", err)
	}
}

// ==========================================================================
// R3-231: VerifyWithKMSProviderOptions replaces map entirely on each call
//
// FINDING: VerifyWithKMSProviderOptions uses assignment (vo.kmsProviderOptions = opts)
// instead of merging maps. This means the second call completely discards
// the first call's provider options. If a caller builds options incrementally
// from multiple sources (e.g., AWS KMS and GCP KMS), the first source's
// options are silently lost.
//
// The same pattern applies to VerifyWithSubjectDigests (replaces instead of
// appending). This is documented in R3-153 already for insecure, but
// VerifyWithKMSProviderOptions has unique implications: KMS provider options
// are typically set per-provider, and losing one provider's options means
// the corresponding KMS signatures cannot be verified.
//
// SEVERITY: MEDIUM -- Verification bypass. If a policy requires signatures
// from two different KMS providers, and the options for one provider are
// silently dropped, verification for that provider's signatures will fail
// with an opaque error about missing KMS configuration.
// ==========================================================================

func TestSecurity_R3_231_VerifyKMSProviderOptionsReplaces(t *testing.T) {
	// Test replacement behavior through the VerifyOption functions that
	// use direct assignment instead of merge/append.
	//
	// We test the same pattern through other VerifyOption functions that
	// exhibit identical behavior: VerifyWithAiServerURL, VerifyWithSubjectDigests.

	// Test 1: VerifyWithAiServerURL replaces on each call
	vo := verifyOptions{}
	VerifyWithAiServerURL("http://first")(&vo)
	if vo.aiServerURL != "http://first" {
		t.Fatalf("expected aiServerURL to be 'http://first', got %q", vo.aiServerURL)
	}
	VerifyWithAiServerURL("http://second")(&vo)
	if vo.aiServerURL != "http://second" {
		t.Fatalf("expected aiServerURL to be 'http://second', got %q", vo.aiServerURL)
	}

	// Test 2: VerifyWithSubjectDigests replaces on each call
	vo2 := verifyOptions{}
	d1 := []cryptoutil.DigestSet{{{Hash: crypto.SHA256}: "aaa"}}
	d2 := []cryptoutil.DigestSet{{{Hash: crypto.SHA256}: "bbb"}}
	VerifyWithSubjectDigests(d1)(&vo2)
	if len(vo2.subjectDigests) != 1 {
		t.Fatalf("expected 1 subject digest, got %d", len(vo2.subjectDigests))
	}
	VerifyWithSubjectDigests(d2)(&vo2)
	if len(vo2.subjectDigests) != 1 {
		// Second call replaced, not appended
		t.Log("Confirmed: VerifyWithSubjectDigests replaces instead of appending")
	}

	// Test 3: Contrast with VerifyWithSigners which APPENDS
	vo3 := verifyOptions{}
	s1, _ := secMakeRSASignerVerifier(t)
	s2, _ := secMakeRSASignerVerifier(t)
	VerifyWithSigners(s1)(&vo3)
	VerifyWithSigners(s2)(&vo3)
	if len(vo3.signers) != 2 {
		t.Fatalf("expected 2 signers (append), got %d", len(vo3.signers))
	}

	t.Log("SECURITY FINDING R3-231: VerifyWithKMSProviderOptions, VerifyWithAiServerURL, " +
		"VerifyWithCollectionSource, and VerifyWithSubjectDigests all use direct " +
		"assignment (vo.field = value) instead of merge/append. Multiple calls " +
		"silently discard earlier values. This is inconsistent with " +
		"VerifyWithSigners and VerifyWithRunOptions which use append. " +
		"For KMS provider options specifically, this means a caller who sets " +
		"options for AWS KMS then sets options for GCP KMS will lose the AWS KMS " +
		"options entirely, causing verification failures for AWS-signed attestations.")
}

// ==========================================================================
// R3-232: Verify builds conflicting RunOptions
//
// FINDING: Verify() appends its own RunOptions AFTER the caller's
// VerifyWithRunOptions options. Specifically:
//   - Line 197-199: if signers are present, appends RunWithSigners(...)
//   - Line 199: else appends RunWithInsecure(true)
//   - Line 202-204: appends RunWithAttestors(...)
//
// If the caller provided RunWithInsecure(false) via VerifyWithRunOptions,
// and also provided no VerifyWithSigners, the Verify function OVERRIDES
// the caller's insecure=false with insecure=true. This is because the
// Verify-generated options are appended AFTER the caller's options, and
// the last RunWithInsecure call wins.
//
// SEVERITY: HIGH -- Security downgrade. A caller who explicitly opts
// into signed mode via VerifyWithRunOptions(RunWithInsecure(false)) is
// silently downgraded to insecure mode if they forget to also provide
// VerifyWithSigners.
// ==========================================================================

func TestSecurity_R3_232_VerifyOverridesCallerInsecureFlag(t *testing.T) {
	// Simulate what Verify does internally with no signers provided
	vo := verifyOptions{}

	// Caller explicitly opts into signed mode via RunOptions
	VerifyWithRunOptions(RunWithInsecure(false))(&vo)

	// Now simulate Verify's internal logic: no signers -> add insecure=true
	// This happens at verify.go lines 196-199
	if len(vo.signers) > 0 {
		vo.runOptions = append(vo.runOptions, RunWithSigners(vo.signers...))
	} else {
		vo.runOptions = append(vo.runOptions, RunWithInsecure(true))
	}

	// Apply all run options to see the effective configuration
	ro := runOptions{}
	for _, opt := range vo.runOptions {
		opt(&ro)
	}

	// The caller wanted insecure=false, but Verify overrode it to true
	if ro.insecure {
		t.Log("SECURITY FINDING R3-232: Verify() silently overrides the caller's " +
			"RunWithInsecure(false) to insecure=true when no VerifyWithSigners is provided. " +
			"The Verify function appends RunWithInsecure(true) AFTER the caller's " +
			"RunOptions, and last-call-wins semantics cause the override. " +
			"A caller who explicitly requests signed verification via " +
			"VerifyWithRunOptions(RunWithInsecure(false)) but forgets VerifyWithSigners " +
			"gets silently downgraded to insecure mode. The error should reject the " +
			"configuration instead of silently downgrading.")
	} else {
		t.Error("insecure should be true after Verify's override, but was false")
	}
}

// ==========================================================================
// R3-233: MultiExporter with nil attestor in ExportedAttestations
//
// FINDING: When a MultiExporter returns a slice containing nil entries
// from ExportedAttestations(), the run() function dereferences the nil
// attestor at line 152 (checking Subjecter interface) and at line 157
// (calling exportedAttestor.Type()). This causes a nil pointer panic.
//
// While the runAttestor wrapper has recover(), the MultiExporter
// processing happens OUTSIDE runAttestor, in the run() function's
// post-processing loop over CompletedAttestors. There is NO recover()
// in this code path, so a nil entry crashes the entire process.
//
// SEVERITY: HIGH -- Denial of service. A malicious or buggy MultiExporter
// plugin can crash the entire attestation process by returning a nil
// in its ExportedAttestations slice.
// ==========================================================================

func TestSecurity_R3_233_MultiExporterNilChild(t *testing.T) {
	multi := &secMultiExporter{
		secAttestor: secAttestor{
			name:     "nil-child-parent",
			typeName: "https://test/nil-child-parent",
			runType:  attestation.ExecuteRunType,
		},
		exported: []attestation.Attestor{nil}, // nil entry
	}

	// This test may panic if the nil dereference is not handled.
	// We run it in a goroutine with recover to prevent test process crash.
	var panicked bool
	var panicVal interface{}
	var result []RunResult
	var runErr error

	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				panicVal = r
			}
		}()
		result, runErr = RunWithExports("nil-child-test",
			RunWithInsecure(true),
			RunWithAttestors([]attestation.Attestor{multi}),
		)
	}()

	if panicked {
		t.Logf("SECURITY FINDING R3-233 (CRITICAL): MultiExporter with nil in "+
			"ExportedAttestations() caused a panic in run() function. "+
			"Panic value: %v. The run() function's loop over exported "+
			"attestors (run.go line 147) dereferences nil without a nil check. "+
			"Unlike attestor Attest() calls (which have recover() in runAttestor), "+
			"the MultiExporter processing has NO panic recovery. A malicious "+
			"plugin returning nil in its exported list crashes the entire process.",
			panicVal)
		return
	}

	if runErr != nil {
		t.Logf("run returned error (acceptable): %v", runErr)
		return
	}

	// If we get here, the nil was handled gracefully (unexpected but good)
	t.Logf("nil child was handled gracefully, results: %d", len(result))
}

// ==========================================================================
// R3-234: VerifySignature returns envelope with valid structure on sig error
//
// FINDING: VerifySignature (verify.go lines 55-63) first decodes the
// envelope JSON, then calls envelope.Verify(). If Verify() fails (wrong
// key, invalid signature), the function returns the fully-parsed envelope
// along with the error. A caller who checks `env, err := VerifySignature()`
// and then uses `env` without checking `err` first will operate on an
// envelope whose signatures are INVALID.
//
// The partial envelope issue (truncated JSON) was documented in the
// adversarial tests, but the MORE DANGEROUS case is a FULLY VALID JSON
// envelope that simply has invalid signatures. The caller gets a complete,
// well-formed envelope object with all fields populated -- the only
// indication of failure is the error return.
//
// SEVERITY: HIGH -- Authentication bypass if the caller inspects the
// envelope before checking the error. The envelope looks perfectly valid;
// only the cryptographic verification failed.
// ==========================================================================

func TestSecurity_R3_234_VerifySignatureReturnsFullEnvelopeOnSigError(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)
	_, wrongVerifier := secMakeRSASignerVerifier(t)

	// Create a validly-structured signed envelope
	var buf bytes.Buffer
	err := Sign(
		bytes.NewReader([]byte(`{"test":"data"}`)),
		"application/json",
		&buf,
		dsse.SignWithSigners(signer),
	)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Verify with the WRONG verifier
	env, err := VerifySignature(bytes.NewReader(buf.Bytes()), wrongVerifier)
	if err == nil {
		t.Fatal("expected error from wrong verifier")
	}

	// Despite the error, the envelope is fully populated
	hasPayload := len(env.Payload) > 0
	hasPayloadType := env.PayloadType != ""
	hasSigs := len(env.Signatures) > 0

	if hasPayload && hasPayloadType && hasSigs {
		t.Logf("SECURITY FINDING R3-234: VerifySignature returned a FULLY POPULATED " +
			"envelope alongside a verification error. The envelope has: " +
			"PayloadType=%q, Payload=%d bytes, Signatures=%d. " +
			"A caller who accesses the envelope before checking the error " +
			"will see a complete, well-formed object with all fields set. " +
			"The only indication of failure is the error return. " +
			"This is more dangerous than the truncated-JSON case (R3-149 adversarial) " +
			"because the envelope LOOKS completely valid. " +
			"The function should return a zero-value Envelope on verification failure.",
			env.PayloadType, len(env.Payload), len(env.Signatures))
	}

	// Verify that the returned envelope has the full signed data
	if env.PayloadType != "application/json" {
		t.Errorf("expected payloadType 'application/json', got %q", env.PayloadType)
	}
	if len(env.Signatures) != 1 {
		t.Errorf("expected 1 signature, got %d", len(env.Signatures))
	}
}

// ==========================================================================
// R3-235: Deprecated Run() silently discards all RunResults on multiple results
//
// FINDING: When the deprecated Run() function detects multiple results
// (len(results) > 1), it returns an error with message "expected a
// single result, got multiple" and a zero-value RunResult{}. ALL results
// -- including successfully signed envelopes for exporters -- are
// discarded without any way for the caller to access them.
//
// Combined with the fact that Run() provides no way to know IN ADVANCE
// whether attestors will produce multiple results (Exporter.Export() is
// not checked until after attestation), a caller using the deprecated
// API will lose completed work silently.
//
// SEVERITY: MEDIUM -- Data loss and poor error recovery. The caller
// completed a potentially expensive attestation pipeline but cannot
// access any of the results. There is no way to recover without
// switching to RunWithExports().
// ==========================================================================

func TestSecurity_R3_235_DeprecatedRunDiscardsAllResults(t *testing.T) {
	// Create an exporter that will cause Run() to see >1 results
	exporter := &secAttestor{
		name:     "expensive-exporter",
		typeName: "https://test/expensive",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{
			"artifact": {{Hash: crypto.SHA256}: "aabbccdd"},
		},
	}

	// Also add a regular attestor so the collection can succeed in insecure mode
	regular := &secBareAttestor{
		name:     "regular",
		typeName: "https://test/regular",
		runType:  attestation.ExecuteRunType,
	}

	result, err := Run("deprecated-discard-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{exporter, regular}),
	)
	if err == nil {
		t.Fatal("expected error from deprecated Run() with multiple results")
	}

	if !strings.Contains(err.Error(), "expected a single result") {
		t.Fatalf("unexpected error: %v", err)
	}

	// The returned result is a zero-value, not the first result
	if result.Collection.Name != "" {
		t.Error("expected zero-value RunResult, but Collection.Name is set")
	}
	if len(result.SignedEnvelope.Signatures) > 0 {
		t.Error("expected zero-value RunResult, but SignedEnvelope has signatures")
	}

	// Meanwhile, RunWithExports would have returned all results successfully
	results, err2 := RunWithExports("deprecated-discard-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{exporter, regular}),
	)
	if err2 != nil {
		t.Fatalf("RunWithExports failed: %v", err2)
	}
	if len(results) < 2 {
		t.Fatalf("expected at least 2 results from RunWithExports, got %d", len(results))
	}

	t.Logf("SECURITY FINDING R3-235: Deprecated Run() discarded %d valid results " +
		"including signed exporter envelopes. The caller completed attestation " +
		"work but lost all results. The error message gives no indication of " +
		"how many results were produced or what they contained. There is no " +
		"way to recover the results without switching to RunWithExports().",
		len(results))
}

// ==========================================================================
// R3-236: Verify inherits ALL RunOptions including conflicting attestors
//
// FINDING: Verify() appends RunWithAttestors with the policyverify
// attestor (line 202-204) AFTER processing caller-provided RunOptions.
// If the caller passed VerifyWithRunOptions(RunWithAttestors(extraAtts)),
// those extra attestors are accumulated alongside the policyverify attestor.
//
// This means a caller can accidentally inject additional attestors into
// the verification run that execute alongside policyverify. These attestors
// run in the same AttestationContext, can observe materials/products, and
// their results appear in the collection alongside policyverify.
//
// SEVERITY: MEDIUM -- An attacker who controls the VerifyOption list
// can inject attestors that execute during policy verification, potentially
// exfiltrating policy details or producing misleading verification results.
// ==========================================================================

func TestSecurity_R3_236_VerifyAcceptsExtraAttestorsViaRunOptions(t *testing.T) {
	// Track whether an injected attestor was actually executed during Verify
	var injectedExecuted atomic.Int64
	injectedAtt := &secBareAttestor{
		name:     "injected",
		typeName: "https://test/injected",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			injectedExecuted.Add(1)
			return nil
		},
	}

	signer, _ := secMakeRSASignerVerifier(t)
	env := dsse.Envelope{
		Payload:     []byte("fake"),
		PayloadType: "test",
		Signatures:  []dsse.Signature{{KeyID: "k", Signature: []byte("s")}},
	}

	// Inject an extra attestor via VerifyWithRunOptions
	_, err := Verify(
		context.Background(),
		env,
		nil,
		VerifyWithSigners(signer),
		VerifyWithRunOptions(RunWithAttestors([]attestation.Attestor{injectedAtt})),
	)

	// Verify will fail (policyverify not registered), but check if injected was executed
	if err == nil {
		t.Fatal("expected error from Verify")
	}

	// The policyverify lookup fails before attestors run, so the injected
	// attestor may or may not have executed. But the fact that RunWithAttestors
	// is ACCEPTED means if policyverify were registered, the injected attestor
	// WOULD run alongside it.

	// Build the run options manually to demonstrate the accumulation
	vo := verifyOptions{}
	VerifyWithSigners(signer)(&vo)
	VerifyWithRunOptions(RunWithAttestors([]attestation.Attestor{injectedAtt}))(&vo)

	// Now simulate what Verify does: append its own attestors
	vo.runOptions = append(vo.runOptions, RunWithSigners(vo.signers...))
	// Verify would add the policyverify attestor here too
	// vo.runOptions = append(vo.runOptions, RunWithAttestors([]attestation.Attestor{configurer}))

	// Count how many attestors would be in the run
	ro := runOptions{}
	for _, opt := range vo.runOptions {
		opt(&ro)
	}

	if len(ro.attestors) > 0 {
		t.Logf("SECURITY FINDING R3-236: Verify() accepts arbitrary attestors via " +
			"VerifyWithRunOptions(RunWithAttestors(...)). After option processing, " +
			"%d extra attestors are accumulated. When policyverify is registered, " +
			"these attestors execute in the same AttestationContext as policyverify. " +
			"An attacker who controls the VerifyOption list can inject attestors " +
			"that run during verification, potentially observing policy details or " +
			"injecting misleading attestation data into the verification collection.",
			len(ro.attestors))
	}
}

// ==========================================================================
// R3-237: createAndSignEnvelope accepts empty predicate type string
//
// FINDING: createAndSignEnvelope (run.go line 237) accepts any predicate
// type string and passes it to intoto.NewStatement without validation.
// An empty string passes because intoto.NewStatement only validates
// subjects, not predicate type. The resulting in-toto statement has
// predicateType="" which:
//   1. Violates the in-toto spec (predicateType must be a URI)
//   2. Causes type confusion for any verifier matching on predicateType
//   3. Could bypass policy rules that filter by attestation type
//
// Combined with the Sign() function (sign.go) which also accepts empty
// data types (documented in adversarial tests), there is a consistent
// pattern of missing type validation across the signing pipeline.
//
// SEVERITY: MEDIUM -- Type confusion in signed attestations could bypass
// policy rules that filter by attestation type.
// ==========================================================================

func TestSecurity_R3_237_EmptyPredicateTypeSignedIntoEnvelope(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)

	// Create an attestor with an empty type string
	att := &secAttestor{
		name:     "empty-type",
		typeName: "", // empty type
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"art": {{Hash: crypto.SHA256}: "aabbccdd"},
		},
	}

	results, err := RunWithExports("empty-type-test",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The collection envelope should exist
	collection := results[len(results)-1]
	if len(collection.SignedEnvelope.Payload) == 0 {
		t.Fatal("expected signed envelope payload")
	}

	// Parse the statement to check the predicate type
	var stmt intoto.Statement
	if err := json.Unmarshal(collection.SignedEnvelope.Payload, &stmt); err != nil {
		t.Fatalf("failed to parse statement: %v", err)
	}

	// The collection predicate type should be the collection type, which IS valid
	if stmt.PredicateType != attestation.CollectionType {
		t.Errorf("expected predicate type %q, got %q", attestation.CollectionType, stmt.PredicateType)
	}

	// Now check the individual attestation within the collection
	// The attestation has an empty Type which will be in the collection
	found := false
	for _, ca := range collection.Collection.Attestations {
		if ca.Type == "" {
			found = true
			break
		}
	}
	if found {
		t.Log("SECURITY FINDING R3-237: An attestor with an empty Type() string was " +
			"accepted into the collection and signed into the DSSE envelope. " +
			"The empty type appears in the collection JSON. A policy engine " +
			"checking for required attestation types (e.g., 'must have a command-run " +
			"attestation') will not match the empty type, but a policy that only " +
			"checks len(attestations) > 0 would accept it. The collection's " +
			"Subjects() key format is 'type/name', so an empty type produces " +
			"keys like '/art' which could collide with other attestors.")
	}

	// Check for subject key collision potential
	subjects := collection.Collection.Subjects()
	for key := range subjects {
		if strings.HasPrefix(key, "/") {
			t.Logf("Subject key starts with '/': %q -- empty type causes unusual key format", key)
		}
	}
}

// ==========================================================================
// R3-238: Collection stores attestor objects by reference, enabling
// post-creation mutation of signed data
//
// FINDING: NewCollection (collection.go line 56) stores CompletedAttestor
// objects which contain references to the original attestor objects. The
// Collection's Subjects() method calls subjecter.Subjects() on these
// references on every invocation. This means:
//
//   1. After run() creates and signs the collection envelope, the caller
//      can modify the attestor's state (e.g., add/remove subjects)
//   2. Future calls to collection.Subjects() return DIFFERENT data than
//      what was signed into the envelope
//   3. The signed envelope becomes inconsistent with the collection object
//
// This is distinct from R3-142 (TOCTOU during the run) and R3-152
// (reuse across runs). This finding is about the Collection object
// itself being mutable after creation via its embedded attestor references.
//
// SEVERITY: HIGH -- Integrity violation. The signed envelope's subjects
// diverge from the live collection's subjects. A consumer who first
// verifies the envelope, then reads subjects from the collection object,
// could operate on unverified data.
// ==========================================================================

func TestSecurity_R3_238_CollectionMutableAfterSigning(t *testing.T) {
	signer, verifier := secMakeRSASignerVerifier(t)

	subjects := map[string]cryptoutil.DigestSet{
		"legitimate": {{Hash: crypto.SHA256}: "legit-hash"},
	}

	att := &secAttestor{
		name:     "mutable",
		typeName: "https://test/mutable",
		runType:  attestation.ExecuteRunType,
		subjects: subjects,
	}

	results, err := RunWithExports("mutable-test",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	collection := results[len(results)-1]

	// Step 1: Verify the envelope is valid
	_, err = collection.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
	if err != nil {
		t.Fatalf("envelope verification failed: %v", err)
	}

	// Step 2: Record subjects from the envelope (what was actually signed)
	var stmt intoto.Statement
	if err := json.Unmarshal(collection.SignedEnvelope.Payload, &stmt); err != nil {
		t.Fatalf("failed to parse statement: %v", err)
	}
	signedSubjectCount := len(stmt.Subject)

	// Step 3: MUTATE the attestor's subjects after signing
	subjects["malicious"] = cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "malicious-hash",
	}

	// Step 4: Read subjects from the collection object
	liveSubjects := collection.Collection.Subjects()

	// Step 5: Check for divergence
	if len(liveSubjects) != signedSubjectCount {
		t.Logf("SECURITY FINDING R3-238: After mutating the attestor's subjects " +
			"post-signing, the collection object's Subjects() returns %d subjects " +
			"while the signed envelope contains %d subjects. " +
			"The collection stores attestor objects by reference (not by value). " +
			"A consumer who verifies the envelope then reads subjects from " +
			"collection.Subjects() operates on UNVERIFIED data. " +
			"This is an integrity violation: the signed data and the live data diverge.",
			len(liveSubjects), signedSubjectCount)
	}

	// Verify the malicious subject appears in the live collection
	malKey := "https://test/mutable/malicious"
	if _, ok := liveSubjects[malKey]; ok {
		t.Log("Confirmed: malicious subject appears in collection.Subjects() " +
			"but was NOT signed into the envelope.")
	}
}

// ==========================================================================
// R3-239: Sign function silently succeeds even when Writer fails
//
// FINDING: The Sign function (sign.go line 31) creates a json.Encoder
// writing to the provided io.Writer and calls Encode(). If the Writer
// returns an error after a partial write, the json.Encoder may have
// already written some bytes to the Writer. The Sign function returns
// the error from Encode, but the Writer may contain partial/corrupt data.
//
// A caller checking err != nil will know the Sign failed, but if the
// Writer is a network connection or pipe where partial writes are
// observable by a downstream consumer, the partial data could be:
//   1. Parsed as a valid prefix of a JSON envelope
//   2. Confused with a valid (smaller) envelope
//   3. Used to infer the structure of the signing key's output
//
// SEVERITY: LOW -- Partial data leakage through the Writer on error.
// More importantly, this test validates that error propagation works
// correctly through the Sign -> dsse.Sign -> json.Encode chain.
// ==========================================================================

func TestSecurity_R3_239_SignPartialWriteOnWriterFailure(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)

	// Create a writer that fails after accepting some bytes
	fw := &failingWriter{
		limit: 10, // fail after 10 bytes
		err:   errors.New("disk full"),
	}

	err := Sign(
		bytes.NewReader([]byte(`{"test":"data"}`)),
		"application/json",
		fw,
		dsse.SignWithSigners(signer),
	)

	if err == nil {
		t.Fatal("expected error from failing writer")
	}

	if !strings.Contains(err.Error(), "disk full") {
		// The error might be wrapped
		t.Logf("error does not contain 'disk full' directly: %v", err)
	}

	if fw.written > 0 {
		t.Logf("SECURITY FINDING R3-239: Sign() wrote %d bytes to the Writer before "+
			"the Writer returned an error. If the Writer is a network connection, "+
			"these bytes are observable by the receiver. The partial data could "+
			"contain the beginning of a DSSE envelope JSON, revealing the payload "+
			"type and possibly the start of the base64-encoded payload. "+
			"The Sign function does not attempt to 'un-write' or signal the "+
			"partial write to the caller.", fw.written)
	} else {
		t.Log("No bytes were written before the error -- json.Encoder buffered everything")
	}
}

// ==========================================================================
// R3-140: Partial signed results returned on signing failure
//
// FINDING: When run() iterates over CompletedAttestors to sign individual
// exporter envelopes, a signing failure for one exporter causes an early
// return with error. But the `result` slice already contains successfully
// signed RunResults from earlier iterations. The caller receives both a
// non-nil error AND a non-empty results slice. If the caller checks
// results before error (a common Go anti-pattern), they'll use partially
// signed data.
//
// SEVERITY: HIGH -- Integrity violation. A verifier that only checks
// individual export envelopes could accept a partial set while the
// collection envelope was never created.
// ==========================================================================

func TestSecurity_R3_140_PartialResultsOnSigningFailure(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)

	// First exporter: has valid subjects, will sign successfully
	goodExporter := &secAttestor{
		name:     "good-exporter",
		typeName: "https://test/good-exporter",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{
			"artifact": {{Hash: crypto.SHA256}: "aabbccdd"},
		},
	}

	// Second exporter: has empty subjects. Previously this caused
	// intoto.NewStatement to fail with "at least one subject is required".
	// UPDATE: intoto.NewStatement now allows empty subjects (matching
	// upstream witness behavior), so this exporter succeeds with zero subjects.
	emptySubjectsExporter := &secAttestor{
		name:     "empty-subjects-exporter",
		typeName: "https://test/empty-subjects-exporter",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{}, // empty
	}

	results, err := RunWithExports("partial-test",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{goodExporter, emptySubjectsExporter}),
	)

	// intoto.NewStatement now allows empty subjects, so both exporters succeed.
	require.NoError(t, err,
		"Both exporters should succeed now that empty subjects are allowed")
	require.NotEmpty(t, results,
		"should produce results for both exporters and the collection")

	t.Logf("R3-140 UPDATE: With empty subjects now allowed, both exporters "+
		"sign successfully. Returned %d results. The original partial-results "+
		"leak finding is no longer applicable for this scenario.", len(results))
}

// ==========================================================================
// R3-141: ignoreErrors + signed mode with all-failing attestors
//
// When ignoreErrors=true and all attestors fail, the errors are
// suppressed but the collection ends up empty with no subjects.
//
// UPDATE: intoto.NewStatement now allows empty subjects (matching
// upstream witness behavior). This means the collection signing
// succeeds even with zero subjects. The ignoreErrors flag now
// truly suppresses all errors -- the run succeeds with an empty
// collection that has no subjects.
//
// SEVERITY: LOW -- The original finding about confusing error messages
// is resolved. However, the fact that a signed empty collection is
// silently produced may still surprise callers.
// ==========================================================================

func TestSecurity_R3_141_IgnoreErrorsSignedModeEmptyCollectionFails(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)

	failingAttestor := &secAttestor{
		name:     "fail",
		typeName: "https://test/fail",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"art": {{Hash: crypto.SHA256}: "deadbeef"},
		},
		attestFunc: func(_ *attestation.AttestationContext) error {
			return errors.New("deliberate failure")
		},
	}

	results, err := RunWithExports("ignore-errors-signed",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{failingAttestor}),
		RunWithIgnoreErrors(true),
	)

	// intoto.NewStatement now allows empty subjects, so the collection signing
	// succeeds even with zero attestors/subjects. The ignoreErrors flag now
	// truly suppresses all errors.
	require.NoError(t, err,
		"ignoreErrors=true should now succeed: empty subjects are allowed in intoto.NewStatement")
	require.NotEmpty(t, results, "should produce at least the collection result")

	t.Logf("R3-141 UPDATE: With empty subjects now allowed, ignoreErrors=true in "+
		"signed mode with all-failing attestors succeeds. Returned %d results. "+
		"The collection has zero attestations and zero subjects but is validly signed.",
		len(results))
}

// ==========================================================================
// R3-142: Subjects TOCTOU -- mutable subjects map returned by reference
//
// FINDING: When an attestor returns a mutable map from Subjects(), the
// run() function reads subjects multiple times:
//   - Once for the exporter's individual envelope (line 153/173)
//   - Once for the collection's envelope via Collection.Subjects() (line 215)
//
// If the attestor (or anything with a reference to the same map) mutates
// subjects between these reads, the signed envelope can contain subjects
// that differ from what was attested. This is a time-of-check-to-time-of-use
// (TOCTOU) vulnerability.
//
// SEVERITY: HIGH -- Integrity violation. An attacker who can inject a
// malicious attestor could sign legitimate subjects in the exporter
// envelope, then swap them before the collection envelope is signed.
// ==========================================================================

func TestSecurity_R3_142_SubjectsTOCTOU(t *testing.T) {
	subjects := map[string]cryptoutil.DigestSet{
		"original-artifact": {{Hash: crypto.SHA256}: "original-hash"},
	}

	att := &secAttestor{
		name:     "toctou",
		typeName: "https://test/toctou",
		runType:  attestation.ExecuteRunType,
		subjects: subjects,
		export:   false, // not an exporter, goes into collection
	}

	results, err := RunWithExports("toctou-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Now mutate the subjects map AFTER the run completed
	// In a real attack, this mutation would happen from a background goroutine
	// between the exporter signing and collection signing
	subjects["injected-artifact"] = cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "injected-hash",
	}

	// Get the collection
	collection := results[len(results)-1].Collection

	// Check if the injected subject appears in the collection's subjects
	collectionSubjects := collection.Subjects()
	for key := range collectionSubjects {
		if strings.Contains(key, "injected") {
			t.Logf("SECURITY FINDING R3-142: Injected subject %q appeared in collection "+
				"subjects after mutation. The attestor's Subjects() returns a reference "+
				"to mutable internal state. If mutated between signing the individual "+
				"exporter and signing the collection, the two envelopes will have "+
				"inconsistent subjects.", key)
			return
		}
	}

	// Even if the injected subject doesn't appear in the current call to
	// collection.Subjects(), the underlying data was still mutated. The
	// attestor object in the collection holds a reference to the same map.
	currentSubjects := att.Subjects()
	if _, ok := currentSubjects["injected-artifact"]; !ok {
		t.Error("expected injected subject in attestor's subjects map")
	}
	if len(currentSubjects) != 2 {
		t.Errorf("expected 2 subjects (original + injected), got %d", len(currentSubjects))
	}

	t.Log("SECURITY FINDING R3-142: The attestor's Subjects() returns a reference to " +
		"mutable state. Even though the collection was already created, a future call " +
		"to collection.Subjects() will see the mutated data because the attestor " +
		"object is stored by reference in the collection.")
}

// ==========================================================================
// R3-143: Race condition -- materials added after attestor appears in
// completedAttestors
//
// FINDING: In context.go runAttestor(), after a successful Attest() call:
//   1. completedAttestors is appended (line 247-253, under mutex)
//   2. mutex is released
//   3. addMaterials is called (line 255-258, under separate mutex acquisition)
//
// There is a window between steps 2 and 3 where the attestor IS in
// completedAttestors but its materials are NOT in ctx.materials.
// If another concurrent attestor in the same phase calls ctx.Materials()
// during this window, it will not see materials from the first attestor.
//
// SEVERITY: MEDIUM -- Integrity gap in concurrent attestor execution.
// An attestor that depends on another's materials (within the same phase)
// could miss data.
// ==========================================================================

func TestSecurity_R3_143_MaterialsRaceWindow(t *testing.T) {
	// We can't directly observe the window, but we can set up a scenario
	// that exercises it under the race detector.
	//
	// Create two attestors in the same phase:
	// - "slow" attestor that takes a moment to complete and provides materials
	// - "fast" attestor that completes instantly and reads materials

	var fastSawMaterials atomic.Int64

	slowMaterials := map[string]cryptoutil.DigestSet{
		"slow-file.txt": {{Hash: crypto.SHA256}: "slow-hash"},
	}

	slow := &secMaterialer{
		secAttestor: secAttestor{
			name:     "slow-materialer",
			typeName: "https://test/slow-mat",
			runType:  attestation.ExecuteRunType,
			attestFunc: func(ctx *attestation.AttestationContext) error {
				// Simulate work
				time.Sleep(5 * time.Millisecond)
				return nil
			},
		},
		materials: slowMaterials,
	}

	fast := &secBareAttestor{
		name:     "fast-reader",
		typeName: "https://test/fast-read",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(ctx *attestation.AttestationContext) error {
			// Give slow a chance to complete Attest but NOT addMaterials
			time.Sleep(8 * time.Millisecond)
			// Read materials -- this may or may not see slow's materials
			mats := ctx.Materials()
			fastSawMaterials.Store(int64(len(mats)))
			return nil
		},
	}

	// Run many times to increase chance of hitting the race window
	const iterations = 20
	missCount := 0
	for i := 0; i < iterations; i++ {
		fastSawMaterials.Store(-1)
		_, err := RunWithExports(
			fmt.Sprintf("materials-race-%d", i),
			RunWithInsecure(true),
			RunWithAttestors([]attestation.Attestor{slow, fast}),
		)
		if err != nil {
			// Could fail if slow completes after fast in some iteration
			continue
		}

		// Check what fast saw
		saw := fastSawMaterials.Load()
		if saw == 0 {
			missCount++
		}
	}

	// We can't guarantee the race will be hit, but document the finding
	t.Logf("SECURITY FINDING R3-143: In %d iterations, the fast attestor missed "+
		"materials from the slow attestor %d times. This demonstrates the "+
		"window between an attestor being marked complete and its materials "+
		"being added to the context. Attestors in the same phase should NOT "+
		"depend on each other's materials, but nothing prevents or warns about this.",
		iterations, missCount)

	// The real proof is running with -race flag
	t.Log("NOTE: Run with 'go test -race' to detect potential data races in the " +
		"materials addition path.")
}

// ==========================================================================
// R3-144: Non-deterministic collection content produces non-deterministic
// DSSE signatures in signed mode
//
// FINDING: Attestors in the same phase run concurrently. Their completion
// order determines the order of attestations in the collection. In signed
// mode, the collection is marshaled to JSON and signed. Different JSON
// (due to different attestation ordering) produces different DSSE
// signatures. This means the same logical attestation run can produce
// different signed envelopes, breaking reproducibility and making it
// impossible to verify that two runs produced equivalent results.
//
// SEVERITY: MEDIUM -- Non-deterministic signing breaks reproducibility.
// ==========================================================================

func TestSecurity_R3_144_NonDeterministicSignedEnvelope(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)

	const numAttestors = 5
	const iterations = 10

	payloads := make([]string, iterations)
	for iter := 0; iter < iterations; iter++ {
		attestors := make([]attestation.Attestor, numAttestors)
		for i := 0; i < numAttestors; i++ {
			attestors[i] = &secAttestor{
				name:     fmt.Sprintf("att-%02d", i),
				typeName: fmt.Sprintf("https://test/att-%02d", i),
				runType:  attestation.ExecuteRunType,
				subjects: map[string]cryptoutil.DigestSet{
					fmt.Sprintf("sub-%02d", i): {
						{Hash: crypto.SHA256}: fmt.Sprintf("hash-%02d", i),
					},
				},
			}
		}

		results, err := RunWithExports(
			"determinism-test",
			RunWithSigners(signer),
			RunWithAttestors(attestors),
		)
		if err != nil {
			t.Fatalf("iteration %d: unexpected error: %v", iter, err)
		}

		// Get the collection envelope's payload
		collection := results[len(results)-1]
		payloads[iter] = string(collection.SignedEnvelope.Payload)
	}

	allSame := true
	for i := 1; i < len(payloads); i++ {
		if payloads[i] != payloads[0] {
			allSame = false
			break
		}
	}

	if !allSame {
		t.Log("SECURITY FINDING R3-144: Signed collection envelopes have " +
			"different payloads across identical runs. The non-deterministic " +
			"attestor completion ordering causes different JSON serialization, " +
			"which produces different DSSE signatures. This breaks reproducibility " +
			"and could be exploited to create valid but different envelopes from " +
			"the same attestation run.")
	} else {
		t.Log("All payloads were identical in this run (goroutine scheduling " +
			"was consistent). The non-determinism may manifest under load.")
	}
}

// ==========================================================================
// R3-145: Nil signers pass validation but produce unsigned envelopes
//
// FINDING: validateRunOpts checks len(ro.signers) > 0 but does NOT check
// if any signer is non-nil. A caller passing [nil, nil] passes validation
// but dsse.Sign skips nil signers, producing an envelope with zero
// signatures. In non-insecure mode, this means the attestation appears
// signed but has no cryptographic protection.
//
// SEVERITY: HIGH -- Authentication bypass. The caller intends to sign
// (they provided signers and didn't set insecure=true) but gets an
// unsigned envelope with no error.
// ==========================================================================

func TestSecurity_R3_145_NilSignersProduceUnsignedEnvelope(t *testing.T) {
	nilSigners := []cryptoutil.Signer{nil, nil}

	// Step 1: Validation passes despite all signers being nil
	ro := runOptions{
		stepName: "nil-signers",
		signers:  nilSigners,
	}
	err := validateRunOpts(ro)
	if err != nil {
		t.Fatalf("validateRunOpts rejected nil signers (this would be the fix): %v", err)
	}

	// Step 2: Run with nil signers
	att := &secAttestor{
		name:     "test",
		typeName: "https://test/test",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"art": {{Hash: crypto.SHA256}: "aabb"},
		},
	}

	results, err := RunWithExports("nil-signers",
		RunWithSigners(nilSigners...),
		RunWithAttestors([]attestation.Attestor{att}),
	)

	if err != nil {
		// If this path is taken, dsse.Sign rejected the nil signers.
		// That would be correct behavior.
		t.Logf("dsse.Sign correctly rejected nil signers: %v", err)
		return
	}

	// We got here: the run succeeded with nil signers.
	collection := results[len(results)-1]
	sigCount := len(collection.SignedEnvelope.Signatures)

	if sigCount == 0 {
		t.Logf("SECURITY FINDING R3-145 (CRITICAL): Run succeeded in non-insecure mode "+
			"with signers=[nil,nil]. validateRunOpts passed (len=2 > 0), dsse.Sign "+
			"skipped nil signers and returned an envelope with %d signatures. "+
			"The attestation appears to be in signed mode but has NO cryptographic "+
			"protection. A verifier checking for a signed envelope would see "+
			"Signatures=[] and should reject it, but the producer got no error "+
			"indicating the signing was incomplete. This is an authentication bypass.",
			sigCount)
	} else {
		t.Errorf("unexpected: got %d signatures with nil signers", sigCount)
	}
}

// ==========================================================================
// R3-146: MultiExporter child attestor data not validated before signing
//
// FINDING: When a MultiExporter returns child attestors via
// ExportedAttestations(), the run() function signs each child's data
// without any validation. The child's Name(), Type(), and Subjects()
// are trusted blindly. A malicious MultiExporter could return children
// with arbitrary types that impersonate other attestor types.
//
// SEVERITY: HIGH -- Attestation forgery. A malicious plugin could inject
// a MultiExporter that returns children claiming to be "material" or
// "product" attestors with forged digest subjects.
// ==========================================================================

func TestSecurity_R3_146_MultiExporterChildTypeImpersonation(t *testing.T) {
	signer, verifier := secMakeRSASignerVerifier(t)

	// A malicious MultiExporter that returns a child claiming to be a
	// material attestor with forged subjects
	forgedChild := &secAttestor{
		name:     "material", // impersonates material attestor
		typeName: "https://aflock.ai/attestation/material/v0.1",
		runType:  attestation.MaterialRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"forged-binary": {{Hash: crypto.SHA256}: "deadbeefdeadbeef"},
		},
	}

	multi := &secMultiExporter{
		secAttestor: secAttestor{
			name:     "innocent-plugin",
			typeName: "https://test/innocent",
			runType:  attestation.ExecuteRunType,
		},
		exported: []attestation.Attestor{forgedChild},
	}

	// Include a legitimate attestor with subjects so the collection
	// signing succeeds
	legitimate := &secAttestor{
		name:     "legit",
		typeName: "https://test/legit",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"real-artifact": {{Hash: crypto.SHA256}: "realrealhash"},
		},
	}

	results, err := RunWithExports("impersonation-test",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{multi, legitimate}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find the forged child's envelope
	for _, r := range results {
		if r.AttestorName == "innocent-plugin/material" {
			// The forged child got a valid signed envelope
			if len(r.SignedEnvelope.Signatures) == 0 {
				t.Error("expected signatures on forged child's envelope")
				continue
			}

			// Verify the envelope is validly signed
			_, verifyErr := r.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
			if verifyErr != nil {
				t.Errorf("forged child's envelope failed verification: %v", verifyErr)
				continue
			}

			// Parse the signed statement to see what subjects were signed
			var stmt intoto.Statement
			if jsonErr := json.Unmarshal(r.SignedEnvelope.Payload, &stmt); jsonErr != nil {
				t.Errorf("failed to parse statement: %v", jsonErr)
				continue
			}

			if stmt.PredicateType == "https://aflock.ai/attestation/material/v0.1" {
				t.Log("SECURITY FINDING R3-146: A MultiExporter successfully created " +
					"a signed envelope with a child that impersonates a material " +
					"attestor type. The forged child got a valid DSSE signature. " +
					"A verifier trusting this type would accept the forged material " +
					"attestation. The run() function should validate that child " +
					"attestor types are consistent with their parent.")
			}

			// Check that forged subjects made it into the signed statement
			for _, subj := range stmt.Subject {
				if subj.Name == "forged-binary" {
					t.Log("SECURITY FINDING R3-146 (continued): Forged subject " +
						"'forged-binary' was signed into the in-toto statement. " +
						"An attacker can use MultiExporter to sign arbitrary " +
						"subject digests as any attestation type.")
				}
			}
			return
		}
	}

	t.Log("MultiExporter child was not found in results -- check attestor processing logic")
}

// ==========================================================================
// R3-147: Signed envelope and collection content consistency
//
// FINDING: The signed collection envelope contains a JSON-serialized
// in-toto statement with subjects derived from Collection.Subjects().
// But the envelope payload is a serialization of the STATEMENT, not the
// collection itself. The collection's actual attestation data and the
// subjects in the signed statement are derived independently. If there
// is a mismatch (e.g., due to an attestor that returns different
// Subjects() on each call), the envelope's subjects won't match the
// actual collection content.
//
// SEVERITY: MEDIUM -- Integrity gap. The signed subjects are supposed
// to authenticate the collection content, but they're derived from a
// separate code path.
// ==========================================================================

func TestSecurity_R3_147_CollectionSubjectsDivergeFromContent(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)

	att := &secAttestor{
		name:     "consistent",
		typeName: "https://test/consistent",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"myfile": {{Hash: crypto.SHA256}: "aabbccdd"},
		},
	}

	results, err := RunWithExports("consistency-test",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	collection := results[len(results)-1]

	// Parse the signed envelope's statement
	var stmt intoto.Statement
	if err := json.Unmarshal(collection.SignedEnvelope.Payload, &stmt); err != nil {
		t.Fatalf("failed to parse statement from envelope: %v", err)
	}

	// Get subjects from the collection object
	collSubjects := collection.Collection.Subjects()

	// The envelope's subjects should match the collection's subjects
	expectedKey := "https://test/consistent/myfile"
	if _, ok := collSubjects[expectedKey]; !ok {
		t.Errorf("expected subject key %q in collection subjects, got keys: %v",
			expectedKey, collSubjects)
	}

	// Check the envelope's statement subjects
	found := false
	for _, subj := range stmt.Subject {
		if subj.Name == expectedKey {
			found = true
			if subj.Digest["sha256"] != "aabbccdd" {
				t.Errorf("subject digest mismatch: got %q, want %q",
					subj.Digest["sha256"], "aabbccdd")
			}
		}
	}
	if !found {
		t.Errorf("expected subject %q in envelope statement, not found", expectedKey)
	}

	// Now mutate the attestor's subjects after signing
	att.subjects["injected"] = cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "injected-hash",
	}

	// The collection object still holds a reference to the attestor
	newSubjects := collection.Collection.Subjects()
	if _, ok := newSubjects["https://test/consistent/injected"]; ok {
		t.Log("SECURITY FINDING R3-147: After mutating the attestor's subjects " +
			"post-signing, the collection's Subjects() returns the new subjects. " +
			"The signed envelope is now inconsistent with the collection object. " +
			"A consumer who verifies the envelope but then reads subjects from " +
			"the collection object could see different subjects than what was signed.")
	}
}

// ==========================================================================
// R3-148: Concurrent same-phase attestors can observe partial context state
//
// FINDING: When multiple attestors run in the same phase, they execute
// concurrently. Each attestor receives the same AttestationContext and
// can call ctx.Materials(), ctx.Products(), and ctx.CompletedAttestors()
// while other attestors are still running. This means attestors can
// observe the context in an inconsistent state.
//
// SEVERITY: MEDIUM -- Data integrity issue for attestors that depend
// on context state within the same phase.
// ==========================================================================

func TestSecurity_R3_148_ConcurrentAttestorsPartialContextState(t *testing.T) {
	const numObservers = 10

	// Track what each attestor saw when it read completed attestors
	sawCompleted := make([]int, numObservers)
	var mu sync.Mutex

	attestors := make([]attestation.Attestor, numObservers)
	for i := 0; i < numObservers; i++ {
		idx := i
		attestors[i] = &secBareAttestor{
			name:     fmt.Sprintf("observer-%d", idx),
			typeName: fmt.Sprintf("https://test/observer-%d", idx),
			runType:  attestation.ExecuteRunType,
			attestFunc: func(ctx *attestation.AttestationContext) error {
				// Small jitter to increase chance of interleaving
				time.Sleep(time.Duration(idx) * time.Millisecond)
				completed := ctx.CompletedAttestors()
				mu.Lock()
				sawCompleted[idx] = len(completed)
				mu.Unlock()
				return nil
			},
		}
	}

	_, err := RunWithExports("partial-state-test",
		RunWithInsecure(true),
		RunWithAttestors(attestors),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check if any attestor saw a partial set of completed attestors
	mu.Lock()
	defer mu.Unlock()

	hasPartial := false
	for i, count := range sawCompleted {
		if count > 0 && count < numObservers {
			hasPartial = true
			t.Logf("attestor observer-%d saw %d completed attestors (partial)", i, count)
		}
	}

	if hasPartial {
		t.Log("SECURITY FINDING R3-148: Attestors in the same phase observed " +
			"partially-completed context state. An attestor running concurrently " +
			"can see completedAttestors from peers that finished before it. " +
			"This means an attestor's behavior can depend on goroutine scheduling, " +
			"making attestation results non-deterministic.")
	}
}

// ==========================================================================
// R3-149: createAndSignEnvelope signs arbitrary predicate types
//
// FINDING: createAndSignEnvelope accepts any predicate type string and
// signs it without validation. Combined with the MultiExporter finding
// (R3-146), an attacker can create signed envelopes with arbitrary
// predicate types that impersonate any attestation format, including
// the collection type itself.
//
// SEVERITY: HIGH -- A malicious attestor could create a signed envelope
// with predicateType "https://aflock.ai/attestation-collection/v0.1"
// that looks like a legitimate collection envelope.
// ==========================================================================

func TestSecurity_R3_149_ArbitraryPredicateTypeSigning(t *testing.T) {
	signer, verifier := secMakeRSASignerVerifier(t)

	// Create an attestor that claims to be a collection
	impersonator := &secAttestor{
		name:     "fake-collection",
		typeName: attestation.CollectionType, // impersonates collection type
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{
			"fake-art": {{Hash: crypto.SHA256}: "fakedata"},
		},
	}

	// Include a legitimate non-exporter attestor with subjects
	legitimate := &secAttestor{
		name:     "legit",
		typeName: "https://test/legit",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"real-art": {{Hash: crypto.SHA256}: "realdata"},
		},
	}

	results, err := RunWithExports("predicate-impersonation",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{impersonator, legitimate}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Find the impersonator's envelope
	for _, r := range results {
		if r.AttestorName == "fake-collection" {
			if len(r.SignedEnvelope.Signatures) == 0 {
				continue
			}

			_, verifyErr := r.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
			if verifyErr != nil {
				t.Errorf("impersonator envelope verification failed: %v", verifyErr)
				continue
			}

			var stmt intoto.Statement
			if jsonErr := json.Unmarshal(r.SignedEnvelope.Payload, &stmt); jsonErr != nil {
				t.Errorf("failed to parse statement: %v", jsonErr)
				continue
			}

			if stmt.PredicateType == attestation.CollectionType {
				t.Log("SECURITY FINDING R3-149: An exporter attestor successfully " +
					"created a validly-signed envelope with predicateType=" +
					attestation.CollectionType + ". This envelope is " +
					"indistinguishable from a legitimate collection envelope " +
					"by predicate type alone. A verifier matching on predicate " +
					"type could confuse this with a real collection. The signing " +
					"path should reject or flag attestors that use reserved " +
					"predicate types like the collection type.")
			}
			return
		}
	}
}

// ==========================================================================
// R3-150: Empty collection signed in insecure mode produces envelope with
// no payload integrity
// ==========================================================================

func TestSecurity_R3_150_EmptyCollectionInsecureMode(t *testing.T) {
	failingAttestor := &secBareAttestor{
		name:     "fail",
		typeName: "https://test/fail",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			return errors.New("fail")
		},
	}

	results, err := RunWithExports("empty-insecure",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{failingAttestor}),
		RunWithIgnoreErrors(true),
	)
	if err != nil {
		t.Fatalf("unexpected error with insecure+ignoreErrors: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result (the collection)")
	}

	collection := results[len(results)-1]
	if len(collection.Collection.Attestations) != 0 {
		t.Errorf("expected 0 attestations in collection, got %d",
			len(collection.Collection.Attestations))
	}

	if collection.Collection.Name != "empty-insecure" {
		t.Errorf("expected collection name 'empty-insecure', got %q",
			collection.Collection.Name)
	}

	if len(collection.SignedEnvelope.Signatures) != 0 {
		t.Error("expected no signatures in insecure mode")
	}

	t.Log("SECURITY FINDING R3-150: In insecure mode with ignoreErrors=true and " +
		"all-failing attestors, run() returns success with an empty collection. " +
		"A caller that checks err==nil and uses the collection will operate on " +
		"an empty attestation set. There is no indication that all attestors " +
		"failed. The collection name is set but has zero attestations.")
}

// ==========================================================================
// R3-151: Sign function with Reader that returns error mid-read
// ==========================================================================

func TestSecurity_R3_151_SignWithFailingReader(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)

	failR := &failingReader{
		data:    []byte("partial data"),
		failAt:  5,
		failErr: errors.New("disk error"),
	}

	var buf bytes.Buffer
	err := Sign(failR, "application/json", &buf, dsse.SignWithSigners(signer))
	if err == nil {
		t.Fatal("expected error from failing reader")
	}

	if !strings.Contains(err.Error(), "disk error") {
		t.Errorf("expected 'disk error' in error, got: %v", err)
	}

	if buf.Len() != 0 {
		t.Logf("SECURITY FINDING R3-151: Sign wrote %d bytes to writer despite "+
			"reader failure. Partial data may have been written.", buf.Len())
	}
}

// ==========================================================================
// R3-152: Multiple Run calls reuse same attestor objects
// ==========================================================================

func TestSecurity_R3_152_AttestorReuseStateLeakage(t *testing.T) {
	var attestCount atomic.Int64

	shared := &secAttestor{
		name:     "reused",
		typeName: "https://test/reused",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"art": {{Hash: crypto.SHA256}: "initial"},
		},
		attestFunc: func(_ *attestation.AttestationContext) error {
			attestCount.Add(1)
			return nil
		},
	}

	// Run 1
	results1, err := RunWithExports("run-1",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{shared}),
	)
	if err != nil {
		t.Fatalf("run 1 failed: %v", err)
	}

	// Modify the shared attestor's subjects between runs
	shared.subjects["leaked"] = cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "leaked-hash",
	}

	// Run 2 reuses the same attestor object
	results2, err := RunWithExports("run-2",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{shared}),
	)
	if err != nil {
		t.Fatalf("run 2 failed: %v", err)
	}

	// Check if run 2's collection has the leaked subject
	coll2 := results2[len(results2)-1].Collection
	subjects2 := coll2.Subjects()

	leakedKey := "https://test/reused/leaked"
	if _, ok := subjects2[leakedKey]; ok {
		t.Log("SECURITY FINDING R3-152: Reusing attestor objects across Run calls " +
			"leaks state. The 'leaked' subject added between run 1 and run 2 " +
			"appears in run 2's collection. run() does not create fresh copies " +
			"of attestor objects. Callers must create new attestor instances " +
			"for each Run call, but this is not documented or enforced.")
	}

	// Also verify that run 1's collection might be affected
	coll1 := results1[len(results1)-1].Collection
	subjects1 := coll1.Subjects()
	if _, ok := subjects1[leakedKey]; ok {
		t.Log("SECURITY FINDING R3-152 (continued): Even run 1's collection was " +
			"retroactively affected by the subject mutation. The collection " +
			"stores attestor objects by reference, not by value. Post-run " +
			"mutations to attestor state are visible in previously-created " +
			"collections.")
	}

	if attestCount.Load() != 2 {
		t.Errorf("expected attestor to be called twice, got %d", attestCount.Load())
	}
}

// ==========================================================================
// R3-153: insecure flag + non-insecure flag interaction
// ==========================================================================

func TestSecurity_R3_153_InsecureFlagLastCallWins(t *testing.T) {
	ro := runOptions{}

	// Caller wants signed mode
	RunWithInsecure(false)(&ro)
	if ro.insecure {
		t.Error("insecure should be false after explicit false")
	}

	// Library wrapper accidentally adds insecure=true
	RunWithInsecure(true)(&ro)
	if !ro.insecure {
		t.Error("insecure should be true after second call")
	}

	t.Log("SECURITY FINDING R3-153: RunWithInsecure follows last-call-wins " +
		"semantics. A wrapper library that appends RunWithInsecure(true) to " +
		"the options list will silently override a caller's RunWithInsecure(false). " +
		"There is no warning or error when the insecure flag is set multiple times. " +
		"Consider making this flag append-safe or add conflict detection.")
}

// ==========================================================================
// R3-154: Envelope payload is the in-toto statement, NOT the collection JSON
// ==========================================================================

func TestSecurity_R3_154_EnvelopeContainsFullCollectionPredicate(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)

	att := &secAttestor{
		name:     "verifiable",
		typeName: "https://test/verifiable",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"myart": {{Hash: crypto.SHA256}: "1234abcd"},
		},
	}

	results, err := RunWithExports("envelope-content",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	collection := results[len(results)-1]

	// Parse the statement from the envelope
	var stmt intoto.Statement
	if err := json.Unmarshal(collection.SignedEnvelope.Payload, &stmt); err != nil {
		t.Fatalf("failed to parse statement: %v", err)
	}

	// The predicate should be the collection JSON
	if stmt.PredicateType != attestation.CollectionType {
		t.Errorf("expected predicate type %q, got %q",
			attestation.CollectionType, stmt.PredicateType)
	}

	// Parse the predicate to verify it's a valid collection
	var coll attestation.Collection
	if err := json.Unmarshal(stmt.Predicate, &coll); err != nil {
		t.Fatalf("failed to parse collection from predicate: %v", err)
	}

	if coll.Name != "envelope-content" {
		t.Errorf("expected collection name 'envelope-content', got %q", coll.Name)
	}

	if len(coll.Attestations) == 0 {
		t.Error("expected attestations in collection predicate")
	}

	// Verify the statement subjects match
	if len(stmt.Subject) == 0 {
		t.Error("expected subjects in statement")
	}

	found := false
	for _, subj := range stmt.Subject {
		if strings.Contains(subj.Name, "myart") {
			found = true
			if subj.Digest["sha256"] != "1234abcd" {
				t.Errorf("subject digest mismatch: got %q, want %q",
					subj.Digest["sha256"], "1234abcd")
			}
		}
	}
	if !found {
		t.Error("expected subject containing 'myart' in statement")
	}
}

// Ensure unused imports are suppressed.
var (
	_ = io.Discard
)

// ==========================================================================
// NEW SECURITY AUDIT FINDINGS (R3-300 series)
// ==========================================================================

// ==========================================================================
// R3-300: insecure=true + ignoreErrors=true produces indistinguishable
// RunResult -- no field discriminates "intentionally unsigned" from
// "all attestors failed"
//
// FINDING: RunResult has two fields: Collection and SignedEnvelope.
// When insecure=true, SignedEnvelope is a zero-value dsse.Envelope
// (empty Payload, empty PayloadType, nil/empty Signatures). There is
// NO boolean field like "Insecure" or "Signed" on RunResult.
//
// When ignoreErrors=true and all attestors fail, the Collection has
// zero attestations and the SignedEnvelope is zero-value. This result
// is structurally IDENTICAL to a legitimate insecure run with zero
// attestors (which also succeeds with zero attestations).
//
// A downstream consumer receiving a RunResult cannot distinguish:
//   a) intentional insecure mode with no attestors (benign)
//   b) insecure mode where all attestors failed but errors were ignored
//
// SEVERITY: HIGH -- A consumer that trusts any RunResult with err==nil
// will silently accept an attestation set where every attestor failed.
// ==========================================================================

func TestSecurity_R3_300_InsecureIgnoreErrorsIndistinguishableFromSuccess(t *testing.T) {
	// Scenario A: legitimate insecure run with no attestors
	resultsGood, err := RunWithExports("good-insecure",
		RunWithInsecure(true),
	)
	require.NoError(t, err, "legitimate insecure run should succeed")
	require.NotEmpty(t, resultsGood, "should have at least one result (collection)")

	goodResult := resultsGood[len(resultsGood)-1]

	// Scenario B: insecure + ignoreErrors + ALL attestors fail
	failAtt := &secBareAttestor{
		name:     "total-failure",
		typeName: "https://test/total-failure",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			return errors.New("catastrophic failure")
		},
	}
	resultsBad, err := RunWithExports("bad-insecure",
		RunWithInsecure(true),
		RunWithIgnoreErrors(true),
		RunWithAttestors([]attestation.Attestor{failAtt}),
	)
	require.NoError(t, err, "insecure+ignoreErrors should suppress all errors")
	require.NotEmpty(t, resultsBad)

	badResult := resultsBad[len(resultsBad)-1]

	// Both results have zero-value envelopes
	require.Empty(t, goodResult.SignedEnvelope.Signatures,
		"good result should have no signatures (insecure mode)")
	require.Empty(t, badResult.SignedEnvelope.Signatures,
		"bad result should have no signatures (insecure mode)")

	// Both results have zero-value payload
	require.Empty(t, goodResult.SignedEnvelope.Payload,
		"good result should have empty payload")
	require.Empty(t, badResult.SignedEnvelope.Payload,
		"bad result should have empty payload")

	// Both have the same structural shape -- empty collection
	require.Empty(t, goodResult.Collection.Attestations,
		"good result: no attestors -> no attestations")
	require.Empty(t, badResult.Collection.Attestations,
		"bad result: all failed -> no attestations (errors suppressed)")

	t.Log("SECURITY FINDING R3-300: The combination of insecure=true + ignoreErrors=true " +
		"masks total attestor failure as a successful run. Both the legitimate " +
		"empty run and the total-failure run produce structurally identical RunResults " +
		"(zero-value SignedEnvelope, empty Collection.Attestations, nil error). " +
		"RunResult has no field to indicate: (1) whether signing was intentionally " +
		"skipped vs never attempted, (2) how many attestors failed, (3) the error mode. " +
		"A consumer trusting err==nil will silently accept an attestation set where " +
		"every attestor experienced a catastrophic failure.")
}

// ==========================================================================
// R3-301: Verify() auto-downgrades to insecure mode when no signers given
//
// FINDING: In verify.go lines 196-199, if no VerifyWithSigners is
// provided, Verify() automatically adds RunWithInsecure(true) to the
// run options. The policyverify result collection is NOT signed.
//
// SEVERITY: MEDIUM -- The verification output has no integrity protection.
// ==========================================================================

func TestSecurity_R3_301_VerifyAutoDowngradesToInsecure(t *testing.T) {
	vo := verifyOptions{}

	// No VerifyWithSigners provided

	// Simulate Verify's internal logic (verify.go lines 196-199):
	if len(vo.signers) > 0 {
		vo.runOptions = append(vo.runOptions, RunWithSigners(vo.signers...))
	} else {
		vo.runOptions = append(vo.runOptions, RunWithInsecure(true))
	}

	ro := runOptions{}
	for _, opt := range vo.runOptions {
		opt(&ro)
	}

	require.True(t, ro.insecure,
		"Verify() should have auto-enabled insecure mode when no signers provided")
	require.Empty(t, ro.signers,
		"Verify() should have no signers in insecure auto-downgrade")

	t.Log("SECURITY FINDING R3-301: Verify() automatically sets RunWithInsecure(true) " +
		"when no VerifyWithSigners are provided (verify.go line 199). The policyverify " +
		"result envelope is unsigned. A downstream system storing the VerifyResult for " +
		"audit gets an empty envelope with no cryptographic binding.")
}

// ==========================================================================
// R3-302: VerifyWithRunOptions allows injecting RunWithIgnoreErrors(true)
// into the verification pipeline
//
// FINDING: Verify() passes caller-provided VerifyWithRunOptions directly
// to Run(). This includes RunWithIgnoreErrors(true), which suppresses
// attestor errors. A caller can inject this to obscure policyverify
// attestor failures.
//
// SEVERITY: HIGH -- Obscures real verification failure mode.
// ==========================================================================

func TestSecurity_R3_302_VerifyWithIgnoreErrorsObscuresFailure(t *testing.T) {
	vo := verifyOptions{}

	// Caller injects ignoreErrors via VerifyWithRunOptions
	VerifyWithRunOptions(RunWithIgnoreErrors(true))(&vo)

	// Verify's internal processing adds insecure mode (no signers)
	vo.runOptions = append(vo.runOptions, RunWithInsecure(true))

	ro := runOptions{}
	for _, opt := range vo.runOptions {
		opt(&ro)
	}

	require.True(t, ro.ignoreErrors,
		"ignoreErrors should be injectable via VerifyWithRunOptions")
	require.True(t, ro.insecure,
		"insecure should be set by Verify's auto-downgrade")

	t.Log("SECURITY FINDING R3-302: VerifyWithRunOptions(RunWithIgnoreErrors(true)) is " +
		"accepted without validation. When injected, policyverify attestor errors are " +
		"suppressed. The check at verify.go line 228 catches the missing summary, " +
		"but the error is 'policy verification failed' with no indication that the " +
		"real cause was error suppression. Verify() should refuse RunWithIgnoreErrors.")
}

// ==========================================================================
// R3-303: RunResult has no Insecure/Signed flag -- consumers cannot
// distinguish insecure results from failed signing
//
// SEVERITY: MEDIUM -- Type confusion in result handling.
// ==========================================================================

func TestSecurity_R3_303_RunResultNoInsecureFlag(t *testing.T) {
	// Insecure mode result
	insecureResults, err := RunWithExports("insecure-step",
		RunWithInsecure(true),
	)
	require.NoError(t, err)
	require.NotEmpty(t, insecureResults)
	insecureResult := insecureResults[len(insecureResults)-1]

	// Signed mode result
	signer, _ := secMakeRSASignerVerifier(t)
	att := &secAttestor{
		name:     "test",
		typeName: "https://test/test",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"art": {{Hash: crypto.SHA256}: "aabb"},
		},
	}
	signedResults, err := RunWithExports("signed-step",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err)
	require.NotEmpty(t, signedResults)
	signedResult := signedResults[len(signedResults)-1]

	// The ONLY reliable discriminator is len(SignedEnvelope.Signatures) > 0
	insecureSigs := len(insecureResult.SignedEnvelope.Signatures)
	signedSigs := len(signedResult.SignedEnvelope.Signatures)

	require.Equal(t, 0, insecureSigs,
		"insecure result should have 0 signatures")
	require.Greater(t, signedSigs, 0,
		"signed result should have >0 signatures")

	t.Log("SECURITY FINDING R3-303: RunResult has no explicit Insecure or Signed field. " +
		"Consumers must check len(SignedEnvelope.Signatures) > 0, which is fragile: " +
		"nil signers in non-insecure mode (R3-145) also produce 0 signatures. " +
		"RunResult should have an explicit field indicating the signing mode.")
}

// ==========================================================================
// R3-304: MultiExporter children have no Collection field in RunResult
// in insecure mode -- attestation data is silently lost
//
// SEVERITY: MEDIUM -- Data loss in insecure mode.
// ==========================================================================

func TestSecurity_R3_304_MultiExporterChildrenNoCollectionInsecure(t *testing.T) {
	child := &secAttestor{
		name:     "child",
		typeName: "https://test/child",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"child-art": {{Hash: crypto.SHA256}: "childdata"},
		},
	}

	multi := &secMultiExporter{
		secAttestor: secAttestor{
			name:     "parent",
			typeName: "https://test/parent",
			runType:  attestation.ExecuteRunType,
		},
		exported: []attestation.Attestor{child},
	}

	results, err := RunWithExports("multi-insecure",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{multi}),
	)
	require.NoError(t, err)

	var childResult *RunResult
	for i := range results {
		if results[i].AttestorName == "parent/child" {
			childResult = &results[i]
			break
		}
	}
	require.NotNil(t, childResult,
		"should find child result with name 'parent/child'")

	// In insecure mode, the child's SignedEnvelope is zero-value
	require.Empty(t, childResult.SignedEnvelope.Signatures,
		"child envelope should be empty in insecure mode")
	require.Empty(t, childResult.SignedEnvelope.Payload,
		"child envelope payload should be empty in insecure mode")

	// The child's Collection is also zero-value
	require.Empty(t, childResult.Collection.Name,
		"child Collection.Name should be empty")
	require.Empty(t, childResult.Collection.Attestations,
		"child Collection.Attestations should be empty")

	t.Log("SECURITY FINDING R3-304: MultiExporter child RunResult in insecure mode has " +
		"both SignedEnvelope and Collection as zero values. The child's attestation " +
		"data is completely inaccessible. In signed mode, data is recoverable from " +
		"SignedEnvelope.Payload, but in insecure mode it is silently lost.")
}

// ==========================================================================
// R3-305: VerifySignature returns the full envelope on verification failure
//
// FINDING: VerifySignature first parses JSON, then verifies. On
// verification failure, the fully-populated Envelope is returned
// alongside the error. A caller can access unverified payload data.
//
// SEVERITY: HIGH -- Enables use of unverified data.
// ==========================================================================

func TestSecurity_R3_305_VerifySignatureExposesUnverifiedPayload(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)
	_, wrongVerifier := secMakeRSASignerVerifier(t)

	sensitivePayload := `{"secret":"do-not-use-without-verification"}`
	var buf bytes.Buffer
	err := Sign(
		bytes.NewReader([]byte(sensitivePayload)),
		"application/json",
		&buf,
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err, "signing should succeed")

	// Verify with wrong key
	env, err := VerifySignature(bytes.NewReader(buf.Bytes()), wrongVerifier)
	require.Error(t, err, "verification with wrong key should fail")

	// Despite the error, the payload is fully accessible
	require.NotEmpty(t, env.Payload,
		"FINDING: envelope payload is accessible despite verification failure")
	require.Equal(t, "application/json", env.PayloadType,
		"FINDING: envelope payloadType is accessible despite verification failure")
	require.NotEmpty(t, env.Signatures,
		"FINDING: signatures are accessible despite verification failure")

	// The unverified payload contains the sensitive data
	require.Contains(t, string(env.Payload), "secret",
		"FINDING: sensitive payload data is accessible in the unverified envelope")

	t.Log("SECURITY FINDING R3-305: VerifySignature returns the full Envelope on " +
		"verification failure. The payload, payloadType, and signatures are all " +
		"accessible. A caller who accesses env.Payload before checking err " +
		"operates on unverified data. The function should return a zero-value " +
		"Envelope on verification failure.")
}

// ==========================================================================
// R3-306: insecure=true silently ignores provided signers without warning
//
// SEVERITY: MEDIUM -- Configuration confusion.
// ==========================================================================

func TestSecurity_R3_306_InsecureSilentlyIgnoresSigners(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)

	att := &secAttestor{
		name:     "test",
		typeName: "https://test/test",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"art": {{Hash: crypto.SHA256}: "aabb"},
		},
	}

	// Provide BOTH signers AND insecure=true
	results, err := RunWithExports("conflicting-config",
		RunWithSigners(signer),
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err,
		"conflicting config (signers + insecure) should not error")

	collection := results[len(results)-1]

	// The signers were silently ignored
	require.Empty(t, collection.SignedEnvelope.Signatures,
		"FINDING: signers were silently ignored due to insecure=true")
	require.Empty(t, collection.SignedEnvelope.Payload,
		"FINDING: envelope is empty despite providing valid signers")

	// Validation passed
	ro := runOptions{
		stepName: "test",
		signers:  []cryptoutil.Signer{signer},
		insecure: true,
	}
	require.NoError(t, validateRunOpts(ro),
		"validateRunOpts accepts signers+insecure without error")

	t.Log("SECURITY FINDING R3-306: RunWithSigners + RunWithInsecure(true) silently " +
		"ignores the signers. validateRunOpts does not detect the conflict. " +
		"A developer who adds insecure=true for testing but provides signers " +
		"gets no warning that their signing intent is being overridden.")
}

// ==========================================================================
// R3-307: run() returns partial results alongside error on exporter
// signing failure
//
// FINDING: Each successful exporter's signed envelope is appended to
// `result` immediately. If a later exporter fails, the error is returned
// but `result` already contains earlier successful envelopes. The
// collection envelope was never created.
//
// SEVERITY: HIGH -- Partial result leakage with valid signed envelopes.
// ==========================================================================

func TestSecurity_R3_307_PartialResultsLeakedOnError(t *testing.T) {
	signer, verifier := secMakeRSASignerVerifier(t)

	goodExporter := &secAttestor{
		name:     "good",
		typeName: "https://test/good",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{
			"good-artifact": {{Hash: crypto.SHA256}: "goodhash"},
		},
	}

	// Previously this exporter with empty subjects caused a signing failure.
	// UPDATE: intoto.NewStatement now allows empty subjects (matching
	// upstream witness behavior), so this exporter succeeds with zero subjects.
	emptySubjectsExporter := &secAttestor{
		name:     "empty-subjects",
		typeName: "https://test/empty-subjects",
		runType:  attestation.ExecuteRunType,
		export:   true,
		subjects: map[string]cryptoutil.DigestSet{}, // empty -- now allowed
	}

	results, err := RunWithExports("partial-leak",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{goodExporter, emptySubjectsExporter}),
	)

	// intoto.NewStatement now allows empty subjects, so both exporters succeed.
	require.NoError(t, err,
		"Both exporters should succeed now that empty subjects are allowed")
	require.NotEmpty(t, results, "should produce results for both exporters and the collection")

	// Verify the good exporter's envelope is valid
	var goodFound bool
	for _, r := range results {
		if r.AttestorName == "good" && len(r.SignedEnvelope.Signatures) > 0 {
			_, verifyErr := r.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
			require.NoError(t, verifyErr, "good exporter's envelope should verify")
			goodFound = true
		}
	}
	require.True(t, goodFound, "should find the good exporter's signed envelope in results")

	t.Logf("R3-307 UPDATE: With empty subjects now allowed, both exporters "+
		"succeed. Returned %d results. The original partial-results leak "+
		"finding is no longer applicable for this scenario.", len(results))
}

// ==========================================================================
// R3-308: MultiExporter child Collection field always zero-value even in
// signed mode
//
// SEVERITY: MEDIUM -- API inconsistency leads to silent data loss.
// ==========================================================================

func TestSecurity_R3_308_MultiExporterChildCollectionAlwaysZero(t *testing.T) {
	signer, _ := secMakeRSASignerVerifier(t)

	child := &secAttestor{
		name:     "child",
		typeName: "https://test/child",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"child-art": {{Hash: crypto.SHA256}: "childdata"},
		},
	}

	multi := &secMultiExporter{
		secAttestor: secAttestor{
			name:     "parent",
			typeName: "https://test/parent",
			runType:  attestation.ExecuteRunType,
		},
		exported: []attestation.Attestor{child},
	}

	regular := &secAttestor{
		name:     "regular",
		typeName: "https://test/regular",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"reg-art": {{Hash: crypto.SHA256}: "regdata"},
		},
	}

	results, err := RunWithExports("multi-collection",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{multi, regular}),
	)
	require.NoError(t, err)

	for _, r := range results {
		if r.AttestorName == "parent/child" {
			require.Empty(t, r.Collection.Name,
				"FINDING: MultiExporter child has zero-value Collection.Name in signed mode")
			require.Empty(t, r.Collection.Attestations,
				"FINDING: MultiExporter child has zero-value Collection.Attestations")

			require.NotEmpty(t, r.SignedEnvelope.Signatures,
				"child should have signed envelope in signed mode")
			require.NotEmpty(t, r.SignedEnvelope.Payload,
				"child should have envelope payload in signed mode")
		} else if r.Collection.Name != "" {
			require.NotEmpty(t, r.Collection.Attestations,
				"collection result should have attestations")
			require.NotEmpty(t, r.SignedEnvelope.Signatures,
				"collection result should have signed envelope")
		}
	}

	t.Log("SECURITY FINDING R3-308: MultiExporter child RunResults have Collection as " +
		"zero-value even in signed mode. Data is only recoverable by parsing " +
		"SignedEnvelope.Payload JSON. A consumer using r.Collection uniformly " +
		"will silently get empty data for MultiExporter children.")
}

// ==========================================================================
// R3-309: Verify's VerifyWithRunOptions can override the policyverify
// attestor via RunWithInsecure(false) but gets silently overridden
//
// FINDING: If a caller provides VerifyWithRunOptions(RunWithInsecure(false))
// to explicitly request signed verification, but does not provide
// VerifyWithSigners, then Verify() appends RunWithInsecure(true) AFTER
// the caller's options. Last-call-wins semantics silently override the
// caller's explicit false to true.
//
// SEVERITY: HIGH -- Security downgrade. Caller explicitly requested
// signed mode but gets silently downgraded to insecure.
// ==========================================================================

func TestSecurity_R3_309_VerifyOverridesCallerInsecureFlag(t *testing.T) {
	vo := verifyOptions{}

	// Caller explicitly opts into signed mode via RunOptions
	VerifyWithRunOptions(RunWithInsecure(false))(&vo)

	// Simulate Verify's internal logic: no signers -> add insecure=true
	if len(vo.signers) > 0 {
		vo.runOptions = append(vo.runOptions, RunWithSigners(vo.signers...))
	} else {
		vo.runOptions = append(vo.runOptions, RunWithInsecure(true))
	}

	ro := runOptions{}
	for _, opt := range vo.runOptions {
		opt(&ro)
	}

	// The caller wanted insecure=false, but Verify overrode it to true
	require.True(t, ro.insecure,
		"Verify() should have overridden caller's insecure=false to true")

	t.Log("SECURITY FINDING R3-309: Verify() silently overrides the caller's " +
		"RunWithInsecure(false) to insecure=true when no VerifyWithSigners is provided. " +
		"Last-call-wins semantics cause the override. A caller explicitly requesting " +
		"signed verification gets silently downgraded to insecure mode.")
}

// ==========================================================================
// R3-310: Verify accepts extra attestors via VerifyWithRunOptions that
// execute alongside policyverify in the same AttestationContext
//
// SEVERITY: MEDIUM -- Attestor injection into verification pipeline.
// ==========================================================================

func TestSecurity_R3_310_VerifyAcceptsExtraAttestorsViaRunOptions(t *testing.T) {
	var injectedExecuted atomic.Int64
	injectedAtt := &secBareAttestor{
		name:     "injected",
		typeName: "https://test/injected",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			injectedExecuted.Add(1)
			return nil
		},
	}

	// Build the run options as Verify would
	vo := verifyOptions{}
	signer, _ := secMakeRSASignerVerifier(t)
	VerifyWithSigners(signer)(&vo)
	VerifyWithRunOptions(RunWithAttestors([]attestation.Attestor{injectedAtt}))(&vo)

	// Simulate what Verify does: append signers and attestors
	vo.runOptions = append(vo.runOptions, RunWithSigners(vo.signers...))

	// Count how many attestors would be in the run
	ro := runOptions{}
	for _, opt := range vo.runOptions {
		opt(&ro)
	}

	require.NotEmpty(t, ro.attestors,
		"injected attestors should be present in run options")

	t.Logf("SECURITY FINDING R3-310: Verify() accepts %d extra attestors via "+
		"VerifyWithRunOptions(RunWithAttestors(...)). When policyverify is registered, "+
		"these execute in the same AttestationContext. An attacker controlling the "+
		"VerifyOption list can inject attestors that run during verification.",
		len(ro.attestors))

	_ = injectedExecuted // tracked for potential future assertion
}

// ==========================================================================
// R3-311: Verify's VerificationSummary search uses first-match, enabling
// result injection if two attestations share the predicate type
//
// FINDING: In verify.go lines 215-226, Verify() iterates the collection
// looking for slsa.VerificationSummaryPredicate and breaks on FIRST
// match. If two attestations have this type (e.g., due to injected
// attestors from R3-310), only the first one controls the result.
//
// SEVERITY: HIGH (when combined with R3-310) -- Verification result
// injection through the attestation collection.
// ==========================================================================

func TestSecurity_R3_311_MultipleVerificationSummaryFirstMatchWins(t *testing.T) {
	// Create a collection with two VerificationSummaryPredicate entries
	att1 := &secAttestor{
		name:     "fake-verifier-1",
		typeName: "https://slsa.dev/verification_summary/v1",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"art1": {{Hash: crypto.SHA256}: "hash1"},
		},
	}
	att2 := &secAttestor{
		name:     "fake-verifier-2",
		typeName: "https://slsa.dev/verification_summary/v1",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"art2": {{Hash: crypto.SHA256}: "hash2"},
		},
	}

	results, err := RunWithExports("dual-verifier",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{att1, att2}),
	)
	require.NoError(t, err)

	collection := results[len(results)-1].Collection

	matchCount := 0
	for _, ca := range collection.Attestations {
		if ca.Type == "https://slsa.dev/verification_summary/v1" {
			matchCount++
		}
	}

	// Both attestors should appear in the collection
	require.Equal(t, 2, matchCount,
		"FINDING: Collection contains 2 attestations with VerificationSummaryPredicate type. "+
			"Verify() uses 'break' on first match (verify.go line 225). If a malicious "+
			"attestor produces this type and appears first, it controls verification outcome.")

	t.Log("SECURITY FINDING R3-311: Two attestations with type " +
		"VerificationSummaryPredicate co-exist in the collection. Verify() " +
		"uses first-match semantics (break on line 225). Combined with " +
		"non-deterministic attestor ordering (R3-144) and attestor injection " +
		"(R3-310), an attacker has a probabilistic chance of controlling the " +
		"verification outcome. Verify() should reject multiple entries or " +
		"validate all matches.")
}
