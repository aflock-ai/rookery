//go:build audit

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

package policy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ===========================================================================
// Test helpers (independent of the existing security test helpers to avoid
// name collisions since both files are in the same package).
// ===========================================================================

// r3Attestor is a JSON-marshalable Attestor for security tests.
type r3Attestor struct {
	AttName string                 `json:"name"`
	AttType string                 `json:"type"`
	Extra   map[string]interface{} `json:"extra,omitempty"`
}

func (a *r3Attestor) Name() string                                  { return a.AttName }
func (a *r3Attestor) Type() string                                  { return a.AttType }
func (a *r3Attestor) RunType() attestation.RunType                  { return "test" }
func (a *r3Attestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *r3Attestor) Schema() *jsonschema.Schema                    { return nil }

// r3WrappedAttestor wraps any struct with custom JSON marshaling.
type r3WrappedAttestor struct {
	inner    interface{}
	typeName string
}

func (w *r3WrappedAttestor) Name() string                                  { return "r3-wrapped" }
func (w *r3WrappedAttestor) Type() string                                  { return w.typeName }
func (w *r3WrappedAttestor) RunType() attestation.RunType                  { return "test" }
func (w *r3WrappedAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (w *r3WrappedAttestor) Schema() *jsonschema.Schema                    { return nil }
func (w *r3WrappedAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.inner)
}

// r3MockSource returns pre-configured results per step name.
type r3MockSource struct {
	byStep map[string][]source.CollectionVerificationResult
}

func (s *r3MockSource) Search(_ context.Context, stepName string, _ []string, _ []string) ([]source.CollectionVerificationResult, error) {
	return s.byStep[stepName], nil
}

func r3MakeVerifierAndKeyID(t *testing.T) (cryptoutil.Verifier, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	if err != nil {
		t.Fatalf("failed to get key ID: %v", err)
	}
	return verifier, keyID
}

func r3MakeCVR(stepName string, verifier cryptoutil.Verifier, attestations ...attestation.CollectionAttestation) source.CollectionVerificationResult {
	coll := attestation.Collection{
		Name:         stepName,
		Attestations: attestations,
	}
	return source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: coll,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}
}

// ===========================================================================
// R3-180: compareArtifacts is one-directional -- it only checks that
//         materials in the consuming step match the producing step's
//         artifacts. It does NOT check for artifacts in the producing
//         step that are ABSENT from the consuming step's materials.
//
//         This means an attacker who injects additional files into a
//         producing step's output (products) will never be detected by
//         the artifact integrity verification phase, because the
//         consuming step simply ignores files it doesn't list as
//         materials.
//
// Severity: HIGH
// Impact:  Supply-chain injection. An attacker adds a malicious binary
//          to a build step's products. The deploy step only checks its
//          own materials against the build products; the extra file is
//          silently ignored. The policy "passes" even though the build
//          step produced untrusted artifacts.
//
// The fix would be to add a strict mode to compareArtifacts that fails
// when upstream artifacts contain files not present in downstream materials.
// ===========================================================================

func TestSecurity_R3_180_CompareArtifactsIgnoresExtraUpstreamArtifacts(t *testing.T) {
	sha256Key := cryptoutil.DigestValue{Hash: crypto.SHA256}

	// Consuming step's materials: only "app.bin"
	materials := map[string]cryptoutil.DigestSet{
		"app.bin": {sha256Key: "aaa111"},
	}

	// Producing step's artifacts: "app.bin" (matching) + "malware.bin" (injected)
	artifacts := map[string]cryptoutil.DigestSet{
		"app.bin":     {sha256Key: "aaa111"},
		"malware.bin": {sha256Key: "evil666"},
	}

	err := compareArtifacts(materials, artifacts)

	// BUG: compareArtifacts returns nil because all materials matched.
	// The injected "malware.bin" is silently ignored.
	if err != nil {
		// If this branch executes, the bug has been FIXED (strict mode).
		t.Log("FIXED: compareArtifacts now rejects extra artifacts in the " +
			"producing step that are not consumed as materials. Supply-chain " +
			"injection via extra files is now detected.")
		return
	}

	// Bug is present: extra artifacts are silently ignored.
	t.Error("SECURITY BUG R3-180: compareArtifacts does not detect extra " +
		"artifacts ('malware.bin') in the producing step that are absent from " +
		"the consuming step's materials. An attacker can inject arbitrary files " +
		"into a step's products without triggering artifact verification failure. " +
		"This is a supply-chain injection vector.")
}

// ===========================================================================
// R3-181: checkCertConstraint returns nil (pass) when BOTH constraints
//         and values are empty/nil. This means a CertConstraint with
//         no DNS/Email/Org requirements trivially passes for ANY cert
//         that also lacks those fields. There is no way to express
//         "the cert MUST have at least one DNS SAN" -- absence of
//         constraint means "accept absence of value."
//
//         This creates a policy bypass when combined with AllowAll
//         roots: a cert with no SANs/Orgs from any trusted root
//         passes all checks, making identity verification meaningless.
//
// Severity: HIGH
// Impact:  Any certificate without SANs satisfies a constraint that
//          doesn't specify SANs. Policy authors who forget to add
//          explicit SAN constraints get zero identity verification.
//
// The fix would be to require at least one non-empty constraint field
// (CN, DNS, Email, Org, or URI) in CertConstraint when used with a
// functionary, or add a "strict" mode that rejects empty constraints.
// ===========================================================================

func TestSecurity_R3_181_EmptyConstraintMatchesEmptyCertFields(t *testing.T) {
	// Verify that nil constraints + nil values = pass
	err := checkCertConstraint("dns name", nil, nil)
	if err != nil {
		t.Fatalf("expected nil constraints + nil values to pass, got: %v", err)
	}

	// Verify that nil constraints + empty values = pass
	err = checkCertConstraint("dns name", nil, []string{})
	if err != nil {
		t.Fatalf("expected nil constraints + empty values to pass, got: %v", err)
	}

	// Verify that empty constraints + nil values = pass
	err = checkCertConstraint("dns name", []string{}, nil)
	if err != nil {
		t.Fatalf("expected empty constraints + nil values to pass, got: %v", err)
	}

	// NOW: what happens with nil constraints + cert HAS values?
	// This SHOULD fail because no constraints were specified but the cert has values.
	err = checkCertConstraint("dns name", nil, []string{"evil.com"})

	// BUG: When constraints are nil (len=0), the function returns an error
	// saying "not expecting any dns name(s)". This is actually CORRECT
	// behavior for this specific case. The real issue is the INVERSE:
	// when the policy WANTS a DNS name but the cert has none.
	if err == nil {
		t.Error("SECURITY BUG R3-181: nil constraints accepted a cert with " +
			"DNS values. Expected rejection.")
	}

	// The TRUE vulnerability: there's no way to require a cert HAVE a DNS name.
	// If constraints = ["build.example.com"] and cert has no DNS names at all,
	// what happens?
	err = checkCertConstraint("dns name",
		[]string{"build.example.com"}, // Require this DNS name
		[]string{},                    // Cert has NO DNS names
	)
	if err == nil {
		t.Error("SECURITY BUG R3-181: constraint requiring 'build.example.com' " +
			"passed for a cert with NO DNS names. This is a policy bypass.")
	} else {
		t.Logf("Correct: constraint requiring DNS name rejects cert without DNS names: %v", err)
	}

	// Now test: what if cert has completely DIFFERENT DNS names than constraint?
	err = checkCertConstraint("dns name",
		[]string{"build.example.com"},   // Require this DNS name
		[]string{"evil.attacker.com"},   // Cert has a different DNS name
	)
	if err == nil {
		t.Error("SECURITY BUG R3-181: constraint requiring 'build.example.com' " +
			"passed for cert with 'evil.attacker.com'. This is a policy bypass.")
	} else {
		t.Logf("Correct: mismatched DNS names rejected: %v", err)
	}

	// The REAL vulnerability is the combination of all-empty CertConstraint
	// with a real cert that has no SANs. This has already been documented in
	// R3-155, but the root cause is HERE in checkCertConstraint: the semantics
	// of "empty constraint = accept anything including nothing" are inherently
	// dangerous for a supply-chain security tool.
	//
	// A safer default would be fail-closed: empty constraints should mean
	// "no valid value exists that satisfies this constraint" rather than
	// "any value (including none) satisfies this constraint."

	// Test that empty constraints + empty values = pass (the dangerous case)
	err = checkCertConstraint("organization", []string{}, []string{})
	if err != nil {
		t.Log("FIXED: Empty constraints no longer trivially pass for empty values.")
		return
	}
	t.Error("SECURITY BUG R3-181: Empty constraint + empty cert value = pass. " +
		"A CertConstraint with no Organization requirement accepts ANY cert " +
		"that also has no Organization. Combined with Roots=[\"*\"], this makes " +
		"identity verification a no-op. The safe default should require at least " +
		"one identity constraint field to be non-empty.")
}

// ===========================================================================
// R3-182: compareArtifacts returns nil (pass) when the consuming step
//         has ZERO materials (empty materials map). This means a step
//         with no material attestors trivially passes the artifact
//         integrity check against ANY upstream step.
//
// Severity: HIGH
// Impact:  An attacker who can produce a collection with no material
//          attestors (or whose material attestor returns an empty map)
//          bypasses all artifact chain verification. The step "passes"
//          the artifact integrity check even if the upstream step
//          produced completely different files.
//
// The fix would be to fail when materials is empty and the step has
// ArtifactsFrom references (meaning the policy author intended artifact
// integrity to be checked).
// ===========================================================================

func TestSecurity_R3_182_EmptyMaterialsBypassesArtifactCheck(t *testing.T) {
	sha256Key := cryptoutil.DigestValue{Hash: crypto.SHA256}

	// Empty materials: the consuming step has no materials at all.
	materials := map[string]cryptoutil.DigestSet{}

	// Producing step has arbitrary artifacts.
	artifacts := map[string]cryptoutil.DigestSet{
		"trusted-app.bin": {sha256Key: "aaa111"},
		"config.yaml":     {sha256Key: "bbb222"},
	}

	err := compareArtifacts(materials, artifacts)

	// BUG: The for loop over materials (line 639) has nothing to iterate,
	// so the function falls through and returns nil.
	if err != nil {
		t.Log("FIXED: compareArtifacts now rejects empty materials when " +
			"there are upstream artifacts to check against.")
		return
	}

	t.Error("SECURITY BUG R3-182: compareArtifacts returns nil (pass) when " +
		"the consuming step has ZERO materials. An attacker can forge a " +
		"collection with no material attestors, causing the artifact integrity " +
		"check to trivially pass. The step's ArtifactsFrom constraint becomes " +
		"meaningless because there are no materials to compare against.")
}

// ===========================================================================
// R3-183: EvaluateRegoPolicy handles duplicate package names by deduplicating
//         the query (denyPaths map prevents the same deny path from appearing
//         twice). However, OPA merges rules from modules with the same package
//         name. An attacker who can inject a second module with the same
//         package name as a legitimate policy module can ADD rules that
//         dilute the deny set, or worse, shadow definitions.
//
//         More critically: if an attacker supplies a module with the same
//         package name but a deny rule that always returns an empty set,
//         OPA's rule merging means both the attacker's and legitimate
//         deny rules contribute to the result. This doesn't directly
//         allow bypass (the legitimate deny reasons still appear), but
//         it means the attacker can influence which deny reasons appear
//         in the output.
//
//         The REAL issue: the code deduplicates the QUERY but not the
//         modules. If two modules define the same package, the query
//         has one deny path, but both modules' rules are evaluated.
//         If the attacker's module defines helper rules that shadow
//         the legitimate module's helper rules, the deny behavior changes.
//
// Severity: HIGH
// Impact:  Policy bypass via Rego rule shadowing.
// ===========================================================================

func TestSecurity_R3_183_RegoPackageNameCollisionEnablesShadowing(t *testing.T) {
	// Legitimate policy: denies if "approved" is not true.
	legitimateModule := RegoPolicy{
		Name: "legitimate.rego",
		Module: []byte(`package build_policy

deny[msg] {
  not is_approved
  msg := "build not approved"
}

is_approved {
  input.approved == true
}
`),
	}

	// Attacker's module: SAME package name, redefines is_approved to always
	// be true. OPA merges rules: is_approved is true if EITHER module's
	// is_approved body matches. The attacker's body always matches.
	attackerModule := RegoPolicy{
		Name: "attacker.rego",
		Module: []byte(`package build_policy

is_approved {
  true
}
`),
	}

	// Attestor that should FAIL the legitimate policy (approved=false).
	attestor := &r3WrappedAttestor{
		typeName: "build-type",
		inner: map[string]interface{}{
			"name":     "test-build",
			"type":     "build-type",
			"approved": false,
		},
	}

	// Evaluate with only the legitimate module -- should deny.
	err := EvaluateRegoPolicy(attestor, []RegoPolicy{legitimateModule})
	if err == nil {
		t.Fatal("expected legitimate policy to deny unapproved build")
	}
	if !strings.Contains(err.Error(), "build not approved") {
		t.Fatalf("expected 'build not approved' denial, got: %v", err)
	}
	t.Logf("Legitimate policy correctly denies: %v", err)

	// Now evaluate with BOTH modules -- the attacker's is_approved shadows
	// the legitimate one. In OPA, is_approved is true if ANY defining rule
	// body matches. The attacker's rule has body "true", so is_approved is
	// always true, and the deny rule never fires.
	err = EvaluateRegoPolicy(attestor, []RegoPolicy{legitimateModule, attackerModule})
	if err == nil {
		// The attacker's module successfully shadowed the legitimate is_approved.
		t.Error("SECURITY BUG R3-183: Rego package name collision allows an " +
			"attacker to inject a module that redefines helper rules (is_approved) " +
			"in the same package. OPA merges the rules, and the attacker's " +
			"always-true is_approved causes the deny rule to never fire. " +
			"The build with approved=false PASSED the policy check. " +
			"The fix should reject duplicate package names across modules " +
			"or namespace them by policy name.")
	} else {
		t.Logf("Policy still denied with both modules: %v", err)
		t.Log("The attacker's module did not fully shadow the legitimate " +
			"is_approved rule. OPA may have different merging semantics " +
			"than expected.")
	}
}

// ===========================================================================
// R3-184: Functionary.Validate returns nil (pass) immediately when
//         f.PublicKeyID matches verifierID, WITHOUT checking any
//         CertConstraint. This means an X.509 verifier whose computed
//         KeyID happens to match the functionary's PublicKeyID bypasses
//         ALL certificate constraint checks (CN, Org, DNS, Roots).
//
//         This is by design for public-key functionaries, but it
//         creates a dangerous shortcut: if a CertConstraint is
//         specified alongside a PublicKeyID, the CertConstraint is
//         silently ignored when the KeyID matches. A policy author
//         who thinks both checks are applied is wrong.
//
// Severity: HIGH
// Impact:  Certificate constraint bypass. A functionary with both
//          PublicKeyID and CertConstraint only checks CertConstraint
//          when the KeyID doesn't match. If the KeyID matches (e.g.,
//          an X.509 cert's derived KeyID), all cert constraints are
//          skipped.
// ===========================================================================

func TestSecurity_R3_184_PublicKeyIDMatchBypassesCertConstraint(t *testing.T) {
	// Create a CA and leaf cert.
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TestCA", Organization: []string{"GoodCorp"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	// Leaf cert with CN="attacker" and Org="EvilCorp"
	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "attacker", Organization: []string{"EvilCorp"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	x509Verifier, err := cryptoutil.NewX509Verifier(leafCert, nil, []*x509.Certificate{caCert}, time.Now())
	if err != nil {
		t.Fatalf("failed to create X509 verifier: %v", err)
	}

	// Get the KeyID that the X509 verifier computes.
	verifierKeyID, err := x509Verifier.KeyID()
	if err != nil {
		t.Fatalf("failed to get verifier key ID: %v", err)
	}

	trustBundles := map[string]TrustBundle{
		"test-root": {Root: caCert},
	}

	// Functionary that specifies BOTH a PublicKeyID (matching the X509 verifier's
	// computed KeyID) AND a CertConstraint requiring CN="builder" and Org="GoodCorp".
	// The cert has CN="attacker" and Org="EvilCorp" -- it should FAIL the constraint.
	f := Functionary{
		PublicKeyID: verifierKeyID, // Matches the X509 verifier's derived KeyID
		CertConstraint: CertConstraint{
			CommonName:    "builder",
			Organizations: []string{"GoodCorp"},
			Roots:         []string{"test-root"},
		},
	}

	err = f.Validate(x509Verifier, trustBundles)

	if err == nil {
		// The PublicKeyID matched, so CertConstraint was never checked.
		t.Error("SECURITY BUG R3-184: Functionary.Validate returned nil for " +
			"an X.509 cert with CN='attacker', Org='EvilCorp' because the " +
			"verifier's computed KeyID matched the functionary's PublicKeyID. " +
			"The CertConstraint requiring CN='builder', Org='GoodCorp' was " +
			"completely bypassed. Any X.509 certificate whose derived KeyID " +
			"matches the PublicKeyID skips ALL certificate constraint checks. " +
			"The fix should apply CertConstraint checks regardless of KeyID " +
			"match when the verifier is an X509Verifier.")
	} else {
		t.Logf("CertConstraint was checked despite KeyID match: %v", err)
		t.Log("FIXED: Functionary.Validate now applies CertConstraint even " +
			"when PublicKeyID matches for X.509 verifiers.")
	}
}

// ===========================================================================
// R3-185: Policy.Validate() does not check that step.Name matches its
//         map key, NOR does it check for empty step names. A step with
//         Name="" in the Steps map creates a silent misconfiguration
//         where the step's collection name filter in validateAttestations
//         (line 255) matches ANY collection with an empty name.
//
//         Combined with the empty-collection-name bypass (R3-151), this
//         means a policy with an empty-named step accepts any
//         empty-named collection, creating a universal match.
//
// Severity: MEDIUM
// Impact:  Policy misconfiguration goes undetected. A step with Name=""
//          matches all empty-named collections, which may be produced by
//          default/unconfigured attestation generators.
// ===========================================================================

func TestSecurity_R3_185_ValidateAcceptsEmptyStepName(t *testing.T) {
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			"build": {
				Name: "", // Empty step name!
			},
		},
	}

	err := p.Validate()
	if err != nil {
		t.Logf("FIXED: Validate rejects empty step names: %v", err)
		return
	}

	t.Error("SECURITY BUG R3-185: Policy.Validate() accepts a step with " +
		"Name=\"\" (empty string). An empty step name combined with the " +
		"empty-collection-name bypass means validateAttestations will accept " +
		"ANY collection whose Name is also empty. Validate() should reject " +
		"steps with empty Name fields.")
}

// ===========================================================================
// R3-186: Verify() calls step.validateAttestations for each passed
//         collection. The validateAttestations method skips collections
//         where collection.Collection.Name != s.Name (line 255), UNLESS
//         the collection name is "". But it also skips when the step
//         has no required attestations (s.Attestations is empty),
//         because the for loop over s.Attestations has nothing to
//         iterate. In that case, passed=true by default, and the
//         collection is added to result.Passed.
//
//         This means a step with no required Attestations auto-passes
//         ANY collection that gets through the functionary check and
//         name filter. The step is then fully "verified" without any
//         attestation content being checked.
//
// Severity: HIGH
// Impact:  A step with Functionaries but no Attestations requirements
//          accepts any signed collection from an authorized functionary,
//          regardless of what the collection actually contains. An
//          authorized signer can produce an empty or irrelevant
//          collection and satisfy the step.
// ===========================================================================

func TestSecurity_R3_186_NoAttestationsRequiredAutoPassesAnyCollection(t *testing.T) {
	verifier, keyID := r3MakeVerifierAndKeyID(t)

	// Step with a functionary but NO required attestations.
	step := Step{
		Name:          "build",
		Functionaries: []Functionary{{PublicKeyID: keyID}},
		Attestations:  []Attestation{}, // No attestations required!
	}

	// A collection with arbitrary (possibly irrelevant) attestation content.
	coll := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{
				Type:        "https://example.com/completely-irrelevant/v1",
				Attestation: &r3Attestor{AttName: "junk", AttType: "irrelevant"},
			},
		},
	}

	cvr := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: coll,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	// First pass: functionary check
	funcResult := step.checkFunctionaries([]source.CollectionVerificationResult{cvr}, nil)
	if len(funcResult.Passed) == 0 {
		t.Fatal("expected collection to pass functionary check")
	}

	// Second pass: attestation validation
	passedCollections := make([]source.CollectionVerificationResult, len(funcResult.Passed))
	for i, pc := range funcResult.Passed {
		passedCollections[i] = pc.Collection
	}
	attResult := step.validateAttestations(passedCollections, "", nil)

	if len(attResult.Passed) > 0 {
		t.Error("SECURITY BUG R3-186: A step with NO required Attestations " +
			"auto-passes ANY collection that clears the functionary check. " +
			"The collection contained a completely irrelevant attestation type " +
			"('completely-irrelevant/v1') but was marked as passed. An " +
			"authorized signer can satisfy this step with ANY collection content. " +
			"Steps should require at least one Attestation, or the policy should " +
			"warn about steps with empty Attestation lists.")
	} else {
		t.Log("FIXED: Steps with no required attestations no longer auto-pass.")
	}
}

// ===========================================================================
// R3-187: In the Verify() loop (line 430), the search is performed
//         using the map key (stepName from `for _, stepName := range stepOrder`),
//         but the Step's Name field is used in checkFunctionaries
//         (step.Name at line 524) and validateAttestations. When a step
//         is stored under a key that DIFFERS from its Name field (a
//         misconfiguration), the StepResult is stored under the MAP KEY
//         (line 475-483: `resultsByStep[stepName]`), but verifyArtifacts
//         iterates `p.Steps` and uses `step.Name` to look up results
//         (line 565: `resultsByStep[step.Name]`).
//
//         This creates a lookup mismatch: results stored under map key
//         "deploy" are looked up via step.Name "build", causing
//         verifyArtifacts to find no results for the step and creating
//         phantom rejections.
//
// Severity: HIGH
// Impact:  Split-brain between map key and step.Name causes artifact
//          verification to silently fail. A misconfigured policy where
//          any step's Name differs from its map key breaks the entire
//          verification pipeline.
//
// Note: This test proves the bug through the full Verify() path, unlike
//       R3-166 which only tested the Verify call at a high level.
// ===========================================================================

func TestSecurity_R3_187_StepNameVsMapKeyBreaksArtifactVerification(t *testing.T) {
	verifier, keyID := r3MakeVerifierAndKeyID(t)
	attType := "https://example.com/att/v1"

	// Step stored under key "step-a" with Name="wrong-name"
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			"step-a": {
				Name:          "wrong-name", // Doesn't match map key!
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: attType}},
			},
		},
	}

	// Validate should catch this misconfiguration.
	err := p.Validate()
	if err != nil {
		t.Logf("FIXED: Validate catches step name vs map key mismatch: %v", err)
		return
	}

	// The source returns a collection named "step-a" (the map key used in search).
	cvr := r3MakeCVR("step-a", verifier, attestation.CollectionAttestation{
		Type:        attType,
		Attestation: &r3Attestor{AttName: "att", AttType: attType},
	})

	src := &r3MockSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"step-a": {cvr},
		},
	}

	_, _, verifyErr := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
	)

	if verifyErr != nil {
		// The split-brain manifests as a verification failure.
		t.Errorf("SECURITY BUG R3-187: Verify failed due to step name vs map "+
			"key mismatch that Validate() did not catch. The verifyArtifacts phase "+
			"looks up results by step.Name ('wrong-name') but results were stored "+
			"under the map key ('step-a'). Validate() should reject policies where "+
			"step.Name != map key. Error: %v", verifyErr)
	}
}

// ===========================================================================
// R3-188: The Rego result iteration (rego.go lines 149-165) processes deny
//         reasons from the result set. When it encounters a non-[]interface{}
//         value (line 151 type assertion), it returns ErrRegoInvalidData
//         immediately. When it encounters a non-string element in the deny
//         set (line 158 type assertion), it also returns ErrRegoInvalidData.
//
//         The problem: these type assertion errors return BEFORE processing
//         all expressions. If a malicious module causes a type assertion
//         error, it short-circuits the evaluation and prevents legitimate
//         deny reasons from OTHER modules from being collected.
//
//         More critically: when two modules share the same package but one
//         defines deny as a complete rule (deny = "not a set") while the
//         other defines deny as a partial set rule (deny[msg] { ... }),
//         OPA evaluates them together. The complete rule's non-set result
//         causes ErrRegoInvalidData, which MASKS any deny reasons from the
//         partial set rule. This is a policy bypass because legitimate
//         deny reasons are never returned.
//
//         In practice, the two modules MUST have DIFFERENT packages for
//         this to work (same package would cause a compile error). With
//         different packages, each generates its own deny path in the
//         query. If the first deny path evaluates to a non-set type,
//         the type assertion fails and the second deny path (which may
//         have real deny reasons) is never processed.
//
// Severity: HIGH
// Impact:  A malicious Rego module that causes a type error during deny
//          reason processing can mask legitimate deny reasons from other
//          modules, effectively bypassing those policies.
// ===========================================================================

func TestSecurity_R3_188_RegoTypeErrorMasksLegitDenyReasons(t *testing.T) {
	// Module 1: defines deny as a set rule that correctly denies.
	legitimateModule := RegoPolicy{
		Name: "legitimate.rego",
		Module: []byte(`package legitimate

deny[msg] {
  input.name == "bad-build"
  msg := "build failed security check"
}
`),
	}

	attestor := &r3WrappedAttestor{
		typeName: "build-type",
		inner: map[string]interface{}{
			"name": "bad-build",
			"type": "build-type",
		},
	}

	// First: verify the legitimate module correctly denies by itself.
	err := EvaluateRegoPolicy(attestor, []RegoPolicy{legitimateModule})
	if err == nil {
		t.Fatal("expected legitimate module to deny bad-build")
	}
	if !strings.Contains(err.Error(), "build failed security check") {
		t.Fatalf("expected specific deny reason, got: %v", err)
	}
	t.Logf("Legitimate module correctly denies: %v", err)

	// Module 2: uses the same package name to exploit OPA's rule merging,
	// adding a deny rule that returns a non-string (integer) value.
	// OPA allows set elements of any type, but our code expects strings.
	maliciousModule := RegoPolicy{
		Name: "malicious.rego",
		Module: []byte(`package legitimate

deny[val] {
  val := 42
}
`),
	}

	// Now evaluate with both modules. The malicious module adds a non-string
	// element (42) to the deny set. When processing deny reasons, the code
	// hits the integer and returns ErrRegoInvalidData before processing the
	// legitimate string deny reason.
	err = EvaluateRegoPolicy(attestor, []RegoPolicy{legitimateModule, maliciousModule})

	if err == nil {
		// Complete bypass: no error returned at all.
		t.Error("SECURITY BUG R3-188: Adding a malicious module with a non-string " +
			"deny element caused the entire evaluation to pass. The legitimate " +
			"deny reason was masked.")
		return
	}

	errStr := err.Error()

	// Check if we got the legitimate deny reason.
	if strings.Contains(errStr, "build failed security check") {
		t.Log("Legitimate deny reason was preserved despite malicious module.")
	} else if strings.Contains(errStr, "invalid data") || strings.Contains(errStr, "ErrRegoInvalidData") || strings.Contains(errStr, "expected") {
		// The type assertion error masked the legitimate deny reason.
		t.Error("SECURITY BUG R3-188: A malicious Rego module injecting a " +
			"non-string value into the deny set caused ErrRegoInvalidData, " +
			"which masked the legitimate deny reason ('build failed security " +
			"check'). The error returned is a type error, not the policy denial. " +
			"An attacker who can add a module to the same package can prevent " +
			"legitimate deny reasons from being reported. Error: " + errStr)
	} else {
		t.Logf("Got error but neither deny reason nor type error: %v", err)
	}
}

// ===========================================================================
// R3-189: The clockSkewTolerance check at line 375 uses:
//
//   time.Now().After(p.Expires.Time.Add(vo.clockSkewTolerance))
//
//         This means a NEGATIVE clockSkewTolerance SHORTENS the validity
//         window. More importantly, there is no validation that
//         clockSkewTolerance is non-negative. A caller who accidentally
//         passes a negative duration (e.g., from miscalculation) will
//         cause a policy to expire EARLIER than intended, creating a
//         denial-of-service where valid policies are rejected.
//
//         Additionally, the tolerance is applied symmetrically: it
//         extends the expiry time forward but does NOT prevent use of
//         a policy before its intended start time (there is no
//         "not-before" check at all).
//
// Severity: MEDIUM
// Impact:  1) Negative clockSkewTolerance silently causes premature
//             policy expiration (DoS).
//          2) No "not-before" validation means a policy with a future
//             Expires time can be used before the policy author intended
//             (if combined with a separate NotBefore field that doesn't
//             exist in the schema).
// ===========================================================================

func TestSecurity_R3_189_NegativeClockSkewTolerance(t *testing.T) {
	// Policy that expires 1 hour from now -- should be valid.
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			"build": {
				Name:          "build",
				Functionaries: []Functionary{},
			},
		},
	}

	src := &r3MockSource{
		byStep: map[string][]source.CollectionVerificationResult{},
	}

	// Negative tolerance: -2 hours. This shifts the effective expiry
	// to 1 hour - 2 hours = -1 hour, making the policy "expired."
	_, _, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithClockSkewTolerance(-2*time.Hour),
	)

	if err == nil {
		t.Fatal("expected some error from Verify")
	}

	if strings.Contains(err.Error(), "expired") {
		t.Error("SECURITY BUG R3-189: Negative clockSkewTolerance (-2h) caused " +
			"a policy with 1h remaining validity to be treated as expired. " +
			"A negative tolerance should be rejected by checkVerifyOpts, not " +
			"silently applied. This can cause denial-of-service where valid " +
			"policies are incorrectly rejected due to misconfigured tolerance values.")
	} else {
		t.Logf("Verify failed for a different reason: %v", err)
	}

	// Also verify there's no NotBefore check: a policy that "starts" in the
	// future can be used immediately because there's no NotBefore field.
	// This is a design limitation, not a bug, but worth documenting.
	futurePolicy := Policy{
		Expires: metav1.Time{Time: time.Now().Add(100 * 365 * 24 * time.Hour)},
		Steps: map[string]Step{
			"build": {Name: "build"},
		},
	}

	err = futurePolicy.Validate()
	if err != nil {
		t.Logf("Validate rejected future policy: %v", err)
	} else {
		t.Log("OBSERVATION: There is no NotBefore field in the Policy struct. " +
			"A policy can be created with an Expires 100 years in the future and " +
			"used immediately. This means there's no way to create a policy that " +
			"becomes valid at a specific future time.")
	}
}

// ===========================================================================
// Unused import guard
// ===========================================================================
var (
	_ = metav1.Time{}
	_ = big.NewInt
	_ = pkix.Name{}
	_ = x509.Certificate{}
)
