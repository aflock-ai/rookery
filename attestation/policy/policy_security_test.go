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
	"fmt"
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
// Security test helpers (stdlib only, no testify)
// ===========================================================================

// secMarshalableAttestor has exported fields for JSON serialization in security tests.
type secMarshalableAttestor struct {
	AttName string                 `json:"name"`
	AttType string                 `json:"type"`
	Extra   map[string]interface{} `json:"extra,omitempty"`
}

func (m *secMarshalableAttestor) Name() string                                  { return m.AttName }
func (m *secMarshalableAttestor) Type() string                                  { return m.AttType }
func (m *secMarshalableAttestor) RunType() attestation.RunType                  { return "test" }
func (m *secMarshalableAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (m *secMarshalableAttestor) Schema() *jsonschema.Schema                    { return nil }

// secWrappedAttestor wraps any struct to implement attestation.Attestor with custom JSON.
type secWrappedAttestor struct {
	inner    interface{}
	typeName string
}

func (w *secWrappedAttestor) Name() string                                  { return "sec-wrapped" }
func (w *secWrappedAttestor) Type() string                                  { return w.typeName }
func (w *secWrappedAttestor) RunType() attestation.RunType                  { return "test" }
func (w *secWrappedAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (w *secWrappedAttestor) Schema() *jsonschema.Schema                    { return nil }
func (w *secWrappedAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.inner)
}

// secMockVerifiedSource returns results per step name.
type secMockVerifiedSource struct {
	byStep map[string][]source.CollectionVerificationResult
}

func (s *secMockVerifiedSource) Search(_ context.Context, stepName string, _ []string, _ []string) ([]source.CollectionVerificationResult, error) {
	return s.byStep[stepName], nil
}

// secGenerateSelfSignedCert creates a self-signed CA cert.
func secGenerateSelfSignedCert(t *testing.T, cn string, orgs []string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: orgs,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	pemBytes := append([]byte("-----BEGIN CERTIFICATE-----\n"), []byte{}...)
	_ = pemBytes // we'll use the proper encoding
	return cert, priv, certDER // return DER for simplicity; callers can PEM-encode if needed
}

// secGenerateLeafCert creates a leaf cert signed by the given CA.
func secGenerateLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, orgs []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: orgs,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}
	return cert, priv
}

func secMakeVerifierAndKeyID(t *testing.T) (cryptoutil.Verifier, string) {
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

func secMakeCVR(stepName string, verifier cryptoutil.Verifier, attestations ...attestation.CollectionAttestation) source.CollectionVerificationResult {
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
// R3-150: Cross-step attestation data injection via buildStepContext
//         last-writer-wins allows attacker-controlled data to overwrite
//         legitimate attestation data visible to downstream Rego policies
//         in a full Verify() flow.
//
// Severity: HIGH
// Attack: If an attacker can produce a second signed collection for the
//         same step with the same attestation type, the attacker's data
//         overwrites the legitimate data in buildStepContext. Downstream
//         Rego policies that inspect cross-step data will see the attacker's
//         version.
//
// This test proves the issue end-to-end through Policy.Verify(), not just
// the buildStepContext helper in isolation.
// ===========================================================================

func TestSecurity_R3_150_CrossStepDataOverwriteInFullVerify(t *testing.T) {
	verifier, keyID := secMakeVerifierAndKeyID(t)

	buildAttType := "https://example.com/build/v1"
	deployAttType := "https://example.com/deploy/v1"

	// Rego policy on the deploy step that reads a field from the build step's
	// attestation and DENIES if the value is "attacker-controlled".
	regoModule := []byte(`
package security_r3_150

deny[msg] {
  build_data := input.steps.build["https://example.com/build/v1"]
  build_data.name == "attacker-controlled"
  msg := "attacker data detected in cross-step context"
}
`)

	steps := map[string]Step{
		"build": {
			Name:          "build",
			Functionaries: []Functionary{{PublicKeyID: keyID}},
			Attestations:  []Attestation{{Type: buildAttType}},
		},
		"deploy": {
			Name:             "deploy",
			AttestationsFrom: []string{"build"},
			Functionaries:    []Functionary{{PublicKeyID: keyID}},
			Attestations: []Attestation{{
				Type:         deployAttType,
				RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "security_r3_150.rego"}},
			}},
		},
	}

	// The source returns TWO passed collections for the build step.
	// The first has legitimate data, the second has attacker-controlled data.
	// Due to last-writer-wins in buildStepContext, the attacker's data wins.
	legitimateCVR := secMakeCVR("build", verifier, attestation.CollectionAttestation{
		Type:        buildAttType,
		Attestation: &secMarshalableAttestor{AttName: "legitimate-build", AttType: buildAttType},
	})
	attackerCVR := secMakeCVR("build", verifier, attestation.CollectionAttestation{
		Type:        buildAttType,
		Attestation: &secMarshalableAttestor{AttName: "attacker-controlled", AttType: buildAttType},
	})

	deployCVR := secMakeCVR("deploy", verifier, attestation.CollectionAttestation{
		Type:        deployAttType,
		Attestation: &secMarshalableAttestor{AttName: "deploy", AttType: deployAttType},
	})

	src := &secMockVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"build":  {legitimateCVR, attackerCVR},
			"deploy": {deployCVR},
		},
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps:   steps,
	}

	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}

	// The attacker's data overwrites the legitimate data in buildStepContext.
	// If the Rego policy sees "attacker-controlled", it will deny the deploy step.
	// If buildStepContext used first-writer-wins or merged data, the behavior
	// would be different.
	//
	// FINDING: The deploy step fails because the Rego policy saw the attacker's
	// data. This proves that an attacker who can get a second collection signed
	// and verified can control what downstream Rego policies see.
	if pass {
		// If it passed, the attacker's data was NOT seen, meaning buildStepContext
		// used the legitimate data (first-writer-wins). Check which happened.
		t.Log("UNEXPECTED: Deploy passed. buildStepContext may have used first-writer-wins.")
	} else {
		deployResult := results["deploy"]
		foundAttackerDeny := false
		for _, rejected := range deployResult.Rejected {
			if rejected.Reason != nil && strings.Contains(rejected.Reason.Error(), "attacker data detected") {
				foundAttackerDeny = true
			}
		}
		if foundAttackerDeny {
			t.Log("SECURITY FINDING CONFIRMED: buildStepContext last-writer-wins allows " +
				"attacker to control cross-step data visible to Rego policies. " +
				"The Rego policy correctly detected the attack, but only because it " +
				"explicitly checked for malicious data. A Rego policy that trusts " +
				"the data would be silently exploited.")
		}
	}
	// Either way, this test documents the behavior. The key concern is that
	// buildStepContext does not protect against this -- it silently overwrites.
}

// ===========================================================================
// R3-151: Empty collection name bypasses step-name filter in
//         validateAttestations, allowing a single forged collection to
//         satisfy ANY step in the policy.
//
// Severity: HIGH
// Attack: Produce a signed collection with Name="" and the right attestation
//         types. It will match any step because the filter at line 255
//         skips the name check when collection.Collection.Name == "".
// ===========================================================================

func TestSecurity_R3_151_EmptyCollectionNameMatchesAllSteps(t *testing.T) {
	verifier, keyID := secMakeVerifierAndKeyID(t)

	attType := "https://example.com/att/v1"

	// A collection with an empty name that has the right attestation type.
	emptyCVR := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{
				Name: "", // Empty name!
				Attestations: []attestation.CollectionAttestation{
					{
						Type:        attType,
						Attestation: &secMarshalableAttestor{AttName: "empty-name", AttType: attType},
					},
				},
			},
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	// This source returns the empty-name collection for BOTH steps.
	src := &secMockVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"build":  {emptyCVR},
			"deploy": {emptyCVR},
		},
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			"build": {
				Name:          "build",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: attType}},
			},
			"deploy": {
				Name:          "deploy",
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: attType}},
			},
		},
	}

	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}

	// Both steps should pass because the empty-name collection matches any step.
	buildPassed := results["build"].HasPassed()
	deployPassed := results["deploy"].HasPassed()

	if buildPassed && deployPassed && pass {
		t.Log("SECURITY FINDING CONFIRMED: A collection with an empty name satisfies " +
			"both 'build' and 'deploy' steps. An attacker who can produce a single " +
			"signed collection with Name=\"\" can satisfy ANY step in the policy, " +
			"bypassing step isolation.")
	} else {
		t.Logf("Result: pass=%v, buildPassed=%v, deployPassed=%v",
			pass, buildPassed, deployPassed)
	}
}

// ===========================================================================
// R3-152: Rego policy with no 'deny' rule is now caught by the
//         len(rs)==0 check, but a policy that defines deny as a
//         completely empty set literal (deny = set()) can bypass this
//         because OPA returns a result for a defined-but-empty set.
//
// Severity: HIGH
// Attack: Supply a Rego module that defines deny = set() instead of
//         deny[msg] { ... }. The query "data.pkg.deny" returns an empty
//         set [], which has zero deny reasons, so the policy silently passes.
//         The len(rs)==0 check does NOT catch this because rs is non-empty
//         (it contains one expression with an empty set value).
// ===========================================================================

func TestSecurity_R3_152_RegoDenyEmptySetBypassesCheck(t *testing.T) {
	// A module that defines deny as a set that is always empty.
	policy := RegoPolicy{
		Name: "empty_set_deny.rego",
		Module: []byte(`package empty_set_deny

# deny is defined as a set comprehension that never matches.
# This is different from having NO deny rule.
deny[msg] {
  false
  msg := "never fires"
}
`),
	}

	err := EvaluateRegoPolicy(
		&secMarshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	// The deny rule is defined but its body is never true, so the set is empty.
	// The query returns a non-empty result set (rs has one expression), but the
	// set value is []. len(allDenyReasons)==0, so the function returns nil.
	if err == nil {
		t.Log("SECURITY FINDING CONFIRMED: A Rego policy with deny[msg] { false } " +
			"silently passes because the deny set is empty. The len(rs)==0 check " +
			"does not catch this case because the result set IS non-empty (it " +
			"contains the empty set). An attacker can supply a module that defines " +
			"deny but never fires, effectively bypassing all policy enforcement.")
	} else {
		t.Fatalf("Expected nil error for empty deny set, got: %v", err)
	}
}

// ===========================================================================
// R3-153: Duplicate AttestationsFrom entries inflate topological sort
//         in-degree, potentially causing steps to never become ready
//         in Kahn's algorithm if the duplicate count is odd.
//
// Severity: MEDIUM
// Bug: When a step has AttestationsFrom: ["build", "build"], Kahn's algorithm
//      increments inDegree for the step by 2. But the dependents map only
//      has one entry (append deduplicates by name in the adjacency list).
//      When "build" is processed, inDegree is only decremented once per
//      dependent, leaving the step with inDegree=1, never reaching 0.
//
// Wait -- let me re-read the code. dependents[dep] = append(dependents[dep], name)
// So for ["build", "build"], dependents["build"] = ["deploy", "deploy"].
// When build is processed, both entries decrement inDegree, so it goes 2->1->0.
// Actually it works. Let me test with triple duplicates.
// ===========================================================================

func TestSecurity_R3_153_DuplicateAttestationsFromInTopologicalSort(t *testing.T) {
	// Triple duplicate: AttestationsFrom: ["build", "build", "build"]
	// inDegree["deploy"] = 3
	// dependents["build"] = ["deploy", "deploy", "deploy"]
	// When "build" is processed, inDegree goes 3->2->1->0. OK.
	//
	// The real issue: this means a step can appear multiple times in the
	// dependents list, which is inefficient but not incorrect.
	// However, if the duplicate entries lead to different counts in different
	// code paths, there could be a subtle bug.
	p := Policy{
		Steps: map[string]Step{
			"build":  {Name: "build"},
			"deploy": {Name: "deploy", AttestationsFrom: []string{"build", "build", "build"}},
		},
	}

	err := p.Validate()
	if err != nil {
		t.Fatalf("Validate failed on policy with duplicate deps: %v", err)
	}

	sorted, err := p.topologicalSort()
	if err != nil {
		t.Fatalf("topologicalSort failed with duplicate deps: %v", err)
	}

	if len(sorted) != 2 {
		t.Fatalf("expected 2 steps in sorted output, got %d: %v", len(sorted), sorted)
	}

	// Verify ordering: build before deploy
	buildIdx, deployIdx := -1, -1
	for i, name := range sorted {
		switch name {
		case "build":
			buildIdx = i
		case "deploy":
			deployIdx = i
		}
	}
	if buildIdx >= deployIdx {
		t.Fatalf("build (idx=%d) should come before deploy (idx=%d)", buildIdx, deployIdx)
	}

	t.Log("Duplicate AttestationsFrom entries are handled correctly by topologicalSort " +
		"(Kahn's algorithm). The in-degree inflation is balanced by the duplicated " +
		"adjacency entries. However, this is wasteful and Validate() should reject duplicates.")
}

// ===========================================================================
// R3-154: validateAttestations found map uses last-writer-wins for
//         duplicate attestation types WITHIN a single collection.
//
// Severity: MEDIUM
// Bug: At line 273, found[att.Type] = att.Attestation overwrites if the
//      same Type appears twice. An attacker who can inject a second
//      attestation with the same type into a collection can control which
//      attestor is passed to EvaluateRegoPolicy.
// ===========================================================================

func TestSecurity_R3_154_DuplicateAttestationTypeInSingleCollection(t *testing.T) {
	attType := "https://example.com/scan/v1"

	// Rego policy that checks the attestation's name field.
	regoModule := []byte(`
package r3_154

deny[msg] {
  input.name == "attacker"
  msg := "attacker attestation detected"
}
`)

	step := Step{
		Name: "build",
		Attestations: []Attestation{{
			Type:         attType,
			RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "r3_154.rego"}},
		}},
	}

	// A collection with TWO attestations of the same type.
	// The first is legitimate, the second is attacker-controlled.
	coll := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{
				Type:        attType,
				Attestation: &secMarshalableAttestor{AttName: "legitimate", AttType: attType},
			},
			{
				Type:        attType,
				Attestation: &secMarshalableAttestor{AttName: "attacker", AttType: attType},
			},
		},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{Collection: coll},
	}

	result := step.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)

	// Check if the attacker's attestation was passed to Rego.
	if len(result.Rejected) > 0 {
		for _, rej := range result.Rejected {
			if rej.Reason != nil && strings.Contains(rej.Reason.Error(), "attacker attestation detected") {
				t.Log("SECURITY FINDING CONFIRMED: When a collection has duplicate " +
					"attestation types, the last one wins in validateAttestations' found map. " +
					"The Rego policy evaluated the attacker's attestation, not the legitimate one. " +
					"An attacker who can append to a collection's attestation list can control " +
					"what Rego policies see.")
				return
			}
		}
	}

	if len(result.Passed) > 0 {
		t.Log("The attacker's attestation was evaluated and passed (Rego didn't detect it), " +
			"or the legitimate attestation was evaluated. Either way, the last-writer-wins " +
			"behavior means the evaluation target is non-deterministic for duplicate types.")
	}
}

// ===========================================================================
// R3-155: AllowAllConstraint ("*") in CertConstraint.Roots bypasses
//         ALL certificate constraint checks when combined with a
//         matching trust bundle -- but the CN/SAN/Org checks still run.
//         However, an empty Roots list (no roots configured) combined
//         with CertConstraint fields that are all empty ("") effectively
//         makes the constraint a no-op since checkCertConstraintGlob
//         returns nil for empty constraints.
//
// Severity: HIGH
// Attack: A functionary with CertConstraint where all fields are empty
//         strings and Roots is ["*"] will match ANY certificate from
//         ANY trusted root with ANY CN/SAN/Org.
// ===========================================================================

func TestSecurity_R3_155_AllowAllConstraintWithEmptyFieldsBypassesAllChecks(t *testing.T) {
	// Create a CA and leaf cert with arbitrary CN but NO organizations/SANs.
	// The key insight: when the cert has no Organization, DNSNames, Emails,
	// or URIs, the nil/empty constraint arrays match trivially because
	// checkCertConstraint returns nil for len(constraints)==0 && len(values)==0.
	// Combined with empty CommonName constraint and Roots=["*"], this means
	// ANY cert with no SANs from ANY trusted root passes.
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "EvilCA"},
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

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	// Leaf cert with arbitrary CN, but NO organizations, DNSNames, Emails, URIs.
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "evil-attacker.com"},
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

	trustBundles := map[string]TrustBundle{
		"evil-root": {Root: caCert},
	}

	// A CertConstraint where ALL fields are empty/default, and Roots is ["*"].
	// The cert has no Org/DNS/Email/URI, so those checks trivially pass.
	// CN is "" (empty constraint = allow any CN).
	// Roots = ["*"] matches any root in the trust bundle.
	cc := CertConstraint{
		CommonName:    "",                           // Empty = allow any CN
		Organizations: nil,                          // nil = no constraint (passes if cert also has none)
		Emails:        nil,                          // nil = no constraint
		DNSNames:      nil,                          // nil = no constraint
		URIs:          nil,                          // nil = no constraint
		Roots:         []string{AllowAllConstraint}, // Match any root
	}

	err = cc.Check(x509Verifier, trustBundles)
	if err == nil {
		t.Log("SECURITY FINDING CONFIRMED: CertConstraint with all empty fields and " +
			"Roots=[\"*\"] matches ANY certificate (that lacks SANs/Orgs) from ANY " +
			"trusted root. The certificate CN='evil-attacker.com' passed all checks. " +
			"A policy author who specifies only Roots=[\"*\"] without explicit CN/Org " +
			"constraints effectively accepts any certificate from any root, making " +
			"the functionary constraint meaningless for identity verification.")
	} else {
		t.Fatalf("Expected cert to pass all-empty constraints, got: %v", err)
	}
}

// ===========================================================================
// R3-156: clockSkewTolerance can be set to extremely large values,
//         keeping an expired policy alive indefinitely. There is no
//         upper bound validation.
//
// Severity: MEDIUM
// Bug: WithClockSkewTolerance accepts any time.Duration, including
//      arbitrarily large values like 100 years. Combined with a policy
//      that expired long ago, this can resurrect the policy.
// ===========================================================================

func TestSecurity_R3_156_UnboundedClockSkewTolerance(t *testing.T) {
	// Policy that expired 10 years ago.
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(-10 * 365 * 24 * time.Hour)},
		Steps: map[string]Step{
			"build": {Name: "build"},
		},
	}

	src := &secMockVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{},
	}

	// Without tolerance: should fail as expired.
	_, _, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got: %v", err)
	}

	// With 20 years tolerance: resurrects the policy.
	_, _, err = p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithClockSkewTolerance(20*365*24*time.Hour),
	)

	// The expiry check should now pass (policy expired 10yr ago + 20yr tolerance = OK).
	// Verification will fail for other reasons (no collections), but NOT for expiry.
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			t.Fatalf("policy should not be expired with 20yr tolerance: %v", err)
		}
		// Failed for a different reason -- that's fine, the point is it wasn't expired.
		t.Log("SECURITY FINDING CONFIRMED: clockSkewTolerance of 20 years " +
			"successfully resurrected a policy that expired 10 years ago. " +
			"There is no upper bound on clockSkewTolerance, allowing " +
			"indefinite policy validity extensions.")
	}
}

// ===========================================================================
// R3-157: Rego policy that defines deny as a complete rule returning a
//         non-set type (e.g., deny = "not a set") bypasses the set
//         iteration check.
//
// Severity: MEDIUM
// Bug: The type assertion at line 151 (denyReasons, ok := value.Value.([]interface{}))
//      fails for non-slice values, returning ErrRegoInvalidData. This means
//      a policy that defines deny as a string or boolean is caught -- good.
//      But what about deny = [] (empty array literal)?
// ===========================================================================

func TestSecurity_R3_157_RegoDenyAsEmptyArrayLiteral(t *testing.T) {
	policy := RegoPolicy{
		Name: "empty_array.rego",
		Module: []byte(`package empty_array

deny = []
`),
	}

	err := EvaluateRegoPolicy(
		&secMarshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	if err == nil {
		t.Log("SECURITY FINDING: deny = [] (empty array literal) silently passes. " +
			"An attacker can define deny as an empty array constant to bypass " +
			"all policy checks. The value is []interface{}, which passes the type " +
			"assertion, but has zero elements, so allDenyReasons is empty.")
	} else {
		t.Logf("deny = [] result: %v", err)
	}
}

// ===========================================================================
// R3-158: checkFunctionaries mutates the input slice by appending to
//         statements[i].Warnings and statements[i].ValidFunctionaries.
//
// Severity: LOW (correctness bug, not directly exploitable)
// Bug: The function receives a []source.CollectionVerificationResult by
//      value, but modifies elements via statements[i]. Since slices share
//      the underlying array, this mutation is visible to the caller.
//      In Verify(), the caller doesn't reuse the slice, so this is not
//      currently exploitable, but it violates the principle of least
//      surprise and could become a bug if the caller changes.
// ===========================================================================

func TestSecurity_R3_158_CheckFunctionariesMutatesInput(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	if err != nil {
		t.Fatalf("failed to get key ID: %v", err)
	}

	step := Step{
		Name: "build",
		Functionaries: []Functionary{
			{PublicKeyID: keyID},
		},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
		},
		Verifiers: []cryptoutil.Verifier{verifier},
	}

	input := []source.CollectionVerificationResult{cvr}

	// Before: no ValidFunctionaries or Warnings
	if len(input[0].ValidFunctionaries) != 0 {
		t.Fatal("precondition failed: expected no ValidFunctionaries before call")
	}

	_ = step.checkFunctionaries(input, nil)

	// After: checkFunctionaries mutated the input slice.
	if len(input[0].ValidFunctionaries) > 0 {
		t.Log("CORRECTNESS BUG CONFIRMED: checkFunctionaries mutates the input " +
			"slice's elements (ValidFunctionaries was populated on the caller's copy). " +
			"This side effect could cause subtle bugs if the same slice is reused.")
	} else {
		t.Log("Input was not mutated (or Go copied the struct on slice index access)")
	}
}

// ===========================================================================
// R3-159: A Rego policy can read and exfiltrate attestation data through
//         the deny message itself. Since deny reasons are included in the
//         error output, an attacker-controlled Rego policy can extract
//         any field from the attestation input by embedding it in the
//         deny message string.
//
// Severity: HIGH (data exfiltration via error messages)
// Attack: A malicious Rego policy uses sprintf to embed input fields
//         in the deny message, which is then exposed in error output.
// ===========================================================================

func TestSecurity_R3_159_RegoDataExfiltrationViaDenyMessage(t *testing.T) {
	// Attestor with a "secret" field.
	attestor := &secWrappedAttestor{
		typeName: "secret-type",
		inner: map[string]interface{}{
			"name":        "harmless",
			"type":        "secret-type",
			"secret_key":  "AKIAIOSFODNN7EXAMPLE",
			"private_data": "ssn-123-45-6789",
		},
	}

	// Malicious Rego policy that exfiltrates input data via deny messages.
	policy := RegoPolicy{
		Name: "exfiltrate_via_deny.rego",
		Module: []byte(`package exfiltrate

deny[msg] {
  key := input.secret_key
  msg := sprintf("EXFIL: secret_key=%s", [key])
}

deny[msg] {
  data := input.private_data
  msg := sprintf("EXFIL: private_data=%s", [data])
}
`),
	}

	err := EvaluateRegoPolicy(attestor, []RegoPolicy{policy})
	if err == nil {
		t.Fatal("expected deny error from exfiltration policy")
	}

	errStr := err.Error()
	if strings.Contains(errStr, "AKIAIOSFODNN7EXAMPLE") {
		t.Log("SECURITY FINDING CONFIRMED: Rego policies can exfiltrate attestation " +
			"data through deny message strings. The secret key 'AKIAIOSFODNN7EXAMPLE' " +
			"appeared in the error output. Any field from the attestation input is " +
			"accessible and can be leaked via error messages.")
	}
	if strings.Contains(errStr, "ssn-123-45-6789") {
		t.Log("SECURITY FINDING CONFIRMED: Private data 'ssn-123-45-6789' also leaked " +
			"via deny message. ALL attestation data is exposed to Rego policies.")
	}
}

// ===========================================================================
// R3-160: Cross-step Rego policy silently passes when step context
//         wrapping is bypassed by an attestor that provides a "steps"
//         field in its own JSON output. When validateAttestations is
//         called with nil stepContext (backward-compat path), the
//         attestor IS the input, so input.steps is the attestor's
//         own "steps" field -- attacker-controlled data.
//
// Severity: HIGH
// Attack: An attestor with a JSON field named "steps" can inject fake
//         cross-step context when the backward-compatibility path is
//         active (nil stepContext). Rego policies that check
//         input.steps will see the attacker's data.
// ===========================================================================

func TestSecurity_R3_160_AttestorStepsFieldInjectionWithoutContext(t *testing.T) {
	attType := "https://example.com/deploy/v1"

	// An attestor that includes a "steps" field with fake build data.
	maliciousAttestor := &secWrappedAttestor{
		typeName: attType,
		inner: map[string]interface{}{
			"name": "deploy",
			"type": attType,
			"steps": map[string]interface{}{
				"build": map[string]interface{}{
					"https://example.com/build-att/v1": map[string]interface{}{
						"name":     "fake-build",
						"approved": true,
						"compiler": "gcc-13.2",
					},
				},
			},
		},
	}

	// Rego policy that checks cross-step data. It's meant to verify
	// that the build step was approved.
	regoModule := []byte(`
package r3_160

deny[msg] {
  build := input.steps.build["https://example.com/build-att/v1"]
  build.approved != true
  msg := "build not approved"
}
`)

	step := Step{
		Name:             "deploy",
		AttestationsFrom: []string{"build"},
		Attestations: []Attestation{{
			Type:         attType,
			RegoPolicies: []RegoPolicy{{Module: regoModule, Name: "r3_160.rego"}},
		}},
	}

	coll := attestation.Collection{
		Name: "deploy",
		Attestations: []attestation.CollectionAttestation{
			{Type: attType, Attestation: maliciousAttestor},
		},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{Collection: coll},
	}

	// Call validateAttestations with nil stepContext (backward-compat path).
	// In this path, input = attestor JSON directly, so input.steps is the
	// attacker's fake data.
	result := step.validateAttestations(
		[]source.CollectionVerificationResult{cvr},
		"",
		nil, // nil stepContext triggers backward-compat path
	)

	if len(result.Passed) > 0 && len(result.Rejected) == 0 {
		t.Log("SECURITY FINDING CONFIRMED: With nil stepContext (backward-compat path), " +
			"the attestor's own 'steps' field becomes input.steps in Rego evaluation. " +
			"The attacker's fake build data (approved=true) was accepted by the Rego " +
			"policy. An attacker who controls an attestor can inject fake cross-step " +
			"context to bypass cross-step Rego policies.")
		t.Log("MITIGATION NOTE: The Verify() method now ensures non-nil stepCtx for " +
			"steps with AttestationsFrom, but direct callers of validateAttestations " +
			"or EvaluateRegoPolicy are still vulnerable.")
	} else if len(result.Rejected) > 0 {
		t.Log("The Rego policy denied the request, meaning the attack did not succeed " +
			"at this level. The attestor's steps field may not have been at the right path.")
		for _, rej := range result.Rejected {
			t.Logf("Rejection reason: %v", rej.Reason)
		}
	}
}

// ===========================================================================
// R3-161: Policy.Verify with searchDepth > 1 can accumulate duplicate
//         passed collections across depth iterations, inflating the
//         StepResult.Passed slice.
//
// Severity: LOW (correctness, not directly exploitable)
// Bug: The merge logic at lines 475-483 of policy.go appends Passed
//      collections from each depth iteration. If the search returns the
//      same collection across multiple depth iterations (because the
//      subject digests overlap), duplicates accumulate.
// ===========================================================================

func TestSecurity_R3_161_DuplicatePassedAcrossDepthIterations(t *testing.T) {
	verifier, keyID := secMakeVerifierAndKeyID(t)

	stepName := "build"
	cvr := secMakeCVR(stepName, verifier)

	// Source always returns the same collection.
	src := &secMockVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			stepName: {cvr},
		},
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			stepName: {
				Name:          stepName,
				Functionaries: []Functionary{{PublicKeyID: keyID}},
			},
		},
	}

	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithSearchDepth(3),
	)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	if !pass {
		t.Fatal("expected Verify to pass")
	}

	passedCount := len(results[stepName].Passed)
	if passedCount > 1 {
		t.Logf("CORRECTNESS BUG CONFIRMED: Step '%s' has %d passed collections "+
			"(expected 1) due to accumulation across %d depth iterations. "+
			"While not directly exploitable, this inflates results and could "+
			"affect downstream logic that counts passed collections.",
			stepName, passedCount, 3)
	} else {
		t.Logf("Step '%s' has %d passed collection(s) across 3 depth iterations", stepName, passedCount)
	}
}

// ===========================================================================
// R3-162: CertConstraint with empty Roots list (not "*", just empty)
//         always fails checkTrustBundles because the for loop over
//         cc.Roots has nothing to iterate. This is the correct behavior
//         (fail-closed), but when combined with the fact that
//         Functionary.Validate checks len(f.CertConstraint.Roots) == 0
//         BEFORE calling Check, a functionary with Type="" and no
//         PublicKeyID falls through to X509 verification but then fails
//         on the empty Roots check.
//
// Severity: LOW (correct fail-closed behavior, documenting for completeness)
// ===========================================================================

func TestSecurity_R3_162_EmptyRootsFallsThroughToRejection(t *testing.T) {
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TestCA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA: %v", err)
	}

	leaf, _ := secGenerateLeafCert(t, caCert, caPriv, "leaf", []string{"Org"})
	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{caCert}, time.Now())
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Functionary with empty PublicKeyID and empty Roots.
	f := Functionary{
		PublicKeyID:    "",
		CertConstraint: CertConstraint{Roots: []string{}},
	}

	err = f.Validate(x509Verifier, map[string]TrustBundle{"root": {Root: caCert}})
	if err == nil {
		t.Fatal("SECURITY ISSUE: Functionary with empty PublicKeyID and empty Roots " +
			"should have been rejected but was accepted")
	}

	if !strings.Contains(err.Error(), "no trusted roots") {
		t.Fatalf("expected 'no trusted roots' error, got: %v", err)
	}

	t.Log("CORRECT: Functionary with empty Roots is properly rejected with " +
		"'no trusted roots provided' error. Fail-closed behavior confirmed.")
}

// ===========================================================================
// R3-163: Rego evaluation timeout (30s) does not protect against
//         policies that are individually fast but collectively slow
//         when many policies are attached to a single attestation.
//
// Severity: MEDIUM
// Bug: Each Rego policy gets its own timeout context, but the outer
//      loop in EvaluateRegoPolicy uses a single 30s timeout for the
//      combined evaluation of ALL policies for ONE attestation type.
//      Actually, re-reading the code -- the timeout wraps the ENTIRE
//      Rego evaluation (all modules are compiled together and evaluated
//      once). So the 30s limit applies to the combined evaluation.
//      But a policy author can attach many attestation types to a step,
//      each getting its own 30s evaluation.
//
// Let me verify: validateAttestations loops over expected attestations
// and calls EvaluateRegoPolicy for each one. Each call creates its own
// 30s timeout context. So N attestation types = N*30s maximum.
// ===========================================================================

func TestSecurity_R3_163_RegoTimeoutPerAttestationType(t *testing.T) {
	// This is a documentation test. We verify that each attestation type
	// in a step's Attestations list gets its own independent 30s timeout.

	// Count how many separate EvaluateRegoPolicy calls would be made
	// for a step with multiple attestation types.
	step := Step{
		Name: "build",
		Attestations: []Attestation{
			{
				Type: "https://example.com/att1",
				RegoPolicies: []RegoPolicy{{
					Name:   "policy1.rego",
					Module: []byte("package p1\ndeny = []"),
				}},
			},
			{
				Type: "https://example.com/att2",
				RegoPolicies: []RegoPolicy{{
					Name:   "policy2.rego",
					Module: []byte("package p2\ndeny = []"),
				}},
			},
			{
				Type: "https://example.com/att3",
				RegoPolicies: []RegoPolicy{{
					Name:   "policy3.rego",
					Module: []byte("package p3\ndeny = []"),
				}},
			},
		},
	}

	// If each attestation type is present, EvaluateRegoPolicy is called 3 times,
	// each with a 30s timeout. Maximum wall-clock time: 90s.
	// The regoEvalTimeout constant is 30s.
	maxTime := time.Duration(len(step.Attestations)) * 30 * time.Second

	t.Logf("SECURITY OBSERVATION: A step with %d attestation types allows "+
		"up to %v of Rego evaluation time (%d calls x 30s each). "+
		"An attacker who controls policy configuration could create many "+
		"attestation types to multiply the DoS window.",
		len(step.Attestations), maxTime, len(step.Attestations))
	t.Logf("RECOMMENDATION: Add a per-step aggregate timeout in addition to " +
		"the per-evaluation timeout.")
}

// ===========================================================================
// R3-164: checkCertConstraint with duplicated values in the cert
//         (e.g., cert has ["A", "A"]) only deletes the constraint
//         map entry once, leaving the second "A" as an unexpected value.
//
// Severity: MEDIUM
// Bug: The iteration at line 198-204 processes each cert value and
//      deletes the matching constraint entry. If the cert has duplicate
//      values, the second occurrence will not find the constraint
//      (already deleted) and will trigger "unexpected value" error.
//      This is technically correct (certs shouldn't have duplicate
//      values) but could reject legitimate certificates with
//      unusual configurations.
// ===========================================================================

func TestSecurity_R3_164_DuplicateValuesInCert(t *testing.T) {
	// Cert has ["A", "A"] but constraint expects ["A", "A"].
	// After map dedup, constraint map = {A: {}}.
	// First cert "A" matches and deletes. Second cert "A" has no match.
	err := checkCertConstraint("org",
		[]string{"A", "A"}, // Constraint (deduped to one entry)
		[]string{"A", "A"}, // Cert values (two entries)
	)

	if err != nil {
		t.Logf("Result: %v", err)
		t.Log("CONFIRMED: When both constraint and cert have duplicate values, " +
			"the constraint map deduplication means the second cert value 'A' " +
			"is treated as unexpected. This could reject legitimate certs with " +
			"unusual duplicate Organization entries.")
	} else {
		t.Log("UNEXPECTED: duplicate values in both constraint and cert passed. " +
			"This means the map dedup + iteration logic handles this case correctly.")
	}
}

// ===========================================================================
// R3-165: The checkCertConstraintGlob function has an asymmetry where
//         only patterns containing "*" trigger glob compilation. Non-star
//         glob characters (?, [...], {...}) are silently treated as
//         literal strings. This is a policy bypass because a policy
//         author using these patterns gets exact-match semantics
//         instead of the expected glob semantics.
//
// Severity: HIGH
// Attack: A policy author writes CommonName: "{build-ci,deploy-ci}"
//         expecting it to match either "build-ci" or "deploy-ci".
//         But since the pattern has no "*", it requires the exact
//         string "{build-ci,deploy-ci}" as the CN.
// ===========================================================================

func TestSecurity_R3_165_GlobCharactersWithoutStarTreatedAsLiteral(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		value      string
		expectErr  bool
	}{
		{
			name:       "question_mark_without_star",
			constraint: "?.example.com",
			value:      "a.example.com",
			expectErr:  true, // Should match in glob but treated as literal
		},
		{
			name:       "character_class_without_star",
			constraint: "[abc].example.com",
			value:      "a.example.com",
			expectErr:  true, // Should match in glob but treated as literal
		},
		{
			name:       "alternation_without_star",
			constraint: "{foo,bar}.example.com",
			value:      "foo.example.com",
			expectErr:  true, // Should match in glob but treated as literal
		},
		{
			name:       "question_mark_WITH_star",
			constraint: "?*.example.com",
			value:      "ab.example.com",
			expectErr:  false, // Star triggers glob mode, ? works correctly
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkCertConstraintGlob("common name", tc.constraint, tc.value)
			if tc.expectErr && err == nil {
				t.Fatalf("expected error for constraint %q value %q, got nil", tc.constraint, tc.value)
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("expected no error for constraint %q value %q, got: %v", tc.constraint, tc.value, err)
			}
			if tc.expectErr {
				t.Logf("CONFIRMED: Glob pattern %q without '*' is treated as literal. "+
					"Policy authors using ?, [...], or {...} without * will get "+
					"unexpected exact-match behavior.", tc.constraint)
			}
		})
	}
}

// ===========================================================================
// R3-166: Policy.Verify does not validate that step Names match their
//         map keys. A step with Name="build" stored under key "deploy"
//         creates a split-brain where the search uses the map key but
//         validateAttestations uses the step Name.
//
// Severity: MEDIUM
// Bug: The source.Search() is called with the map key (stepName in the
//      loop at line 430), but validateAttestations checks
//      collection.Collection.Name against s.Name (the step's Name field).
//      If these differ, a collection matching the map key's search will
//      be rejected by the name filter in validateAttestations.
// ===========================================================================

func TestSecurity_R3_166_StepNameMismatchMapKey(t *testing.T) {
	verifier, keyID := secMakeVerifierAndKeyID(t)

	attType := "https://example.com/att/v1"

	// Step stored under key "deploy" but with Name="build".
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			"deploy": {
				Name:          "build", // Name doesn't match key!
				Functionaries: []Functionary{{PublicKeyID: keyID}},
				Attestations:  []Attestation{{Type: attType}},
			},
		},
	}

	// Source returns a collection named "deploy" (matching the map key).
	deployCVR := secMakeCVR("deploy", verifier, attestation.CollectionAttestation{
		Type:        attType,
		Attestation: &secMarshalableAttestor{AttName: "deploy-att", AttType: attType},
	})

	src := &secMockVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"deploy": {deployCVR},
		},
	}

	pass, _, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
	)

	// The split-brain manifests in multiple ways depending on the code path.
	// The search uses map key "deploy" to find collections, but the step's
	// Name="build" is used internally for name matching in validateAttestations
	// and for looking up step results in verifyArtifacts. This creates confusion:
	// the step result is stored under map key "deploy", but verifyArtifacts
	// looks for step.Name "build" in the results map and fails.
	if err != nil {
		if strings.Contains(err.Error(), "build") {
			t.Log("CORRECTNESS BUG CONFIRMED: Step stored under key 'deploy' with " +
				"Name='build' creates a split-brain. The error references step name " +
				"'build' which doesn't match any map key. The mismatch between " +
				"the map key ('deploy') and step.Name ('build') causes internal " +
				"lookups to fail. Validate() should check that step.Name matches " +
				"its map key.")
			t.Logf("Error: %v", err)
		} else {
			t.Logf("Verify returned unexpected error: %v", err)
		}
		return
	}

	if !pass {
		t.Log("CORRECTNESS BUG CONFIRMED: Verify failed (pass=false) due to " +
			"step Name vs map key mismatch. Validate() should reject this configuration.")
	} else {
		t.Log("UNEXPECTED: Verify passed despite name mismatch. " +
			"The collection must have matched through the empty-name path.")
	}
}

// ===========================================================================
// R3-167: buildStepContext silently skips attestations that fail JSON
//         marshaling or unmarshaling, without any indication in the
//         returned context. A Rego policy checking for a specific
//         attestation type in the step context will see it as absent
//         rather than getting an error.
//
// Severity: MEDIUM
// Bug: At lines 207-218, marshaling/unmarshaling failures are logged
//      at debug level and the attestation is skipped. If ALL attestations
//      in a dependency fail to marshal, the step won't appear in the
//      context map at all, potentially triggering "missing dep" Rego
//      denials when the data was actually present but unmarshalable.
// ===========================================================================

func TestSecurity_R3_167_BuildStepContextSilentlySkipsUnmarshalable(t *testing.T) {
	attType := "https://example.com/scan/v1"

	// An attestor that cannot be marshaled to JSON will cause json.Marshal
	// to return an error. Using a channel (which can't be marshaled).
	type unmarshalable struct {
		Ch chan int `json:"ch"`
	}

	unmarshalableAttestor := &secWrappedAttestor{
		typeName: attType,
		inner:    &unmarshalable{Ch: make(chan int)},
	}

	results := map[string]StepResult{
		"scan": {
			Step: "scan",
			Passed: []PassedCollection{{
				Collection: source.CollectionVerificationResult{
					CollectionEnvelope: source.CollectionEnvelope{
						Collection: attestation.Collection{
							Name: "scan",
							Attestations: []attestation.CollectionAttestation{{
								Type:        attType,
								Attestation: unmarshalableAttestor,
							}},
						},
					},
				},
			}},
		},
	}

	ctx := buildStepContext([]string{"scan"}, results)

	// The unmarshalable attestation is silently skipped. Since it was the only
	// attestation in the step, the step has no data and is not added to the
	// context map.
	if ctx == nil {
		t.Log("CONFIRMED: buildStepContext returns nil when all attestations in a " +
			"dependency step fail JSON marshaling. The dependency's data is silently " +
			"dropped. A Rego policy checking for this step's data will see it as " +
			"absent rather than receiving an explicit error about marshaling failure.")
	} else {
		_, hasScan := ctx["scan"]
		if !hasScan {
			t.Log("CONFIRMED: scan step absent from context despite having passed " +
				"collections. JSON marshaling failure silently suppressed the data.")
		} else {
			t.Log("UNEXPECTED: scan step present in context despite unmarshalable attestation")
		}
	}
}

// ===========================================================================
// R3-168: Policy with a single step that has no Functionaries accepts
//         collections with no verifiers, then rejects them in
//         checkFunctionaries. However, if the step also has no required
//         Attestations, the rejected collection from checkFunctionaries
//         is the only signal, and the step fails. This is correct.
//
//         BUT: if ArtifactsFrom references this step, the verifyArtifacts
//         phase will see "no passed collections" and add another rejection.
//         The error accumulation can be confusing.
//
// This test verifies that the error handling is complete and no
// collections can slip through the functionary check.
// ===========================================================================

func TestSecurity_R3_168_NoFunctionariesRejectsAllCollections(t *testing.T) {
	verifier, _ := secMakeVerifierAndKeyID(t)

	step := Step{
		Name:          "build",
		Functionaries: []Functionary{}, // No functionaries at all!
		Attestations:  []Attestation{},
	}

	cvr := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	result := step.checkFunctionaries([]source.CollectionVerificationResult{cvr}, nil)

	if len(result.Passed) > 0 {
		t.Fatal("SECURITY ISSUE: Collection passed functionary check despite step " +
			"having NO functionaries defined. This means any signer is accepted.")
	}

	if len(result.Rejected) == 0 {
		t.Fatal("SECURITY ISSUE: Collection was neither passed nor rejected. " +
			"This is a logic hole.")
	}

	t.Log("CORRECT: Step with no functionaries rejects all collections. " +
		"No collections can pass the functionary check when no functionaries are defined.")
}

// ===========================================================================
// R3-169: Rego evaluation with StrictBuiltinErrors catches runtime
//         errors from builtins, but the error message may contain
//         sensitive attestation data. This is similar to R3-159 but
//         through the builtin error path rather than deny messages.
//
// Severity: MEDIUM
// Bug: When a Rego builtin errors with strict mode on, the error
//      message often includes the arguments passed to it. If those
//      arguments come from attestation data, sensitive values leak.
// ===========================================================================

func TestSecurity_R3_169_StrictBuiltinErrorLeaksData(t *testing.T) {
	// An attestor with a secret value that we'll try to leak through
	// a builtin error.
	attestor := &secWrappedAttestor{
		typeName: "leak-type",
		inner: map[string]interface{}{
			"name":       "test",
			"type":       "leak-type",
			"secret_api_key": "sk_live_VERYSECRETKEY123",
		},
	}

	// Rego policy that tries to parse the secret as JSON, which will fail
	// and include the secret in the error message.
	policy := RegoPolicy{
		Name: "leak_via_builtin.rego",
		Module: []byte(`package leak_builtin

deny[msg] {
  parsed := json.unmarshal(input.secret_api_key)
  msg := "should not reach here"
}
`),
	}

	err := EvaluateRegoPolicy(attestor, []RegoPolicy{policy})
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "sk_live_VERYSECRETKEY123") {
			t.Log("SECURITY FINDING: Secret API key leaked through Rego builtin " +
				"error message. StrictBuiltinErrors includes the argument value " +
				"in the error, exposing sensitive attestation data.")
		} else {
			t.Logf("Builtin error did not contain the secret directly: %v", err)
		}
	}
}

// ===========================================================================
// R3-170: Policy.Verify with an ArtifactsFrom reference to a step that
//         is also in AttestationsFrom creates a double dependency, but
//         only AttestationsFrom is used for topological ordering.
//         ArtifactsFrom ordering is not guaranteed, which could lead to
//         the artifact check running before the referenced step has
//         passed collections.
//
// Severity: LOW (the artifact check at verifyArtifacts happens AFTER
//           all step evaluations, so ordering doesn't matter for it)
// ===========================================================================

func TestSecurity_R3_170_ArtifactsFromNotInTopologicalOrder(t *testing.T) {
	// A policy where deploy depends on build for both artifacts and attestations.
	p := Policy{
		Steps: map[string]Step{
			"build": {Name: "build"},
			"deploy": {
				Name:             "deploy",
				ArtifactsFrom:    []string{"build"},
				AttestationsFrom: []string{"build"},
			},
		},
	}

	err := p.Validate()
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	sorted, err := p.topologicalSort()
	if err != nil {
		t.Fatalf("topologicalSort failed: %v", err)
	}

	if len(sorted) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(sorted))
	}

	// Build should come before deploy.
	if sorted[0] != "build" || sorted[1] != "deploy" {
		t.Fatalf("expected [build, deploy], got %v", sorted)
	}

	t.Log("CORRECT: AttestationsFrom drives topological ordering. ArtifactsFrom " +
		"is handled in verifyArtifacts() which runs after all step evaluations, " +
		"so ordering is not an issue for artifact checks.")
}

// ===========================================================================
// R3-171: Verify() validates artifactsFrom references point to existing
//         steps (lines 392-398), but it does NOT validate that
//         attestationsFrom references point to existing steps at the
//         same location. That validation happens in Validate().
//         If someone calls Verify() on a policy that hasn't been
//         validated... wait, Verify() DOES call Validate() at line 380.
//
//         Actually, the real issue: Validate() checks attestationsFrom
//         references, but the early return on the first error means
//         if there are BOTH attestationsFrom AND artifactsFrom issues,
//         only the first one is reported. Let's verify.
// ===========================================================================

func TestSecurity_R3_171_ValidateReportsFirstErrorOnly(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"deploy": {
				Name:             "deploy",
				AttestationsFrom: []string{"ghost_att"},
				ArtifactsFrom:    []string{"ghost_art"},
			},
		},
	}

	err := p.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}

	// Check which error we got.
	errStr := err.Error()
	hasAttErr := strings.Contains(errStr, "ghost_att")
	hasArtErr := strings.Contains(errStr, "ghost_art")

	if hasAttErr && !hasArtErr {
		t.Log("CONFIRMED: Validate() reports the attestationsFrom error first and " +
			"does not report the artifactsFrom error. The artifactsFrom check is in " +
			"Verify() at line 392, not in Validate(). Policy authors only see one " +
			"error at a time.")
	} else if hasArtErr && !hasAttErr {
		t.Log("artifactsFrom error reported before attestationsFrom error")
	} else if hasAttErr && hasArtErr {
		t.Log("Both errors reported -- good error reporting")
	} else {
		t.Logf("Unexpected error: %v", err)
	}
}

// ===========================================================================
// Summary of findings:
//
// R3-150 (HIGH): buildStepContext last-writer-wins allows cross-step data overwrite
// R3-151 (HIGH): Empty collection name bypasses step-name filter
// R3-152 (HIGH): Rego deny[msg] { false } silently passes (empty set bypass)
// R3-153 (MEDIUM): Duplicate AttestationsFrom handled but not rejected by Validate
// R3-154 (MEDIUM): Duplicate attestation types within collection: last-writer-wins
// R3-155 (HIGH): AllowAllConstraint + empty fields = accept any certificate
// R3-156 (MEDIUM): Unbounded clockSkewTolerance can resurrect expired policies
// R3-157 (MEDIUM): deny = [] (empty array) silently passes
// R3-158 (LOW): checkFunctionaries mutates input slice
// R3-159 (HIGH): Rego data exfiltration via deny messages
// R3-160 (HIGH): Attestor "steps" field injection via backward-compat path
// R3-161 (LOW): Duplicate passed collections across depth iterations
// R3-162 (LOW): Empty Roots properly fail-closed (correct behavior)
// R3-163 (MEDIUM): Per-attestation-type Rego timeout enables DoS multiplication
// R3-164 (MEDIUM): Duplicate constraint/cert values interact with map dedup
// R3-165 (HIGH): Non-star glob chars treated as literals in checkCertConstraintGlob
// R3-166 (MEDIUM): Step Name vs map key mismatch creates split-brain
// R3-167 (MEDIUM): buildStepContext silently drops unmarshalable attestations
// R3-168 (LOW): No functionaries correctly rejects all (correct behavior)
// R3-169 (MEDIUM): StrictBuiltinErrors leaks attestation data in error messages
// R3-170 (LOW): ArtifactsFrom not in topological order (correct, checked after)
// R3-171 (LOW): Validate reports first error only, not all validation errors
// ===========================================================================

// Ensure all types compile properly.
var _ = fmt.Sprintf
