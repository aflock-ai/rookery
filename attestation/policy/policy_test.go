package policy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// mockVerifiedSource implements source.VerifiedSourcer for testing
type mockVerifiedSource struct {
	results []source.CollectionVerificationResult
	err     error
}

func (m *mockVerifiedSource) Search(_ context.Context, _ string, _ []string, _ []string) ([]source.CollectionVerificationResult, error) {
	return m.results, m.err
}

// dummyAttestor satisfies attestation.Attestor for rego and validation tests.
type dummyAttestor struct {
	name    string
	typeStr string
}

func (d *dummyAttestor) Name() string                                  { return d.name }
func (d *dummyAttestor) Type() string                                  { return d.typeStr }
func (d *dummyAttestor) RunType() attestation.RunType                  { return "test" }
func (d *dummyAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (d *dummyAttestor) Schema() *jsonschema.Schema                    { return nil }

// marshalableAttestor is like dummyAttestor but with exported fields so it
// produces useful JSON when marshaled (e.g. for Rego input testing).
type marshalableAttestor struct {
	AttName string `json:"name"`
	AttType string `json:"type"`
}

func (m *marshalableAttestor) Name() string                                  { return m.AttName }
func (m *marshalableAttestor) Type() string                                  { return m.AttType }
func (m *marshalableAttestor) RunType() attestation.RunType                  { return "test" }
func (m *marshalableAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (m *marshalableAttestor) Schema() *jsonschema.Schema                    { return nil }

// generateSelfSignedCert creates a self-signed CA cert and returns the cert, key, and PEM bytes.
func generateSelfSignedCert(t *testing.T, cn string, orgs []string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

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
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return cert, priv, pemBytes
}

// generateLeafCert creates a leaf cert signed by the given CA.
func generateLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, orgs, emails, dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: orgs,
		},
		EmailAddresses: emails,
		DNSNames:       dnsNames,
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &priv.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert, priv
}

// newDigestSet is a shorthand for tests.
func newDigestSet(sha256 string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: crypto.SHA256}: sha256,
	}
}

// ---------------------------------------------------------------------------
// checkCertConstraint (unexported, but accessible from same package)
// ---------------------------------------------------------------------------

func TestCheckCertConstraint_AllowAll(t *testing.T) {
	err := checkCertConstraint("common name", []string{AllowAllConstraint}, []string{"anything"})
	assert.NoError(t, err, "wildcard constraint should pass any value")
}

func TestCheckCertConstraint_ExactMatch(t *testing.T) {
	err := checkCertConstraint("email", []string{"alice@example.com"}, []string{"alice@example.com"})
	assert.NoError(t, err)
}

func TestCheckCertConstraint_MultipleMatch(t *testing.T) {
	err := checkCertConstraint("org", []string{"ACME", "Globex"}, []string{"ACME", "Globex"})
	assert.NoError(t, err)
}

func TestCheckCertConstraint_MissingValue(t *testing.T) {
	// Constraint requires "ACME" but cert has nothing.
	err := checkCertConstraint("org", []string{"ACME"}, []string{})
	assert.Error(t, err, "should fail when cert lacks required value")
}

func TestCheckCertConstraint_UnexpectedValue(t *testing.T) {
	// Constraint only allows "ACME", cert has "ACME" + "Evil Corp".
	err := checkCertConstraint("org", []string{"ACME"}, []string{"ACME", "Evil Corp"})
	assert.Error(t, err, "should fail when cert has unexpected extra value")
}

func TestCheckCertConstraint_EmptyConstraintNonEmptyValue(t *testing.T) {
	// No constraints set, but cert has a value — should fail.
	err := checkCertConstraint("dns name", []string{}, []string{"foo.bar"})
	assert.Error(t, err)
}

func TestCheckCertConstraint_EmptyBothSides(t *testing.T) {
	err := checkCertConstraint("dns name", []string{}, []string{})
	assert.NoError(t, err, "no constraints and no values should pass")
}

func TestCheckCertConstraint_SingleEmptyStringBothSides(t *testing.T) {
	// Special case: single empty-string normalization on both sides.
	err := checkCertConstraint("common name", []string{""}, []string{""})
	assert.NoError(t, err)
}

func TestCheckCertConstraint_ConstraintEmptyStringCertHasValue(t *testing.T) {
	// Constraint is a single empty string (treated as empty), cert has a value.
	err := checkCertConstraint("common name", []string{""}, []string{"real-cn"})
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// StepResult
// ---------------------------------------------------------------------------

func TestStepResult_Analyze_Passed(t *testing.T) {
	sr := StepResult{
		Step: "build",
		Passed: []PassedCollection{
			{Collection: source.CollectionVerificationResult{CollectionEnvelope: source.CollectionEnvelope{Collection: attestation.Collection{Name: "build"}}}},
		},
	}
	assert.True(t, sr.Analyze())
}

func TestStepResult_Analyze_NoPassed(t *testing.T) {
	sr := StepResult{
		Step: "build",
		Rejected: []RejectedCollection{
			{Reason: fmt.Errorf("bad")},
		},
	}
	assert.False(t, sr.Analyze())
}

func TestStepResult_Analyze_PassedWithErrors(t *testing.T) {
	// If a passed collection somehow has errors, Analyze should return false.
	sr := StepResult{
		Step: "build",
		Passed: []PassedCollection{
			{Collection: source.CollectionVerificationResult{
				CollectionEnvelope: source.CollectionEnvelope{Collection: attestation.Collection{Name: "build"}},
				Errors:             []error{fmt.Errorf("surprise")},
			}},
		},
	}
	assert.False(t, sr.Analyze())
}

func TestStepResult_HasErrors(t *testing.T) {
	sr := StepResult{Rejected: []RejectedCollection{{Reason: fmt.Errorf("x")}}}
	assert.True(t, sr.HasErrors())
	assert.False(t, StepResult{}.HasErrors())
}

func TestStepResult_HasPassed(t *testing.T) {
	sr := StepResult{Passed: []PassedCollection{{}}}
	assert.True(t, sr.HasPassed())
	assert.False(t, StepResult{}.HasPassed())
}

func TestStepResult_Error_ContainsStepName(t *testing.T) {
	sr := StepResult{
		Step:     "deploy",
		Rejected: []RejectedCollection{{Reason: fmt.Errorf("no functionary")}},
	}
	msg := sr.Error()
	assert.Contains(t, msg, "deploy")
	assert.Contains(t, msg, "no functionary")
}

// ---------------------------------------------------------------------------
// compareArtifacts
// ---------------------------------------------------------------------------

func TestCompareArtifacts_Match(t *testing.T) {
	ds := newDigestSet("abc123")
	mats := map[string]cryptoutil.DigestSet{"file.txt": ds}
	arts := map[string]cryptoutil.DigestSet{"file.txt": ds}
	assert.NoError(t, compareArtifacts(mats, arts))
}

func TestCompareArtifacts_Mismatch(t *testing.T) {
	mats := map[string]cryptoutil.DigestSet{"file.txt": newDigestSet("aaa")}
	arts := map[string]cryptoutil.DigestSet{"file.txt": newDigestSet("bbb")}
	err := compareArtifacts(mats, arts)
	assert.Error(t, err)
	var mismatch ErrMismatchArtifact
	assert.ErrorAs(t, err, &mismatch)
	assert.Equal(t, "file.txt", mismatch.Path)
}

func TestCompareArtifacts_DisjointPaths(t *testing.T) {
	mats := map[string]cryptoutil.DigestSet{"a.txt": newDigestSet("aaa")}
	arts := map[string]cryptoutil.DigestSet{"b.txt": newDigestSet("bbb")}
	// No overlap means no error — paths that don't intersect are ignored.
	assert.NoError(t, compareArtifacts(mats, arts))
}

func TestCompareArtifacts_EmptyMaterials(t *testing.T) {
	arts := map[string]cryptoutil.DigestSet{"file.txt": newDigestSet("abc")}
	assert.NoError(t, compareArtifacts(nil, arts))
}

func TestCompareArtifacts_EmptyArtifacts(t *testing.T) {
	mats := map[string]cryptoutil.DigestSet{"file.txt": newDigestSet("abc")}
	assert.NoError(t, compareArtifacts(mats, nil))
}

// ---------------------------------------------------------------------------
// checkVerifyOpts
// ---------------------------------------------------------------------------

func TestCheckVerifyOpts_Valid(t *testing.T) {
	vo := &verifyOptions{
		verifiedSource: &mockVerifiedSource{},
		subjectDigests: []string{"sha256:abc"},
		searchDepth:    3,
	}
	assert.NoError(t, checkVerifyOpts(vo))
}

func TestCheckVerifyOpts_NilSource(t *testing.T) {
	vo := &verifyOptions{
		subjectDigests: []string{"sha256:abc"},
		searchDepth:    3,
	}
	err := checkVerifyOpts(vo)
	assert.Error(t, err)
	var invalid ErrInvalidOption
	assert.ErrorAs(t, err, &invalid)
	assert.Equal(t, "verified source", invalid.Option)
}

func TestCheckVerifyOpts_NoDigests(t *testing.T) {
	vo := &verifyOptions{
		verifiedSource: &mockVerifiedSource{},
		searchDepth:    3,
	}
	err := checkVerifyOpts(vo)
	assert.Error(t, err)
	var invalid ErrInvalidOption
	assert.ErrorAs(t, err, &invalid)
	assert.Equal(t, "subject digests", invalid.Option)
}

func TestCheckVerifyOpts_ZeroDepth(t *testing.T) {
	vo := &verifyOptions{
		verifiedSource: &mockVerifiedSource{},
		subjectDigests: []string{"sha256:abc"},
		searchDepth:    0,
	}
	err := checkVerifyOpts(vo)
	assert.Error(t, err)
	var invalid ErrInvalidOption
	assert.ErrorAs(t, err, &invalid)
	assert.Equal(t, "search depth", invalid.Option)
}

// ---------------------------------------------------------------------------
// VerifyOption functional options
// ---------------------------------------------------------------------------

func TestWithVerifiedSource(t *testing.T) {
	ms := &mockVerifiedSource{}
	vo := &verifyOptions{}
	WithVerifiedSource(ms)(vo)
	assert.Equal(t, ms, vo.verifiedSource)
}

func TestWithSubjectDigests(t *testing.T) {
	vo := &verifyOptions{}
	WithSubjectDigests([]string{"d1", "d2"})(vo)
	assert.Equal(t, []string{"d1", "d2"}, vo.subjectDigests)
}

func TestWithSearchDepth(t *testing.T) {
	vo := &verifyOptions{}
	WithSearchDepth(7)(vo)
	assert.Equal(t, 7, vo.searchDepth)
}

// ---------------------------------------------------------------------------
// Policy.Verify - expiry
// ---------------------------------------------------------------------------

func TestVerify_PolicyExpired(t *testing.T) {
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(-1 * time.Hour)},
		Steps:   map[string]Step{},
	}
	ms := &mockVerifiedSource{}
	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	assert.False(t, pass)
	assert.Nil(t, results)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "policy expired")
}

func TestVerify_MissingOptions(t *testing.T) {
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps:   map[string]Step{},
	}
	// No verified source — should fail option validation before anything else.
	pass, results, err := p.Verify(context.Background(),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	assert.False(t, pass)
	assert.Nil(t, results)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Policy.Verify - search error propagation
// ---------------------------------------------------------------------------

func TestVerify_SearchError(t *testing.T) {
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			"build": {Name: "build"},
		},
	}
	ms := &mockVerifiedSource{err: fmt.Errorf("search exploded")}
	pass, _, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	assert.False(t, pass)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "search exploded")
}

// ---------------------------------------------------------------------------
// Policy.Verify - no collections for step (step fails)
// ---------------------------------------------------------------------------

func TestVerify_NoCollections(t *testing.T) {
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			"build": {Name: "build"},
		},
	}
	ms := &mockVerifiedSource{results: nil}
	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	assert.NoError(t, err)
	assert.False(t, pass)
	assert.NotNil(t, results)
	assert.True(t, results["build"].HasErrors())
}

// ---------------------------------------------------------------------------
// Step.validateAttestations
// ---------------------------------------------------------------------------

func TestValidateAttestations_EmptyCollections(t *testing.T) {
	s := Step{Name: "build"}
	result := s.validateAttestations(nil, "", nil)
	assert.Equal(t, "build", result.Step)
	assert.Empty(t, result.Passed)
	assert.Empty(t, result.Rejected)
}

func TestValidateAttestations_CollectionWithMatchingAttestations(t *testing.T) {
	attType := "https://example.com/attestation/v1"
	s := Step{
		Name: "build",
		Attestations: []Attestation{
			{Type: attType},
		},
	}

	coll := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{
				Type:        attType,
				Attestation: &dummyAttestor{name: "dummy", typeStr: attType},
			},
		},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: coll,
		},
	}

	result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
	assert.Len(t, result.Passed, 1)
	assert.Empty(t, result.Rejected)
}

func TestValidateAttestations_MissingAttestation(t *testing.T) {
	s := Step{
		Name: "build",
		Attestations: []Attestation{
			{Type: "https://example.com/needed"},
		},
	}

	coll := attestation.Collection{Name: "build"}
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{Collection: coll},
	}

	result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
	assert.Empty(t, result.Passed)
	assert.Len(t, result.Rejected, 1)
	assert.Contains(t, result.Rejected[0].Reason.Error(), "missing attestation")
}

func TestValidateAttestations_CollectionWithErrors(t *testing.T) {
	s := Step{
		Name:         "build",
		Attestations: []Attestation{},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "build"},
		},
		Errors: []error{fmt.Errorf("envelope verification failed")},
	}

	result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
	assert.Empty(t, result.Passed)
	assert.Len(t, result.Rejected, 1)
	assert.Contains(t, result.Rejected[0].Reason.Error(), "envelope verification failed")
}

func TestValidateAttestations_SkipsDifferentCollectionName(t *testing.T) {
	s := Step{
		Name:         "build",
		Attestations: []Attestation{},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "deploy"},
		},
	}

	result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
	assert.Empty(t, result.Passed)
	assert.Empty(t, result.Rejected)
}

// ---------------------------------------------------------------------------
// Step.checkFunctionaries
// ---------------------------------------------------------------------------

func TestCheckFunctionaries_NoVerifiers(t *testing.T) {
	s := Step{Name: "build"}
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	result := s.checkFunctionaries([]source.CollectionVerificationResult{cvr}, nil)
	assert.Empty(t, result.Passed)
	assert.Len(t, result.Rejected, 1)
	assert.Contains(t, result.Rejected[0].Reason.Error(), "no verifiers present")
}

func TestCheckFunctionaries_WrongPredicateType(t *testing.T) {
	s := Step{Name: "build"}
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Statement: intoto.Statement{PredicateType: "https://wrong/type"},
		},
	}

	result := s.checkFunctionaries([]source.CollectionVerificationResult{cvr}, nil)
	// Even if predicate type is wrong, the "no verifiers" rejection also fires.
	found := false
	for _, r := range result.Rejected {
		if r.Reason != nil && (assert.ObjectsAreEqual(r.Reason.Error(), "") == false) {
			found = true
		}
	}
	assert.True(t, found, "should have rejection entries")
}

func TestCheckFunctionaries_PublicKeyIDMatch(t *testing.T) {
	// Generate a real key so KeyID returns something deterministic.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	s := Step{
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

	result := s.checkFunctionaries([]source.CollectionVerificationResult{cvr}, nil)
	assert.Len(t, result.Passed, 1)
	assert.Empty(t, result.Rejected)
}

func TestCheckFunctionaries_PublicKeyIDMismatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)

	s := Step{
		Name: "build",
		Functionaries: []Functionary{
			{PublicKeyID: "definitely-wrong-key-id"},
		},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
		},
		Verifiers: []cryptoutil.Verifier{verifier},
	}

	result := s.checkFunctionaries([]source.CollectionVerificationResult{cvr}, nil)
	assert.Empty(t, result.Passed)
	assert.NotEmpty(t, result.Rejected)
}

// ---------------------------------------------------------------------------
// Functionary.Validate
// ---------------------------------------------------------------------------

func TestFunctionary_Validate_PublicKeyMatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	f := Functionary{PublicKeyID: keyID}
	assert.NoError(t, f.Validate(verifier, nil))
}

func TestFunctionary_Validate_PublicKeyMismatch_NotX509(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)

	f := Functionary{PublicKeyID: "wrong-id"}
	err = f.Validate(verifier, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a public key verifier or a x509 verifier")
}

func TestFunctionary_Validate_X509_NoRoots(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "leaf", []string{"TestOrg"}, nil, nil)

	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	// Functionary with no PublicKeyID and no CertConstraint.Roots => should fail
	f := Functionary{
		CertConstraint: CertConstraint{},
	}
	err = f.Validate(x509Verifier, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no trusted roots provided")
}

func TestFunctionary_Validate_X509_WithRoots(t *testing.T) {
	ca, caKey, pemBytes := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "leaf", []string{"TestOrg"}, nil, nil)

	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	trustBundles := map[string]TrustBundle{
		"test-root": {Root: ca},
	}

	_ = pemBytes
	f := Functionary{
		CertConstraint: CertConstraint{
			CommonName:    "leaf",
			Organizations: []string{"TestOrg"},
			Roots:         []string{"test-root"},
		},
	}
	err = f.Validate(x509Verifier, trustBundles)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// CertConstraint.Check
// ---------------------------------------------------------------------------

func TestCertConstraint_Check_AllFields(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "leaf-cn", []string{"LeafOrg"}, []string{"test@example.com"}, []string{"example.com"})

	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	trustBundles := map[string]TrustBundle{
		"root1": {Root: ca},
	}

	cc := CertConstraint{
		CommonName:    "leaf-cn",
		Organizations: []string{"LeafOrg"},
		Emails:        []string{"test@example.com"},
		DNSNames:      []string{"example.com"},
		Roots:         []string{"root1"},
	}

	err = cc.Check(x509Verifier, trustBundles)
	assert.NoError(t, err)
}

func TestCertConstraint_Check_WrongCommonName(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "actual-cn", []string{"Org"}, nil, nil)

	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	trustBundles := map[string]TrustBundle{
		"root1": {Root: ca},
	}

	cc := CertConstraint{
		CommonName:    "expected-cn",
		Organizations: []string{"Org"},
		Roots:         []string{"root1"},
	}

	err = cc.Check(x509Verifier, trustBundles)
	assert.Error(t, err)
}

func TestCertConstraint_Check_WildcardRoots(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "leaf", []string{"Org"}, nil, nil)

	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	trustBundles := map[string]TrustBundle{
		"root1": {Root: ca},
	}

	cc := CertConstraint{
		CommonName:    "leaf",
		Organizations: []string{"Org"},
		Roots:         []string{AllowAllConstraint},
	}

	err = cc.Check(x509Verifier, trustBundles)
	assert.NoError(t, err)
}

func TestCertConstraint_Check_WrongRoot(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "leaf", []string{"Org"}, nil, nil)

	// Verifier references the real CA but the trust bundle doesn't contain it.
	otherCA, _, _ := generateSelfSignedCert(t, "OtherCA", []string{"Other"})
	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	trustBundles := map[string]TrustBundle{
		"other-root": {Root: otherCA},
	}

	cc := CertConstraint{
		CommonName:    "leaf",
		Organizations: []string{"Org"},
		Roots:         []string{"other-root"},
	}

	err = cc.Check(x509Verifier, trustBundles)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// TrustBundles / TimestampAuthorityTrustBundles
// ---------------------------------------------------------------------------

func TestPolicy_TrustBundles(t *testing.T) {
	_, _, pemBytes := generateSelfSignedCert(t, "RootCA", []string{"Org"})
	p := Policy{
		Roots: map[string]Root{
			"root1": {Certificate: pemBytes},
		},
	}
	bundles, err := p.TrustBundles()
	require.NoError(t, err)
	assert.Len(t, bundles, 1)
	assert.NotNil(t, bundles["root1"].Root)
	assert.Equal(t, "RootCA", bundles["root1"].Root.Subject.CommonName)
}

func TestPolicy_TrustBundles_InvalidCert(t *testing.T) {
	p := Policy{
		Roots: map[string]Root{
			"bad": {Certificate: []byte("not-a-cert")},
		},
	}
	_, err := p.TrustBundles()
	assert.Error(t, err)
}

func TestPolicy_TrustBundles_WithIntermediates(t *testing.T) {
	ca, caKey, caPEM := generateSelfSignedCert(t, "RootCA", []string{"Org"})

	// Create an intermediate CA.
	intPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	intTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject:      pkix.Name{CommonName: "IntermediateCA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, ca, &intPriv.PublicKey, caKey)
	require.NoError(t, err)
	intPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intDER})

	p := Policy{
		Roots: map[string]Root{
			"root1": {
				Certificate:   caPEM,
				Intermediates: [][]byte{intPEM},
			},
		},
	}
	bundles, err := p.TrustBundles()
	require.NoError(t, err)
	assert.Len(t, bundles["root1"].Intermediates, 1)
	assert.Equal(t, "IntermediateCA", bundles["root1"].Intermediates[0].Subject.CommonName)
}

func TestPolicy_TimestampAuthorityTrustBundles(t *testing.T) {
	_, _, pemBytes := generateSelfSignedCert(t, "TSACA", []string{"TSA"})
	p := Policy{
		TimestampAuthorities: map[string]Root{
			"tsa1": {Certificate: pemBytes},
		},
	}
	bundles, err := p.TimestampAuthorityTrustBundles()
	require.NoError(t, err)
	assert.Len(t, bundles, 1)
	assert.Equal(t, "TSACA", bundles["tsa1"].Root.Subject.CommonName)
}

// ---------------------------------------------------------------------------
// PublicKeyVerifiers
// ---------------------------------------------------------------------------

func TestPolicy_PublicKeyVerifiers_ECDSAKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubPEM, err := cryptoutil.PublicPemBytes(&priv.PublicKey)
	require.NoError(t, err)

	keyID, err := cryptoutil.GeneratePublicKeyID(&priv.PublicKey, crypto.SHA256)
	require.NoError(t, err)

	p := Policy{
		PublicKeys: map[string]PublicKey{
			"key1": {KeyID: keyID, Key: pubPEM},
		},
	}

	verifiers, err := p.PublicKeyVerifiers(nil)
	require.NoError(t, err)
	assert.Len(t, verifiers, 1)
	assert.Contains(t, verifiers, keyID)
}

func TestPolicy_PublicKeyVerifiers_KeyIDMismatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubPEM, err := cryptoutil.PublicPemBytes(&priv.PublicKey)
	require.NoError(t, err)

	p := Policy{
		PublicKeys: map[string]PublicKey{
			"key1": {KeyID: "wrong-key-id", Key: pubPEM},
		},
	}

	_, err = p.PublicKeyVerifiers(nil)
	assert.Error(t, err)
	var mismatchErr ErrKeyIDMismatch
	assert.ErrorAs(t, err, &mismatchErr)
}

func TestPolicy_PublicKeyVerifiers_InvalidKey(t *testing.T) {
	p := Policy{
		PublicKeys: map[string]PublicKey{
			"key1": {KeyID: "some-id", Key: []byte("not-a-key")},
		},
	}

	_, err := p.PublicKeyVerifiers(nil)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// EvaluateRegoPolicy
// ---------------------------------------------------------------------------

func TestEvaluateRegoPolicy_NoPolicies(t *testing.T) {
	err := EvaluateRegoPolicy(&dummyAttestor{name: "dummy", typeStr: "test"}, nil)
	assert.NoError(t, err, "no policies should always pass")
}

func TestEvaluateRegoPolicy_PassingPolicy(t *testing.T) {
	module := []byte(`
package test

deny = reasons {
	reasons := []
}
`)
	policies := []RegoPolicy{{Module: module, Name: "test.rego"}}
	err := EvaluateRegoPolicy(&dummyAttestor{name: "dummy", typeStr: "test"}, policies)
	assert.NoError(t, err)
}

func TestEvaluateRegoPolicy_DenyingPolicy(t *testing.T) {
	module := []byte(`
package test

deny[msg] {
	msg := "always denied"
}
`)
	policies := []RegoPolicy{{Module: module, Name: "test.rego"}}
	err := EvaluateRegoPolicy(&dummyAttestor{name: "dummy", typeStr: "test"}, policies)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "always denied")
}

func TestEvaluateRegoPolicy_InvalidModule(t *testing.T) {
	module := []byte(`this is not valid rego at all!!!`)
	policies := []RegoPolicy{{Module: module, Name: "bad.rego"}}
	err := EvaluateRegoPolicy(&dummyAttestor{name: "dummy", typeStr: "test"}, policies)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

func TestErrorTypes(t *testing.T) {
	t.Run("ErrVerifyArtifactsFailed", func(t *testing.T) {
		e := ErrVerifyArtifactsFailed{Reasons: []string{"reason1", "reason2"}}
		assert.Contains(t, e.Error(), "reason1")
		assert.Contains(t, e.Error(), "reason2")
	})

	t.Run("ErrNoCollections", func(t *testing.T) {
		e := ErrNoCollections{Step: "build"}
		assert.Contains(t, e.Error(), "build")
	})

	t.Run("ErrMissingAttestation", func(t *testing.T) {
		e := ErrMissingAttestation{Step: "build", Attestation: "https://example.com/att"}
		assert.Contains(t, e.Error(), "build")
		assert.Contains(t, e.Error(), "https://example.com/att")
	})

	t.Run("ErrPolicyExpired", func(t *testing.T) {
		ts := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
		e := ErrPolicyExpired(ts)
		assert.Contains(t, e.Error(), "2024")
	})

	t.Run("ErrKeyIDMismatch", func(t *testing.T) {
		e := ErrKeyIDMismatch{Expected: "abc", Actual: "xyz"}
		assert.Contains(t, e.Error(), "abc")
		assert.Contains(t, e.Error(), "xyz")
	})

	t.Run("ErrUnknownStep", func(t *testing.T) {
		e := ErrUnknownStep("deploy")
		assert.Contains(t, e.Error(), "deploy")
	})

	t.Run("ErrArtifactCycle", func(t *testing.T) {
		e := ErrArtifactCycle("a -> b -> a")
		assert.Contains(t, e.Error(), "cycle")
	})

	t.Run("ErrMismatchArtifact", func(t *testing.T) {
		e := ErrMismatchArtifact{Path: "/foo/bar"}
		assert.Contains(t, e.Error(), "/foo/bar")
	})

	t.Run("ErrRegoInvalidData", func(t *testing.T) {
		e := ErrRegoInvalidData{Path: "data.test", Expected: "string", Actual: 42}
		assert.Contains(t, e.Error(), "data.test")
	})

	t.Run("ErrPolicyDenied", func(t *testing.T) {
		e := ErrPolicyDenied{Reasons: []string{"bad thing"}}
		assert.Contains(t, e.Error(), "bad thing")
	})

	t.Run("ErrConstraintCheckFailed", func(t *testing.T) {
		e := ErrConstraintCheckFailed{errs: []error{fmt.Errorf("failed")}}
		assert.Contains(t, e.Error(), "failed")
	})

	t.Run("ErrInvalidOption", func(t *testing.T) {
		e := ErrInvalidOption{Option: "source", Reason: "nil"}
		assert.Contains(t, e.Error(), "source")
		assert.Contains(t, e.Error(), "nil")
	})
}

// ---------------------------------------------------------------------------
// Policy.verifyArtifacts
// ---------------------------------------------------------------------------

func TestVerifyArtifacts_NoPassedCollections(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"build": {Name: "build"},
		},
	}

	resultsByStep := map[string]StepResult{
		"build": {Step: "build"},
	}

	result, err := p.verifyArtifacts(resultsByStep)
	require.NoError(t, err)
	assert.True(t, result["build"].HasErrors())
	assert.Contains(t, result["build"].Rejected[0].Reason.Error(), "no passed collections present")
}

// ---------------------------------------------------------------------------
// verifyCollectionArtifacts
// ---------------------------------------------------------------------------

func TestVerifyCollectionArtifacts_NoArtifactsFrom(t *testing.T) {
	step := Step{Name: "build"}
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "build"},
		},
	}
	err := verifyCollectionArtifacts(step, cvr, nil)
	assert.NoError(t, err, "no artifactsFrom means nothing to verify")
}

func TestVerifyCollectionArtifacts_ArtifactsFromMissing(t *testing.T) {
	step := Step{
		Name:          "deploy",
		ArtifactsFrom: []string{"build"},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "deploy"},
		},
	}

	// The "build" step has no passed collections, so verification should fail.
	collectionsByStep := map[string]StepResult{
		"build": {Step: "build"},
	}

	err := verifyCollectionArtifacts(step, cvr, collectionsByStep)
	assert.Error(t, err)
	var artErr ErrVerifyArtifactsFailed
	assert.ErrorAs(t, err, &artErr)
}

// ---------------------------------------------------------------------------
// Policy.Verify integration: full pass scenario with functionary match
// ---------------------------------------------------------------------------

func TestVerify_FullPassWithPublicKeyFunctionary(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	stepName := "build"
	coll := attestation.Collection{Name: stepName}

	cvr := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: coll,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	ms := &mockVerifiedSource{results: []source.CollectionVerificationResult{cvr}}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			stepName: {
				Name: stepName,
				Functionaries: []Functionary{
					{PublicKeyID: keyID},
				},
			},
		},
	}

	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	require.NoError(t, err)
	assert.True(t, pass)
	assert.NotNil(t, results)
	assert.True(t, results[stepName].HasPassed())
}

// ---------------------------------------------------------------------------
// Policy.Verify integration: fail when functionary doesn't match
// ---------------------------------------------------------------------------

func TestVerify_FailWhenFunctionaryDoesNotMatch(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)

	stepName := "build"
	coll := attestation.Collection{Name: stepName}

	cvr := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: coll,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	ms := &mockVerifiedSource{results: []source.CollectionVerificationResult{cvr}}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			stepName: {
				Name: stepName,
				Functionaries: []Functionary{
					{PublicKeyID: "totally-wrong-key-id"},
				},
			},
		},
	}

	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	require.NoError(t, err)
	assert.False(t, pass)
	assert.True(t, results[stepName].HasErrors())
}

// ---------------------------------------------------------------------------
// urisToStrings
// ---------------------------------------------------------------------------

func TestUrisToStrings(t *testing.T) {
	result := urisToStrings(nil)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// DeepCopy tests (generated code, but worth smoke-testing)
// ---------------------------------------------------------------------------

func TestDeepCopy_Policy(t *testing.T) {
	p := &Policy{
		Expires: metav1.Time{Time: time.Now()},
		Roots: map[string]Root{
			"r": {Certificate: []byte("cert")},
		},
		Steps: map[string]Step{
			"s": {Name: "s", Functionaries: []Functionary{{PublicKeyID: "k"}}},
		},
		PublicKeys: map[string]PublicKey{
			"pk": {KeyID: "k", Key: []byte("key")},
		},
	}
	cp := p.DeepCopy()
	require.NotNil(t, cp)

	// Mutate original, ensure copy is not affected.
	p.Roots["r"] = Root{Certificate: []byte("changed")}
	assert.Equal(t, []byte("cert"), cp.Roots["r"].Certificate)
}

func TestDeepCopy_NilPolicy(t *testing.T) {
	var p *Policy
	assert.Nil(t, p.DeepCopy())
}

func TestDeepCopy_Step(t *testing.T) {
	s := &Step{
		Name:          "build",
		Functionaries: []Functionary{{PublicKeyID: "k"}},
		ArtifactsFrom: []string{"prev"},
	}
	cp := s.DeepCopy()
	require.NotNil(t, cp)
	s.ArtifactsFrom[0] = "changed"
	assert.Equal(t, "prev", cp.ArtifactsFrom[0])
}

func TestDeepCopy_NilStep(t *testing.T) {
	var s *Step
	assert.Nil(t, s.DeepCopy())
}

func TestDeepCopy_CertConstraint(t *testing.T) {
	cc := &CertConstraint{
		CommonName: "cn",
		DNSNames:   []string{"a.com"},
		Emails:     []string{"a@b.com"},
		Roots:      []string{"r1"},
	}
	cp := cc.DeepCopy()
	require.NotNil(t, cp)
	cc.DNSNames[0] = "changed"
	assert.Equal(t, "a.com", cp.DNSNames[0])
}

func TestDeepCopy_NilCertConstraint(t *testing.T) {
	var cc *CertConstraint
	assert.Nil(t, cc.DeepCopy())
}

func TestDeepCopy_Step_AttestationsFrom(t *testing.T) {
	s := &Step{
		Name:             "deploy",
		AttestationsFrom: []string{"build", "test"},
	}
	cp := s.DeepCopy()
	require.NotNil(t, cp)
	assert.Equal(t, []string{"build", "test"}, cp.AttestationsFrom)
	s.AttestationsFrom[0] = "changed"
	assert.Equal(t, "build", cp.AttestationsFrom[0])
}

// ---------------------------------------------------------------------------
// Policy.Validate — self-reference, unknown step, circular dependency
// ---------------------------------------------------------------------------

func TestValidate_NoSteps(t *testing.T) {
	p := Policy{Steps: map[string]Step{}}
	assert.NoError(t, p.Validate())
}

func TestValidate_NoDependencies(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"build": {Name: "build"},
			"test":  {Name: "test"},
		},
	}
	assert.NoError(t, p.Validate())
}

func TestValidate_ValidLinearChain(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"build":  {Name: "build"},
			"test":   {Name: "test", AttestationsFrom: []string{"build"}},
			"deploy": {Name: "deploy", AttestationsFrom: []string{"test"}},
		},
	}
	assert.NoError(t, p.Validate())
}

func TestValidate_ValidDiamondDAG(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"build":  {Name: "build"},
			"lint":   {Name: "lint", AttestationsFrom: []string{"build"}},
			"test":   {Name: "test", AttestationsFrom: []string{"build"}},
			"deploy": {Name: "deploy", AttestationsFrom: []string{"lint", "test"}},
		},
	}
	assert.NoError(t, p.Validate())
}

func TestValidate_SelfReference(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"build": {Name: "build", AttestationsFrom: []string{"build"}},
		},
	}
	err := p.Validate()
	assert.Error(t, err)
	var selfRef ErrSelfReference
	assert.ErrorAs(t, err, &selfRef)
	assert.Equal(t, "build", selfRef.Step)
}

func TestValidate_UnknownStep(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"build": {Name: "build", AttestationsFrom: []string{"nonexistent"}},
		},
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestValidate_DirectCycle(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"a": {Name: "a", AttestationsFrom: []string{"b"}},
			"b": {Name: "b", AttestationsFrom: []string{"a"}},
		},
	}
	err := p.Validate()
	assert.Error(t, err)
	var cycle ErrCircularDependency
	assert.ErrorAs(t, err, &cycle)
}

func TestValidate_IndirectCycle(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"a": {Name: "a", AttestationsFrom: []string{"c"}},
			"b": {Name: "b", AttestationsFrom: []string{"a"}},
			"c": {Name: "c", AttestationsFrom: []string{"b"}},
		},
	}
	err := p.Validate()
	assert.Error(t, err)
	var cycle ErrCircularDependency
	assert.ErrorAs(t, err, &cycle)
	assert.GreaterOrEqual(t, len(cycle.Steps), 3)
}

// ---------------------------------------------------------------------------
// topologicalSort
// ---------------------------------------------------------------------------

func TestTopologicalSort_NoSteps(t *testing.T) {
	p := Policy{Steps: map[string]Step{}}
	sorted, err := p.topologicalSort()
	assert.NoError(t, err)
	assert.Empty(t, sorted)
}

func TestTopologicalSort_NoDependencies(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"a": {Name: "a"},
			"b": {Name: "b"},
		},
	}
	sorted, err := p.topologicalSort()
	assert.NoError(t, err)
	assert.Len(t, sorted, 2)
	assert.ElementsMatch(t, []string{"a", "b"}, sorted)
}

func TestTopologicalSort_LinearChain(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"build":  {Name: "build"},
			"test":   {Name: "test", AttestationsFrom: []string{"build"}},
			"deploy": {Name: "deploy", AttestationsFrom: []string{"test"}},
		},
	}
	sorted, err := p.topologicalSort()
	assert.NoError(t, err)
	assert.Len(t, sorted, 3)

	// build must come before test, test must come before deploy
	indexOf := func(name string) int {
		for i, s := range sorted {
			if s == name {
				return i
			}
		}
		return -1
	}
	assert.Less(t, indexOf("build"), indexOf("test"))
	assert.Less(t, indexOf("test"), indexOf("deploy"))
}

func TestTopologicalSort_Diamond(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"build":  {Name: "build"},
			"lint":   {Name: "lint", AttestationsFrom: []string{"build"}},
			"test":   {Name: "test", AttestationsFrom: []string{"build"}},
			"deploy": {Name: "deploy", AttestationsFrom: []string{"lint", "test"}},
		},
	}
	sorted, err := p.topologicalSort()
	assert.NoError(t, err)
	assert.Len(t, sorted, 4)

	indexOf := func(name string) int {
		for i, s := range sorted {
			if s == name {
				return i
			}
		}
		return -1
	}
	assert.Less(t, indexOf("build"), indexOf("lint"))
	assert.Less(t, indexOf("build"), indexOf("test"))
	assert.Less(t, indexOf("lint"), indexOf("deploy"))
	assert.Less(t, indexOf("test"), indexOf("deploy"))
}

// ---------------------------------------------------------------------------
// checkDependencies
// ---------------------------------------------------------------------------

func TestCheckDependencies_AllSatisfied(t *testing.T) {
	results := map[string]StepResult{
		"build": {Step: "build", Passed: []PassedCollection{{}}},
		"test":  {Step: "test", Passed: []PassedCollection{{}}},
	}
	err := checkDependencies([]string{"build", "test"}, results)
	assert.NoError(t, err)
}

func TestCheckDependencies_Missing(t *testing.T) {
	results := map[string]StepResult{
		"build": {Step: "build", Passed: []PassedCollection{{}}},
	}
	err := checkDependencies([]string{"build", "test"}, results)
	assert.Error(t, err)
	var depErr ErrDependencyNotVerified
	assert.ErrorAs(t, err, &depErr)
	assert.Equal(t, "test", depErr.Step)
}

func TestCheckDependencies_NoPassed(t *testing.T) {
	results := map[string]StepResult{
		"build": {Step: "build"},
	}
	err := checkDependencies([]string{"build"}, results)
	assert.Error(t, err)
	var depErr ErrDependencyNotVerified
	assert.ErrorAs(t, err, &depErr)
}

func TestCheckDependencies_Empty(t *testing.T) {
	err := checkDependencies(nil, nil)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// buildStepContext
// ---------------------------------------------------------------------------

func TestBuildStepContext_NoDeps(t *testing.T) {
	ctx := buildStepContext(nil, nil)
	assert.Nil(t, ctx)
}

func TestBuildStepContext_WithPassedDep(t *testing.T) {
	attType := "https://example.com/att/v1"
	results := map[string]StepResult{
		"build": {
			Step: "build",
			Passed: []PassedCollection{
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "build",
								Attestations: []attestation.CollectionAttestation{
									{
										Type:        attType,
										Attestation: &dummyAttestor{name: "dummy", typeStr: attType},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	ctx := buildStepContext([]string{"build"}, results)
	require.NotNil(t, ctx)
	buildCtx, ok := ctx["build"]
	require.True(t, ok)
	buildMap, ok := buildCtx.(map[string]interface{})
	require.True(t, ok)
	_, ok = buildMap[attType]
	assert.True(t, ok, "should contain the attestation type key")
}

func TestBuildStepContext_DepNotPassed(t *testing.T) {
	results := map[string]StepResult{
		"build": {Step: "build"}, // no passed collections
	}
	ctx := buildStepContext([]string{"build"}, results)
	assert.Nil(t, ctx)
}

func TestBuildStepContext_DepNotFound(t *testing.T) {
	ctx := buildStepContext([]string{"nonexistent"}, map[string]StepResult{})
	assert.Nil(t, ctx)
}

// ---------------------------------------------------------------------------
// EvaluateRegoPolicy with stepContext
// ---------------------------------------------------------------------------

func TestEvaluateRegoPolicy_WithStepContext(t *testing.T) {
	// Policy that checks input.steps.build exists.
	module := []byte(`
package test

deny[msg] {
	not input.steps.build
	msg := "build step data missing"
}
`)
	policies := []RegoPolicy{{Module: module, Name: "test.rego"}}
	stepCtx := map[string]interface{}{
		"build": map[string]interface{}{
			"https://example.com/att/v1": map[string]interface{}{
				"name": "dummy",
			},
		},
	}

	err := EvaluateRegoPolicy(&dummyAttestor{name: "dummy", typeStr: "test"}, policies, stepCtx)
	assert.NoError(t, err, "should pass when step context contains build data")
}

func TestEvaluateRegoPolicy_WithStepContext_DenyWhenMissing(t *testing.T) {
	// Policy that denies when build step is missing.
	module := []byte(`
package test

deny[msg] {
	not input.steps.build
	msg := "build step data missing"
}
`)
	policies := []RegoPolicy{{Module: module, Name: "test.rego"}}

	// Pass step context WITHOUT the "build" key.
	stepCtx := map[string]interface{}{
		"other": map[string]interface{}{},
	}

	err := EvaluateRegoPolicy(&dummyAttestor{name: "dummy", typeStr: "test"}, policies, stepCtx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "build step data missing")
}

func TestEvaluateRegoPolicy_WithNilStepContext_BackwardCompat(t *testing.T) {
	// When no step context is passed, input should be the attestor data directly
	// (not wrapped in {attestation: ..., steps: ...}).
	module := []byte(`
package test

deny[msg] {
	not input.name
	msg := "name field missing"
}
`)
	policies := []RegoPolicy{{Module: module, Name: "test.rego"}}

	// Without step context, input is the attestor JSON directly.
	// Use marshalableAttestor so the "name" field appears in JSON.
	err := EvaluateRegoPolicy(&marshalableAttestor{AttName: "dummy", AttType: "test"}, policies)
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Cross-step attestation new error types
// ---------------------------------------------------------------------------

func TestErrorTypes_CrossStep(t *testing.T) {
	t.Run("ErrCircularDependency", func(t *testing.T) {
		e := ErrCircularDependency{Steps: []string{"a", "b", "c", "a"}}
		assert.Contains(t, e.Error(), "circular dependency")
		assert.Contains(t, e.Error(), "a -> b -> c -> a")
	})

	t.Run("ErrSelfReference", func(t *testing.T) {
		e := ErrSelfReference{Step: "build"}
		assert.Contains(t, e.Error(), "build")
		assert.Contains(t, e.Error(), "cannot depend on itself")
	})

	t.Run("ErrDependencyNotVerified", func(t *testing.T) {
		e := ErrDependencyNotVerified{Step: "build"}
		assert.Contains(t, e.Error(), "build")
		assert.Contains(t, e.Error(), "not verified")
	})
}

// ---------------------------------------------------------------------------
// validateAttestations with cross-step context
// ---------------------------------------------------------------------------

func TestValidateAttestations_WithStepContext(t *testing.T) {
	attType := "https://example.com/attestation/v1"
	// A rego policy that accesses cross-step data.
	module := []byte(`
package test

deny[msg] {
	not input.steps.build
	msg := "no build step context"
}
`)
	s := Step{
		Name:             "test",
		AttestationsFrom: []string{"build"},
		Attestations: []Attestation{
			{
				Type:         attType,
				RegoPolicies: []RegoPolicy{{Module: module, Name: "cross-step.rego"}},
			},
		},
	}

	coll := attestation.Collection{
		Name: "test",
		Attestations: []attestation.CollectionAttestation{
			{
				Type:        attType,
				Attestation: &dummyAttestor{name: "dummy", typeStr: attType},
			},
		},
	}

	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{Collection: coll},
	}

	// With step context containing "build" data — should pass.
	stepCtx := map[string]interface{}{
		"build": map[string]interface{}{
			"some-att": map[string]interface{}{"data": "value"},
		},
	}
	result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", stepCtx)
	assert.Len(t, result.Passed, 1, "should pass when step context provides build data")
	assert.Empty(t, result.Rejected)

	// Without step context — should fail because policy requires build data.
	result2 := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
	assert.Empty(t, result2.Passed)
	assert.Len(t, result2.Rejected, 1, "should fail when no step context is provided")
}

// ---------------------------------------------------------------------------
// Policy.Verify with cross-step attestation (integration)
// ---------------------------------------------------------------------------

func TestVerify_CrossStepAttestationAccess(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	buildAttType := "https://example.com/build-att/v1"

	// Build step collection.
	buildColl := attestation.Collection{
		Name: "build",
		Attestations: []attestation.CollectionAttestation{
			{
				Type:        buildAttType,
				Attestation: &dummyAttestor{name: "build-att", typeStr: buildAttType},
			},
		},
	}
	buildCVR := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: buildColl,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	// Deploy step collection — no attestations needed (just functionary check).
	deployColl := attestation.Collection{Name: "deploy"}
	deployCVR := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: deployColl,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	// Return different results based on step name.
	ms2 := &stepAwareVerifiedSource{
		byStep: map[string][]source.CollectionVerificationResult{
			"build":  {buildCVR},
			"deploy": {deployCVR},
		},
	}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			"build": {
				Name: "build",
				Functionaries: []Functionary{
					{PublicKeyID: keyID},
				},
				Attestations: []Attestation{
					{Type: buildAttType},
				},
			},
			"deploy": {
				Name:             "deploy",
				AttestationsFrom: []string{"build"},
				Functionaries: []Functionary{
					{PublicKeyID: keyID},
				},
			},
		},
	}

	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(ms2),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	require.NoError(t, err)
	assert.True(t, pass)
	assert.NotNil(t, results)
	assert.True(t, results["build"].HasPassed())
	assert.True(t, results["deploy"].HasPassed())
}

// stepAwareVerifiedSource returns different results per step name.
type stepAwareVerifiedSource struct {
	byStep map[string][]source.CollectionVerificationResult
}

func (s *stepAwareVerifiedSource) Search(_ context.Context, stepName string, _ []string, _ []string) ([]source.CollectionVerificationResult, error) {
	return s.byStep[stepName], nil
}

// ---------------------------------------------------------------------------
// Policy.Verify rejects circular deps
// ---------------------------------------------------------------------------

func TestVerify_RejectsCircularDependency(t *testing.T) {
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			"a": {Name: "a", AttestationsFrom: []string{"b"}},
			"b": {Name: "b", AttestationsFrom: []string{"a"}},
		},
	}
	ms := &mockVerifiedSource{}
	pass, _, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	assert.False(t, pass)
	assert.Error(t, err)
}

func TestVerify_RejectsSelfReference(t *testing.T) {
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			"build": {Name: "build", AttestationsFrom: []string{"build"}},
		},
	}
	ms := &mockVerifiedSource{}
	pass, _, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	assert.False(t, pass)
	assert.Error(t, err)
	var selfRef ErrSelfReference
	assert.ErrorAs(t, err, &selfRef)
}
