// jade:ring local

package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// A signing leaf's keyUsage, when present, must assert digitalSignature
// (RFC 5280 §4.2.1.3). Go's x509.Verify ignores the leaf's keyUsage bits, so
// a certificate issued for key encipherment, chaining to a trusted root and
// carrying codeSigning, used to verify DSSE signatures. formal/signing-trust
// refutes this as ce_leaf_without_digitalSignature (#9917).

func keyUsageChain(t *testing.T, leafKU x509.KeyUsage) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ku-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ku-leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Minute),
		KeyUsage:     leafKU,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return root, leaf, leafKey
}

func TestX509VerifierLeafKeyUsage(t *testing.T) {
	body := []byte("signed body")
	cases := []struct {
		name   string
		ku     x509.KeyUsage
		accept bool
	}{
		{"digitalSignature", x509.KeyUsageDigitalSignature, true},
		{"no keyUsage extension", 0, true},
		{"digitalSignature plus keyEncipherment", x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, true},
		{"keyEncipherment only", x509.KeyUsageKeyEncipherment, false},
		{"keyAgreement only", x509.KeyUsageKeyAgreement, false},
		{"contentCommitment only", x509.KeyUsageContentCommitment, false},
		{"digitalSignature plus keyCertSign on a non-CA", x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, false},
		{"digitalSignature plus cRLSign on a non-CA", x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, leaf, key := keyUsageChain(t, c.ku)
			sig, err := NewECDSASigner(key, crypto.SHA256).Sign(bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			v, err := NewX509Verifier(leaf, nil, []*x509.Certificate{root}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			verr := v.Verify(bytes.NewReader(body), sig)
			berr := v.BelongsToRoot(root)
			if c.accept {
				if verr != nil || berr != nil {
					t.Fatalf("Verify=%v BelongsToRoot=%v, want both nil", verr, berr)
				}
				return
			}
			if !errors.Is(verr, ErrSigningKeyUsage) || !errors.Is(berr, ErrSigningKeyUsage) {
				t.Fatalf("Verify=%v BelongsToRoot=%v: a leaf whose keyUsage lacks digitalSignature must fail with ErrSigningKeyUsage", verr, berr)
			}
		})
	}
}

func TestCheckSigningKeyUsageContentCommitment(t *testing.T) {
	_, leaf, _ := keyUsageChain(t, x509.KeyUsageContentCommitment)
	if err := CheckSigningKeyUsage(leaf, true); err != nil {
		t.Fatalf("contentCommitment must satisfy a signer that allows it: %v", err)
	}
	if err := CheckSigningKeyUsage(leaf, false); !errors.Is(err, ErrSigningKeyUsage) {
		t.Fatalf("contentCommitment alone must not satisfy a digitalSignature signer: %v", err)
	}
}
