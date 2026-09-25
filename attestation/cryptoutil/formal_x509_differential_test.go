// jade:ring local

package cryptoutil

// formal:differential signing-trust TestFormalX509Differential
//
// Binds the Lean model of RFC 5280 path validation (formal/signing-trust,
// SigningTrust/X509.lean) to X509Verifier.Verify. Each case of the model's
// "x509" vectors is a linear chain (leaf, intermediates, root) with the
// model's basicConstraints, pathLenConstraint, keyUsage, extKeyUsage,
// validity and unknown-critical-extension choices, built for real with
// x509.CreateCertificate, plus the set of certificates the verifier trusts.
// The verifier runs at the model's time over a valid signature, and must
// accept exactly when the model does.
//
// x509Model names which model the shipped code must match: "asbuilt" while
// a leaf's keyUsage is ignored, "required" once the fix lands.
//
// The test skips when the vectors are not on disk and FAILS instead when
// JADE_FORMAL_DIFFERENTIAL=1.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

const x509Model = "required"

// FormalCert is one certificate as the signing-trust model describes it.
type FormalCert struct {
	ID      int  `json:"id"`
	BC      bool `json:"bc"`
	CA      bool `json:"ca"`
	PathLen *int `json:"pathLen"`
	KU      *struct {
		DS bool `json:"ds"`
		CC bool `json:"cc"`
		CS bool `json:"cs"`
	} `json:"ku"`
	EKU  string `json:"eku"`
	NB   int    `json:"nb"`
	NA   int    `json:"na"`
	Crit bool   `json:"crit"`
}

// FormalAt maps a model time to a wall-clock time: model 1000 is base.
func FormalAt(base time.Time, m int) time.Time {
	return base.Add(time.Duration(m-1000) * time.Minute)
}

var formalUnknownCriticalOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// FormalTemplate turns a model certificate into a template.
func FormalTemplate(base time.Time, c FormalCert) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(int64(1000 + c.ID)),
		Subject:               pkix.Name{CommonName: fmt.Sprintf("formal-cert-%d", c.ID)},
		NotBefore:             FormalAt(base, c.NB),
		NotAfter:              FormalAt(base, c.NA),
		BasicConstraintsValid: c.BC,
		IsCA:                  c.CA,
		MaxPathLen:            -1,
	}
	if c.PathLen != nil {
		tmpl.MaxPathLen = *c.PathLen
		tmpl.MaxPathLenZero = *c.PathLen == 0
	}
	if c.KU != nil {
		ku := x509.KeyUsage(0)
		if c.KU.DS {
			ku |= x509.KeyUsageDigitalSignature
		}
		if c.KU.CC {
			ku |= x509.KeyUsageContentCommitment
		}
		if c.KU.CS {
			ku |= x509.KeyUsageCertSign
		}
		if ku == 0 {
			ku = x509.KeyUsageKeyEncipherment
		}
		tmpl.KeyUsage = ku
	}
	switch c.EKU {
	case "codeSigning":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	case "timeStamping":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	case "serverAuth":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "any":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	case "codeAndServer":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageServerAuth}
	case "tsAndServer":
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageServerAuth}
	}
	if c.Crit {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: formalUnknownCriticalOID, Critical: true, Value: []byte{0x05, 0x00}}}
	}
	return tmpl
}

// FormalChain builds a linear chain, leaf first, each certificate issued by
// the next and the last self-signed. It returns the certificates and keys.
func FormalChain(t *testing.T, base time.Time, chain []FormalCert) ([]*x509.Certificate, []*ecdsa.PrivateKey) {
	t.Helper()
	n := len(chain)
	certs := make([]*x509.Certificate, n)
	keys := make([]*ecdsa.PrivateKey, n)
	for i := range keys {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = k
	}
	for i := n - 1; i >= 0; i-- {
		tmpl := FormalTemplate(base, chain[i])
		parent, parentKey := tmpl, keys[i]
		if i < n-1 {
			parent, parentKey = certs[i+1], keys[i+1]
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &keys[i].PublicKey, parentKey)
		if err != nil {
			t.Fatalf("create cert %d: %v", chain[i].ID, err)
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			t.Fatal(err)
		}
	}
	return certs, keys
}

type formalX509Case struct {
	Chain    []FormalCert `json:"chain"`
	Anchors  []int        `json:"anchors"`
	T        int          `json:"t"`
	AsBuilt  bool         `json:"asbuilt"`
	Required bool         `json:"required"`
}

func TestFormalX509Differential(t *testing.T) {
	path := filepath.Join("..", "..", "formal", "signing-trust", "vectors", "signing-trust.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") != "" {
			t.Fatalf("JADE_FORMAL_DIFFERENTIAL is set but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal vectors not on disk (%v); the differential needs the repository checkout", err)
	}
	var v struct {
		X509 []formalX509Case `json:"x509"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(v.X509) == 0 {
		t.Fatal("vectors have no x509 section")
	}
	base := time.Now().UTC().Truncate(time.Second)
	body := []byte("formal signing-trust body")
	bad, accepted := 0, 0
	for i, c := range v.X509 {
		certs, keys := FormalChain(t, base, c.Chain)
		var roots, inters []*x509.Certificate
		for j, fc := range c.Chain {
			switch {
			case slices.Contains(c.Anchors, fc.ID):
				roots = append(roots, certs[j])
			case j > 0:
				inters = append(inters, certs[j])
			}
		}
		sig, err := NewECDSASigner(keys[0], crypto.SHA256).Sign(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := NewX509Verifier(certs[0], inters, roots, FormalAt(base, c.T))
		if err != nil {
			t.Fatal(err)
		}
		verr := verifier.Verify(bytes.NewReader(body), sig)
		got := verr == nil
		want := c.AsBuilt
		if x509Model == "required" {
			want = c.Required
		}
		if got {
			accepted++
		}
		if got != want {
			bad++
			if bad <= 20 {
				js, _ := json.Marshal(c)
				t.Errorf("x509 case %d: code accepts=%v (%v), %s model %v\n  %s", i, got, verr, x509Model, want, js)
			}
		}
	}
	if bad > 0 {
		t.Fatalf("x509: %d of %d cases disagree with the %s model", bad, len(v.X509), x509Model)
	}
	t.Logf("x509: %d cases (%d accepted) agree with the %s model", len(v.X509), accepted, x509Model)
}
