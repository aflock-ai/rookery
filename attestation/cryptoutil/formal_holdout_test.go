//go:build formalholdout

// jade:ring local

package cryptoutil

// Holdout for formal/signing-trust (#9917): third-party vectors the model and
// the code were NOT tuned against, run after both were final. Nothing
// downloaded is committed; point FORMAL_HOLDOUT_DIR at a directory holding
//
//	limbo.json                     C2SP/x509-limbo
//	ecdsa_p256_sha256.json         C2SP/wycheproof testvectors_v1/ecdsa_secp256r1_sha256_test.json
//	rsa_pkcs1_2048_sha256.json     .../rsa_signature_2048_sha256_test.json
//	rsa_pss_2048_sha256_32.json    .../rsa_pss_2048_sha256_mgf1_32_test.json
//
// and run: go test -tags formalholdout -run TestFormalHoldout -v ./cryptoutil/
//
// It reports counts; it asserts nothing, because a holdout disagreement is a
// finding to classify, not a test failure.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func holdoutDir(t *testing.T) string {
	d := os.Getenv("FORMAL_HOLDOUT_DIR")
	if d == "" {
		t.Skip("FORMAL_HOLDOUT_DIR not set")
	}
	return d
}

type limboCase struct {
	ID                     string   `json:"id"`
	Features               []string `json:"features"`
	TrustedCerts           []string `json:"trusted_certs"`
	UntrustedIntermediates []string `json:"untrusted_intermediates"`
	PeerCertificate        string   `json:"peer_certificate"`
	ValidationTime         *string  `json:"validation_time"`
	ExtendedKeyUsage       []string `json:"extended_key_usage"`
	ExpectedResult         string   `json:"expected_result"`
	ExpectedPeerName       *struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	} `json:"expected_peer_name"`
	ExpectedPeerNames []json.RawMessage `json:"expected_peer_names"`
	MaxChainDepth     *int              `json:"max_chain_depth"`
}

func pemCerts(t *testing.T, ps []string) ([]*x509.Certificate, bool) {
	var out []*x509.Certificate
	for _, p := range ps {
		b, _ := pem.Decode([]byte(p))
		if b == nil {
			return nil, false
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, false
		}
		out = append(out, c)
	}
	return out, true
}

var limboEKU = map[string]x509.ExtKeyUsage{
	"serverAuth": x509.ExtKeyUsageServerAuth, "clientAuth": x509.ExtKeyUsageClientAuth,
	"codeSigning": x509.ExtKeyUsageCodeSigning, "timeStamping": x509.ExtKeyUsageTimeStamping,
	"emailProtection": x509.ExtKeyUsageEmailProtection, "OCSPSigning": x509.ExtKeyUsageOCSPSigning,
	"anyExtendedKeyUsage": x509.ExtKeyUsageAny,
}

// pathVerify is the signing-trust verifier with the purpose swapped for the
// case's EKU (the path logic only): the leaf profile (not a CA, keyUsage
// permits signing) plus Go's chain check.
func pathVerify(leaf *x509.Certificate, inters, roots []*x509.Certificate, at time.Time, ekus []x509.ExtKeyUsage, profile bool) error {
	if profile {
		v := &X509Verifier{cert: leaf}
		if err := v.checkSigningLeaf(); err != nil {
			return err
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots: certificatesToPool(roots), Intermediates: certificatesToPool(inters), CurrentTime: at, KeyUsages: ekus,
	})
	return err
}

func TestFormalHoldoutLimbo(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(holdoutDir(t), "limbo.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Testcases []limboCase `json:"testcases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	skipped := map[string]int{}
	type tally struct{ agree, falseAccept, falseReject int }
	var profileT, pathT, goT, codeT tally
	falseAccepts := map[string][]string{}
	falseRejectPrefix := map[string]int{}
	ran := 0
	for _, c := range doc.Testcases {
		switch {

		case c.MaxChainDepth != nil:
			skipped["max_chain_depth (Go exposes no depth limit)"]++
			continue
		case slices_contains(c.Features, "has-crl"):
			skipped["CRL (no revocation in this verifier; known, #9842)"]++
			continue
		}
		roots, ok1 := pemCerts(t, c.TrustedCerts)
		inters, ok2 := pemCerts(t, c.UntrustedIntermediates)
		leafs, ok3 := pemCerts(t, []string{c.PeerCertificate})
		if !ok1 || !ok2 || !ok3 {
			skipped["unparseable certificate (Go's parser refuses it; counts as reject)"]++
			continue
		}
		at := time.Now()
		if c.ValidationTime != nil {
			if at, err = time.Parse(time.RFC3339, *c.ValidationTime); err != nil {
				t.Fatal(err)
			}
		}
		var ekus []x509.ExtKeyUsage
		for _, e := range c.ExtendedKeyUsage {
			if k, ok := limboEKU[e]; ok {
				ekus = append(ekus, k)
			}
		}
		if len(ekus) == 0 {
			ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}
		ran++
		want := c.ExpectedResult == "SUCCESS"
		score := func(tl *tally, got bool, name string) {
			switch {
			case got == want:
				tl.agree++
			case got:
				tl.falseAccept++
				if name != "" {
					falseAccepts[name] = append(falseAccepts[name], c.ID)
				}
			default:
				tl.falseReject++
				if name == "path" {
					p := c.ID
					for i := 0; i < len(p); i++ {
						if p[i] == ':' {
							p = p[:i]
							break
						}
					}
					falseRejectPrefix[p]++
				}
			}
		}
		score(&pathT, pathVerify(leafs[0], inters, roots, at, ekus, true) == nil, "path")
		score(&goT, pathVerify(leafs[0], inters, roots, at, ekus, false) == nil, "go")
		v := &X509Verifier{cert: leafs[0]}
		// The shipped verifier over a signature it cannot check: only the
		// certificate checks decide, so compare on those.
		profileErr := v.checkSigningLeaf()
		if profileErr == nil {
			_, profileErr = leafs[0].Verify(x509.VerifyOptions{Roots: certificatesToPool(roots), Intermediates: certificatesToPool(inters), CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
		}
		score(&profileT, profileErr == nil, "")
		_ = codeT
	}
	keys := make([]string, 0, len(skipped))
	for k := range skipped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("limbo: %d cases, %d run", len(doc.Testcases), ran)
	for _, k := range keys {
		t.Logf("  skipped %d: %s", skipped[k], k)
	}
	t.Logf("  path logic (case EKU, signing-leaf profile): agree %d, accepted-but-FAILURE %d, rejected-but-SUCCESS %d", pathT.agree, pathT.falseAccept, pathT.falseReject)
	t.Logf("  plain Go x509 (case EKU, no profile):       agree %d, accepted-but-FAILURE %d, rejected-but-SUCCESS %d", goT.agree, goT.falseAccept, goT.falseReject)
	t.Logf("  shipped profile (codeSigning EKU):          agree %d, accepted-but-FAILURE %d, rejected-but-SUCCESS %d", profileT.agree, profileT.falseAccept, profileT.falseReject)
	fap := map[string]int{}
	for _, id := range falseAccepts["path"] {
		p := id
		if i := len(p); i > 0 {
			// namespace::feature::case -> namespace::feature
			n := 0
			for j := 0; j < len(p); j++ {
				if p[j] == ':' && j+1 < len(p) && p[j+1] == ':' {
					n++
					if n == 2 {
						p = p[:j]
						break
					}
				}
			}
		}
		fap[p]++
	}
	fk := make([]string, 0, len(fap))
	for k := range fap {
		fk = append(fk, k)
	}
	sort.Strings(fk)
	for _, k := range fk {
		t.Logf("  path accepted FAILURE cases in %s: %d", k, fap[k])
	}
	pk := make([]string, 0, len(falseRejectPrefix))
	for k := range falseRejectPrefix {
		pk = append(pk, k)
	}
	sort.Strings(pk)
	for _, k := range pk {
		t.Logf("  path rejected SUCCESS cases in %s: %d", k, falseRejectPrefix[k])
	}
}

func slices_contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

type wycheGroup struct {
	PublicKeyDer string `json:"publicKeyDer"`
	Tests        []struct {
		TcID   int      `json:"tcId"`
		Msg    string   `json:"msg"`
		Sig    string   `json:"sig"`
		Result string   `json:"result"`
		Flags  []string `json:"flags"`
	} `json:"tests"`
}

func runWyche(t *testing.T, file string, mk func(pub crypto.PublicKey) Verifier) {
	raw, err := os.ReadFile(filepath.Join(holdoutDir(t), file))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		TestGroups []wycheGroup `json:"testGroups"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var validOK, validBad, invalidOK, invalidBad, accAcc, accRej int
	var bad []string
	for _, g := range doc.TestGroups {
		der, _ := hex.DecodeString(g.PublicKeyDer)
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatalf("%s: public key: %v", file, err)
		}
		v := mk(pub)
		for _, tc := range g.Tests {
			msg, _ := hex.DecodeString(tc.Msg)
			sig, _ := hex.DecodeString(tc.Sig)
			ok := v.Verify(bytes.NewReader(msg), sig) == nil
			switch tc.Result {
			case "valid":
				if ok {
					validOK++
				} else {
					validBad++
					bad = append(bad, "valid rejected tc"+itoa(tc.TcID))
				}
			case "invalid":
				if ok {
					invalidBad++
					bad = append(bad, "invalid accepted tc"+itoa(tc.TcID)+" "+joinFlags(tc.Flags))
				} else {
					invalidOK++
				}
			default:
				if ok {
					accAcc++
				} else {
					accRej++
				}
			}
		}
	}
	t.Logf("%s: valid accepted %d, valid REJECTED %d, invalid rejected %d, invalid ACCEPTED %d, acceptable accepted %d / rejected %d",
		file, validOK, validBad, invalidOK, invalidBad, accAcc, accRej)
	for _, b := range bad {
		t.Logf("  %s", b)
	}
}

func itoa(n int) string { return fmtInt(n) }

func fmtInt(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func joinFlags(f []string) string {
	s := ""
	for i, x := range f {
		if i > 0 {
			s += ","
		}
		s += x
	}
	return s
}

func TestFormalHoldoutWycheproof(t *testing.T) {
	runWyche(t, "ecdsa_p256_sha256.json", func(pub crypto.PublicKey) Verifier {
		return NewECDSAVerifier(pub.(*ecdsa.PublicKey), crypto.SHA256)
	})
	runWyche(t, "rsa_pss_2048_sha256_32.json", func(pub crypto.PublicKey) Verifier {
		return NewRSAVerifier(pub.(*rsa.PublicKey), crypto.SHA256)
	})
	runWyche(t, "rsa_pkcs1_2048_sha256.json", func(pub crypto.PublicKey) Verifier {
		return NewRSAVerifierWithOptions(pub.(*rsa.PublicKey), crypto.SHA256, WithPKCS1v15Fallback())
	})
}
