// Copyright 2026 TestifySec, Inc.
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

// Enforcement tests for the #6266 policy-verification hardening flags.
//
// #6276 shipped the loud WARNs for these findings with zero behavior change, and
// the -tags audit detector tests (TestSecurity_R3_181/183/184/185/187/209)
// deliberately stay RED to track that enforcement is NOT the default. This file
// proves the OTHER half: when an embedder opts in via SetHardening, each finding
// is actually enforced (fails closed), and with the default (all-off) options the
// pre-#6266 behavior is preserved. The default remains warn-first per Cole's
// direction on #6266; flipping a HardeningOptions default is the one-line change
// that would make enforcement the default and turn the matching detector green.
//
// R3_201 has no flag (warn-only by design — see hardening.go) so it has no
// enforcement test here; its warning is covered by TestWarn_R3_201.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// withHardening installs hardening options for the duration of the test and
// restores the previous options on cleanup. Like the warn-capture helper in
// warn_first_6266_test.go, tests using it must NOT call t.Parallel(): they mutate
// the package-global hardening options.
func withHardening(t *testing.T, h HardeningOptions) {
	t.Helper()
	prev := Hardening()
	SetHardening(h)
	t.Cleanup(func() { SetHardening(prev) })
}

// makeX509FunctionaryVerifier builds a CA-signed leaf cert with the given subject
// and returns a verifier for it plus the trust bundle keyed "test-root".
func makeX509FunctionaryVerifier(t *testing.T, cn, org string) (cryptoutil.Verifier, map[string]TrustBundle) {
	t.Helper()
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TestCA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	v, err := cryptoutil.NewX509Verifier(leafCert, nil, []*x509.Certificate{caCert}, time.Now())
	if err != nil {
		t.Fatalf("x509 verifier: %v", err)
	}
	return v, map[string]TrustBundle{"test-root": {Root: caCert}}
}

// R3_184: with EnforceCertConstraintOnKeyIDMatch a functionary that pins a
// matching PublicKeyID AND sets a CertConstraint has the constraint enforced
// despite the key-ID match; with the default the constraint is bypassed.
func TestEnforce_R3_184_CertConstraintEnforcedWhenFlagOn(t *testing.T) {
	v, trust := makeX509FunctionaryVerifier(t, "attacker", "EvilCorp")
	keyID, err := v.KeyID()
	if err != nil {
		t.Fatalf("keyid: %v", err)
	}
	// Pins the key AND demands an identity the cert does not have.
	bad := Functionary{
		PublicKeyID: keyID,
		CertConstraint: CertConstraint{
			CommonName:    "builder",
			Organizations: []string{"GoodCorp"},
			Roots:         []string{"test-root"},
		},
	}

	t.Run("default_off_bypasses_TRACKED_by_detector", func(t *testing.T) {
		withHardening(t, HardeningOptions{})
		if err := bad.Validate(v, trust); err != nil {
			t.Fatalf("default (warn-first) must not enforce the constraint; got: %v", err)
		}
	})

	t.Run("flag_on_enforces", func(t *testing.T) {
		withHardening(t, HardeningOptions{EnforceCertConstraintOnKeyIDMatch: true})
		if err := bad.Validate(v, trust); err == nil {
			t.Fatal("expected CertConstraint (CN/Org mismatch) to be enforced when flag on")
		}
	})

	t.Run("flag_on_allows_matching_cert", func(t *testing.T) {
		withHardening(t, HardeningOptions{EnforceCertConstraintOnKeyIDMatch: true})
		good := Functionary{
			PublicKeyID: keyID,
			CertConstraint: CertConstraint{
				CommonName:    "attacker",
				Organizations: []string{"EvilCorp"},
				Roots:         []string{"test-root"},
			},
		}
		if err := good.Validate(v, trust); err != nil {
			t.Fatalf("a cert satisfying the constraint must still pass with flag on: %v", err)
		}
	})

	t.Run("flag_on_nonx509_verifier_fails_closed", func(t *testing.T) {
		withHardening(t, HardeningOptions{EnforceCertConstraintOnKeyIDMatch: true})
		f := Functionary{PublicKeyID: "k", CertConstraint: CertConstraint{Roots: []string{"test-root"}}}
		if err := f.Validate(warnFakeVerifier{id: "k"}, trust); err == nil {
			t.Fatal("a CertConstraint on a non-x509 verifier must fail closed with flag on")
		}
	})
}

// R3_181: with RejectEmptyConstraintEmptyField an empty constraint matched against
// an empty cert field fails closed; with the default it is a no-op pass.
func TestEnforce_R3_181_EmptyConstraintFailsClosedWhenFlagOn(t *testing.T) {
	t.Run("default_off_empty_empty_passes_TRACKED", func(t *testing.T) {
		withHardening(t, HardeningOptions{})
		if err := checkCertConstraint("organization", []string{}, []string{}); err != nil {
			t.Fatalf("default (warn-first) must treat empty+empty as a no-op pass; got: %v", err)
		}
	})
	t.Run("flag_on_empty_empty_fails", func(t *testing.T) {
		withHardening(t, HardeningOptions{RejectEmptyConstraintEmptyField: true})
		if err := checkCertConstraint("organization", []string{}, []string{}); err == nil {
			t.Fatal("expected empty constraint + empty cert field to fail closed when flag on")
		}
	})
	t.Run("flag_on_still_passes_matching_values", func(t *testing.T) {
		withHardening(t, HardeningOptions{RejectEmptyConstraintEmptyField: true})
		if err := checkCertConstraint("organization", []string{"GoodCorp"}, []string{"GoodCorp"}); err != nil {
			t.Fatalf("a satisfied constraint must still pass with flag on: %v", err)
		}
	})
}

// R3_183: with RejectDuplicateRegoPackage two modules sharing a package name are
// rejected; with the default they merge (warn-first).
func TestEnforce_R3_183_DuplicateRegoPackageRejectedWhenFlagOn(t *testing.T) {
	attestor := &marshalableAttestor{AttName: "n", AttType: "https://witness.dev/attestations/test/v0.1"}
	mod := func(pkg string) RegoPolicy {
		return RegoPolicy{
			Name:   pkg + "-module",
			Module: []byte("package " + pkg + "\n\ndeny[msg] {\n\tinput.nonexistent == \"x\"\n\tmsg := \"unreachable\"\n}\n"),
		}
	}

	t.Run("default_off_merges_TRACKED", func(t *testing.T) {
		withHardening(t, HardeningOptions{})
		if err := EvaluateRegoPolicy(attestor, []RegoPolicy{mod("shared"), mod("shared")}); err != nil {
			t.Fatalf("default (warn-first) must merge duplicate packages; got: %v", err)
		}
	})
	t.Run("flag_on_rejects_duplicate", func(t *testing.T) {
		withHardening(t, HardeningOptions{RejectDuplicateRegoPackage: true})
		if err := EvaluateRegoPolicy(attestor, []RegoPolicy{mod("shared"), mod("shared")}); err == nil {
			t.Fatal("expected duplicate rego package name to be rejected when flag on")
		}
	})
	t.Run("flag_on_allows_distinct", func(t *testing.T) {
		withHardening(t, HardeningOptions{RejectDuplicateRegoPackage: true})
		if err := EvaluateRegoPolicy(attestor, []RegoPolicy{mod("alpha"), mod("beta")}); err != nil {
			t.Fatalf("distinct packages must still pass with flag on: %v", err)
		}
	})
}

// R3_185/187/209: with EnforceStepNameCoherence Policy.Validate rejects an empty
// or mismatched step Name at load time; with the default it warns and passes.
func TestEnforce_R3_185_187_209_StepNameCoherenceWhenFlagOn(t *testing.T) {
	empty := Policy{Steps: map[string]Step{"build": {Name: ""}}}
	mismatch := Policy{Steps: map[string]Step{"build": {Name: "compile"}}}
	clean := Policy{Steps: map[string]Step{"build": {Name: "build"}}}

	t.Run("default_off_passes_TRACKED", func(t *testing.T) {
		withHardening(t, HardeningOptions{})
		if err := empty.Validate(); err != nil {
			t.Fatalf("default (warn-first) must not reject empty Name; got: %v", err)
		}
		if err := mismatch.Validate(); err != nil {
			t.Fatalf("default (warn-first) must not reject mismatched Name; got: %v", err)
		}
	})
	t.Run("flag_on_rejects_empty_name", func(t *testing.T) {
		withHardening(t, HardeningOptions{EnforceStepNameCoherence: true})
		err := empty.Validate()
		if err == nil {
			t.Fatal("expected empty step Name to be rejected when flag on")
		}
		if _, ok := err.(ErrStepNameIncoherent); !ok {
			t.Fatalf("expected ErrStepNameIncoherent, got %T: %v", err, err)
		}
	})
	t.Run("flag_on_rejects_mismatch", func(t *testing.T) {
		withHardening(t, HardeningOptions{EnforceStepNameCoherence: true})
		if err := mismatch.Validate(); err == nil {
			t.Fatal("expected mismatched step Name to be rejected when flag on")
		}
	})
	t.Run("flag_on_allows_coherent", func(t *testing.T) {
		withHardening(t, HardeningOptions{EnforceStepNameCoherence: true})
		if err := clean.Validate(); err != nil {
			t.Fatalf("a coherent policy must still validate with flag on: %v", err)
		}
	})
}
