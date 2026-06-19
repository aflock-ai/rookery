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

package yubipiv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
)

// Fixtures captured from a real YubiKey 5Ci (serial 17770230, firmware 5.4.3),
// PIV slot 9c generated with pin-policy=ONCE, touch-policy=ALWAYS:
//   testdata/leaf-9c.pem          - the slot 9c attestation certificate
//   testdata/intermediate-f9.pem  - the device f9 attestation certificate
//   testdata/yubico-piv-root.pem  - the Yubico PIV Root CA (also embedded)

func loadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return c
}

func realChain(t *testing.T) (leaf, intermediate *x509.Certificate) {
	t.Helper()
	return loadCert(t, "testdata/leaf-9c.pem"), loadCert(t, "testdata/intermediate-f9.pem")
}

// TestVerify_RealYubiKey verifies the full chain against the EMBEDDED Yubico
// root and asserts every parsed field matches the physical device.
func TestVerify_RealYubiKey(t *testing.T) {
	leaf, inter := realChain(t)
	att, err := Verify(leaf, inter)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if att.Serial != 17770230 {
		t.Errorf("Serial = %d, want 17770230", att.Serial)
	}
	if att.Firmware != "5.4.3" {
		t.Errorf("Firmware = %q, want 5.4.3", att.Firmware)
	}
	if att.PINPolicy != PINPolicyOnce {
		t.Errorf("PINPolicy = %s, want once", att.PINPolicy)
	}
	if att.TouchPolicy != TouchPolicyAlways {
		t.Errorf("TouchPolicy = %s, want always", att.TouchPolicy)
	}
	if err := att.RequireTouchAlways(); err != nil {
		t.Errorf("RequireTouchAlways on a touch=ALWAYS key: %v", err)
	}
	if att.PublicKey == nil {
		t.Error("attested PublicKey not exposed")
	}
	if !att.MatchesPublicKey(leaf.PublicKey) {
		t.Error("MatchesPublicKey(leaf.PublicKey) = false, want true")
	}
}

// TestVerify_WrongRoot_Fails: an empty/foreign root pool must reject the chain
// (proves trust is anchored to the Yubico root, not just structural parsing).
func TestVerify_WrongRoot_Fails(t *testing.T) {
	leaf, inter := realChain(t)
	if att, err := VerifyWithRoots(leaf, inter, x509.NewCertPool()); err == nil {
		t.Fatalf("expected chain failure with empty root pool, got %+v", att)
	}
}

// TestVerify_MissingIntermediate_Fails: without the genuine f9 intermediate the
// leaf cannot chain to the root.
func TestVerify_MissingIntermediate_Fails(t *testing.T) {
	leaf, _ := realChain(t)
	if _, err := Verify(leaf, leaf); err == nil {
		t.Fatal("expected failure when the intermediate is not the f9 attestation cert")
	}
}

// TestVerify_TamperedLeaf_Fails: flipping a signature byte must break the chain.
func TestVerify_TamperedLeaf_Fails(t *testing.T) {
	leaf, inter := realChain(t)
	// Re-parse a tampered copy: corrupt the last signature byte.
	der := append([]byte(nil), leaf.Raw...)
	der[len(der)-1] ^= 0xff
	tampered, err := x509.ParseCertificate(der)
	if err != nil {
		// A parse failure is also an acceptable (fail-closed) outcome.
		return
	}
	if _, err := Verify(tampered, inter); err == nil {
		t.Fatal("expected chain failure for a tampered leaf signature")
	}
}

// TestVerify_NonYubicoCert_Fails: a self-signed cert that is not a Yubico
// attestation must not verify (and would not parse the policy extension).
func TestVerify_NonYubicoCert_Fails(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "not-a-yubikey"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(c, c); err == nil {
		t.Fatal("expected failure for a non-Yubico self-signed cert")
	}
}

// TestRequireTouchAlways_Gate exercises the gate logic on synthetic policies
// (covers the negative case we have no hardware fixture for).
func TestRequireTouchAlways_Gate(t *testing.T) {
	cases := []struct {
		tp      TouchPolicy
		wantErr bool
	}{
		{TouchPolicyAlways, false},
		{TouchPolicyNever, true},
		{TouchPolicyCached, true},
		{TouchPolicy(0x00), true},
	}
	for _, c := range cases {
		err := (&Attestation{TouchPolicy: c.tp}).RequireTouchAlways()
		if (err != nil) != c.wantErr {
			t.Errorf("TouchPolicy %s: err=%v, wantErr=%v", c.tp, err, c.wantErr)
		}
	}
}

// TestMatchesPublicKey_Negative: a different key must not match the attestation.
func TestMatchesPublicKey_Negative(t *testing.T) {
	leaf, inter := realChain(t)
	att, err := Verify(leaf, inter)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if att.MatchesPublicKey(&other.PublicKey) {
		t.Error("MatchesPublicKey(unrelated key) = true, want false")
	}
	if att.MatchesPublicKey(nil) {
		t.Error("MatchesPublicKey(nil) = true, want false")
	}
}

func TestEmbeddedRootParses(t *testing.T) {
	pool, err := yubicoRoots()
	if err != nil {
		t.Fatalf("yubicoRoots: %v", err)
	}
	if pool == nil {
		t.Fatal("nil root pool")
	}
}
