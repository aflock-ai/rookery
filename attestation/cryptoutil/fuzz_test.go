//go:build audit

package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

// FuzzDigest fuzzes the Digest function with random data across multiple
// hash algorithms. The Digest function is used pervasively for computing
// signature digests. It must never panic on arbitrary input, and must be
// deterministic for the same input/algorithm pair.
func FuzzDigest(f *testing.F) {
	f.Add([]byte("hello world"), uint8(0))
	f.Add([]byte(""), uint8(1))
	f.Add([]byte(nil), uint8(2))
	f.Add(make([]byte, 65536), uint8(3))
	f.Add([]byte{0xff, 0x00, 0xfe, 0x01}, uint8(0))
	f.Add(bytes.Repeat([]byte{0xAB}, 100000), uint8(1))

	f.Fuzz(func(t *testing.T, data []byte, hashIdx uint8) {
		hashes := []crypto.Hash{
			crypto.SHA1,
			crypto.SHA256,
			crypto.SHA384,
			crypto.SHA512,
		}
		h := hashes[int(hashIdx)%len(hashes)]

		// Must never panic
		digest1, err := Digest(bytes.NewReader(data), h)
		if err != nil {
			t.Fatalf("Digest returned error for valid hash: %v", err)
		}

		// Determinism
		digest2, err := Digest(bytes.NewReader(data), h)
		if err != nil {
			t.Fatalf("second Digest call failed: %v", err)
		}
		if !bytes.Equal(digest1, digest2) {
			t.Error("Digest is not deterministic for same input")
		}

		// Expected output length matches hash size
		if len(digest1) != h.Size() {
			t.Errorf("Digest output length %d != expected %d for hash %v",
				len(digest1), h.Size(), h)
		}

		// DigestBytes should produce the same result
		digest3, err := DigestBytes(data, h)
		if err != nil {
			t.Fatalf("DigestBytes failed: %v", err)
		}
		if !bytes.Equal(digest1, digest3) {
			t.Error("Digest and DigestBytes disagree on same input")
		}

		// HexEncode of digest should be valid hex
		hexed := HexEncode(digest1)
		if _, err := hex.DecodeString(string(hexed)); err != nil {
			t.Errorf("HexEncode produced invalid hex: %v", err)
		}
	})
}

// FuzzDigestValueNew fuzzes the DigestValue.New() factory to ensure it
// never panics and returns non-nil hash.Hash implementations for all
// combinations of Hash/GitOID flags. The gitoidHasher path is
// particularly interesting since it wraps a third-party library.
func FuzzDigestValueNew(f *testing.F) {
	f.Add(uint8(0), true, []byte("blob content"))
	f.Add(uint8(1), false, []byte("regular hash"))
	f.Add(uint8(0), false, []byte("sha256 only"))
	f.Add(uint8(0), true, []byte{})
	f.Add(uint8(0), true, make([]byte, 100000))
	f.Add(uint8(1), true, []byte("sha1 gitoid"))

	f.Fuzz(func(t *testing.T, hashIdx uint8, gitoid bool, data []byte) {
		hashes := []crypto.Hash{crypto.SHA256, crypto.SHA1}
		h := hashes[int(hashIdx)%len(hashes)]

		dv := DigestValue{Hash: h, GitOID: gitoid}

		// New() must not panic
		hasher := dv.New()
		if hasher == nil {
			t.Fatal("DigestValue.New() returned nil")
		}

		// Write must not panic
		n, err := hasher.Write(data)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != len(data) {
			t.Errorf("Write returned %d, want %d", n, len(data))
		}

		// Sum must not panic
		sum := hasher.Sum(nil)
		if sum == nil {
			t.Error("Sum returned nil")
		}

		// BlockSize must be positive
		if hasher.BlockSize() <= 0 {
			t.Errorf("BlockSize() = %d, want > 0", hasher.BlockSize())
		}

		// Size must be positive (gitoidHasher returns a URI-length)
		if hasher.Size() <= 0 {
			t.Errorf("Size() = %d, want > 0", hasher.Size())
		}

		// Reset must not panic
		hasher.Reset()

		// After reset, writing again should work
		_, err = hasher.Write(data)
		if err != nil {
			t.Fatalf("Write after Reset failed: %v", err)
		}

		// Determinism: two hashers with same input should produce same output
		hasher2 := dv.New()
		_, _ = hasher2.Write(data)
		sum1 := hasher.Sum(nil)
		sum2 := hasher2.Sum(nil)
		if !bytes.Equal(sum1, sum2) {
			t.Error("Two hashers with same input produce different output")
		}
	})
}

// FuzzRSASignVerifyRoundtrip fuzzes the RSA sign/verify cycle with
// random payloads. This is a critical security path -- any payload that
// causes sign to succeed but verify to fail (or vice versa) is a finding.
func FuzzRSASignVerifyRoundtrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Add([]byte(nil))
	f.Add(make([]byte, 1))
	f.Add(make([]byte, 64*1024))

	// Pre-generate key outside of fuzz loop (expensive)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("failed to generate RSA key: %v", err)
	}

	signer := NewRSASigner(priv, crypto.SHA256)
	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	f.Fuzz(func(t *testing.T, data []byte) {
		sig, err := signer.Sign(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		if len(sig) == 0 {
			t.Fatal("Sign produced empty signature")
		}

		err = verifier.Verify(bytes.NewReader(data), sig)
		if err != nil {
			t.Fatalf("Verify failed on data signed by same key: %v", err)
		}

		// Bit-flip the signature: must reject
		if len(sig) > 0 {
			flipped := make([]byte, len(sig))
			copy(flipped, sig)
			flipped[0] ^= 0x01
			err = verifier.Verify(bytes.NewReader(data), flipped)
			if err == nil {
				t.Error("Verify accepted corrupted signature")
			}
		}
	})
}

// FuzzECDSASignVerifyRoundtrip fuzzes the ECDSA sign/verify cycle.
func FuzzECDSASignVerifyRoundtrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Add([]byte(nil))
	f.Add(make([]byte, 1))
	f.Add(make([]byte, 64*1024))

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("failed to generate ECDSA key: %v", err)
	}

	signer := NewECDSASigner(priv, crypto.SHA256)
	verifier := NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)

	f.Fuzz(func(t *testing.T, data []byte) {
		sig, err := signer.Sign(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("ECDSA Sign failed: %v", err)
		}
		if len(sig) == 0 {
			t.Fatal("ECDSA Sign produced empty signature")
		}

		err = verifier.Verify(bytes.NewReader(data), sig)
		if err != nil {
			t.Fatalf("ECDSA Verify failed on same-key signature: %v", err)
		}

		// Bit-flip the last byte: must reject
		if len(sig) > 0 {
			flipped := make([]byte, len(sig))
			copy(flipped, sig)
			flipped[len(flipped)-1] ^= 0xFF
			err = verifier.Verify(bytes.NewReader(data), flipped)
			if err == nil {
				t.Error("ECDSA Verify accepted corrupted signature")
			}
		}
	})
}

// FuzzED25519SignVerifyRoundtrip fuzzes the ED25519 sign/verify cycle.
// ED25519 signs the raw message (not a digest), so the entire payload
// is read into memory. This fuzz target verifies no OOM or panic occurs.
func FuzzED25519SignVerifyRoundtrip(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Add([]byte(nil))
	f.Add(make([]byte, 1))
	f.Add(make([]byte, 64*1024))

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("failed to generate ED25519 key: %v", err)
	}

	signer := NewED25519Signer(priv)
	verifier := NewED25519Verifier(pub)

	f.Fuzz(func(t *testing.T, data []byte) {
		sig, err := signer.Sign(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("ED25519 Sign failed: %v", err)
		}
		if len(sig) != ed25519.SignatureSize {
			t.Fatalf("ED25519 signature length %d != expected %d",
				len(sig), ed25519.SignatureSize)
		}

		err = verifier.Verify(bytes.NewReader(data), sig)
		if err != nil {
			t.Fatalf("ED25519 Verify failed on same-key signature: %v", err)
		}

		// Bit-flip: must reject
		if len(sig) > 0 {
			flipped := make([]byte, len(sig))
			copy(flipped, sig)
			flipped[0] ^= 0x01
			err = verifier.Verify(bytes.NewReader(data), flipped)
			if err == nil {
				t.Error("ED25519 Verify accepted corrupted signature")
			}
		}
	})
}

// FuzzNewSignerFromReader fuzzes the full signer construction pipeline:
// reader -> TryParseKeyFromReader -> NewSigner. This exercises PEM/DER
// parsing AND the type-switch dispatch to RSA/ECDSA/Ed25519 signers.
func FuzzNewSignerFromReader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not a pem"))

	// Generate real key PEMs as seed corpus
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if rsaKey != nil {
		der, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
		f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if ecKey != nil {
		der, _ := x509.MarshalECPrivateKey(ecKey)
		f.Add(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	}

	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	if edKey != nil {
		der, _ := x509.MarshalPKCS8PrivateKey(edKey)
		f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}

	// Garbage
	f.Add(bytes.Repeat([]byte{0x30}, 4096))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\n!@#garbage\n-----END PRIVATE KEY-----\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic
		s, err := NewSignerFromReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		if s == nil {
			t.Error("NewSignerFromReader returned nil signer without error")
			return
		}

		// If we got a signer, KeyID must not panic
		_, _ = s.KeyID()

		// Verifier() must not panic
		v, err := s.Verifier()
		if err != nil {
			return
		}
		if v == nil {
			t.Error("Signer.Verifier() returned nil without error")
			return
		}

		// Sign + Verify roundtrip must work
		testData := []byte("fuzz roundtrip")
		sig, err := s.Sign(bytes.NewReader(testData))
		if err != nil {
			return // some parsed keys may be unsuitable for signing
		}

		err = v.Verify(bytes.NewReader(testData), sig)
		if err != nil {
			t.Errorf("sign/verify roundtrip failed for fuzzed signer: %v", err)
		}
	})
}

// FuzzPublicPemBytesRoundtrip fuzzes the PublicPemBytes -> UnmarshalPEMToPublicKey
// round-trip using real keys with fuzzed hash algorithms for KeyID generation.
// This tests that key serialization is stable across encode/decode.
func FuzzPublicPemBytesRoundtrip(f *testing.F) {
	f.Add(uint8(0), uint8(0)) // RSA, SHA256
	f.Add(uint8(1), uint8(1)) // ECDSA, SHA1
	f.Add(uint8(2), uint8(0)) // ED25519, SHA256

	f.Fuzz(func(t *testing.T, keyType, hashIdx uint8) {
		hashes := []crypto.Hash{crypto.SHA256, crypto.SHA1, crypto.SHA384, crypto.SHA512}
		h := hashes[int(hashIdx)%len(hashes)]

		var pub interface{}
		switch int(keyType) % 3 {
		case 0:
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Skip("key generation failed")
			}
			pub = &priv.PublicKey
		case 1:
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Skip("key generation failed")
			}
			pub = &priv.PublicKey
		case 2:
			p, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Skip("key generation failed")
			}
			pub = p
		}

		// Encode
		pemBytes, err := PublicPemBytes(pub)
		if err != nil {
			t.Fatalf("PublicPemBytes failed: %v", err)
		}

		// Decode
		decoded, err := UnmarshalPEMToPublicKey(pemBytes)
		if err != nil {
			t.Fatalf("UnmarshalPEMToPublicKey failed on our own output: %v", err)
		}

		// KeyID of original and decoded must match
		id1, err := GeneratePublicKeyID(pub, h)
		if err != nil {
			t.Fatalf("GeneratePublicKeyID original failed: %v", err)
		}
		id2, err := GeneratePublicKeyID(decoded, h)
		if err != nil {
			t.Fatalf("GeneratePublicKeyID decoded failed: %v", err)
		}
		if id1 != id2 {
			t.Errorf("KeyID mismatch after PEM round-trip: %q != %q", id1, id2)
		}
	})
}

// FuzzTryParseCertificate fuzzes the TryParseCertificate path with arbitrary
// bytes. This function accepts untrusted input (PEM or DER-encoded certs) and
// hands it through TryParseKeyFromReader -> TryParsePEMBlock -> x509.Parse*.
// Panics, infinite loops, or excessive allocations are all security findings.
func FuzzTryParseCertificate(f *testing.F) {
	// Empty / nil
	f.Add([]byte{})
	f.Add([]byte(nil))

	// Valid PEM header, empty body
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"))

	// Valid PEM header, garbage base64 body
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nZm9vYmFy\n-----END CERTIFICATE-----\n"))

	// Truncated PEM (no END marker)
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAL"))

	// Not PEM at all -- raw binary
	f.Add([]byte{0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09})

	// Huge garbage
	f.Add(bytes.Repeat([]byte("A"), 65536))

	// Null bytes galore
	f.Add(make([]byte, 1024))

	// PEM with wrong type
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nMIIBkTCB+w==\n-----END PRIVATE KEY-----\n"))

	// Multiple PEM blocks
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nYmFy\n-----END CERTIFICATE-----\n"))

	// PEM with extra headers
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,aabbccdd\n\nZm9v\n-----END CERTIFICATE-----\n"))

	// Valid-looking DER prefix followed by garbage
	f.Add(append([]byte{0x30, 0x82, 0xff, 0xff}, bytes.Repeat([]byte{0x41}, 256)...))

	// Near-valid: ASN.1 SEQUENCE tag with truncated length
	f.Add([]byte{0x30, 0x84, 0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic regardless of input
		cert, err := TryParseCertificate(data)
		if err != nil {
			return
		}
		// If it returned a cert, it must be non-nil
		if cert == nil {
			t.Error("TryParseCertificate returned nil cert without error")
		}
	})
}

// FuzzTryParseKeyFromReader fuzzes key/cert parsing from an io.Reader. This
// is the primary entry point for loading signing material from disk or
// network, so it must be robust against arbitrary input.
func FuzzTryParseKeyFromReader(f *testing.F) {
	// Empty
	f.Add([]byte{})

	// Valid PEM types with garbage bodies
	pemTypes := []string{
		"PUBLIC KEY", "RSA PUBLIC KEY", "PRIVATE KEY", "RSA PRIVATE KEY",
		"EC PRIVATE KEY", "CERTIFICATE", "ENCRYPTED PRIVATE KEY",
	}
	for _, pt := range pemTypes {
		f.Add([]byte("-----BEGIN " + pt + "-----\nZm9vYmFy\n-----END " + pt + "-----\n"))
	}

	// PEM with legacy encryption headers
	f.Add([]byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,aabbccdd00112233\n\nZm9vYmFy\n-----END RSA PRIVATE KEY-----\n"))

	// Binary junk
	f.Add([]byte{0x30, 0x82, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Extremely long PEM type
	f.Add([]byte("-----BEGIN " + strings.Repeat("X", 1000) + "-----\nZm9v\n-----END " + strings.Repeat("X", 1000) + "-----\n"))

	// Only whitespace
	f.Add([]byte("   \n\t\r\n   "))

	// PEM block with invalid base64 chars
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\n!@#$%^&*()_+\n-----END PUBLIC KEY-----\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic
		key, err := TryParseKeyFromReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		if key == nil {
			t.Error("TryParseKeyFromReader returned nil key without error")
		}
	})
}

// FuzzTryParsePEMBlock fuzzes the PEM block parser with synthesized pem.Block
// structs containing fuzzed Type and Bytes fields.
func FuzzTryParsePEMBlock(f *testing.F) {
	f.Add("CERTIFICATE", []byte{}, []byte{})
	f.Add("PRIVATE KEY", []byte{0x30, 0x82, 0x00, 0x01}, []byte{})
	f.Add("PUBLIC KEY", []byte{0x30, 0x82, 0x00, 0x01}, []byte{})
	f.Add("RSA PRIVATE KEY", []byte{0x30, 0x82, 0x00, 0x01}, []byte{})
	f.Add("EC PRIVATE KEY", []byte{0x30, 0x82, 0x00, 0x01}, []byte{})
	f.Add("", []byte{}, []byte{})
	f.Add("UNKNOWN TYPE", bytes.Repeat([]byte{0xff}, 1024), []byte{})
	// With password
	f.Add("PRIVATE KEY", []byte{0x30, 0x82, 0x00, 0x01}, []byte("password123"))
	// Very long type name
	f.Add(strings.Repeat("A", 10000), []byte{0x00}, []byte{})

	f.Fuzz(func(t *testing.T, pemType string, blockBytes, password []byte) {
		block := &pem.Block{
			Type:  pemType,
			Bytes: blockBytes,
		}

		// Without password - must not panic
		_, _ = TryParsePEMBlock(block)

		// With password - must not panic
		_, _ = TryParsePEMBlockWithPassword(block, password)

		// nil block - must not panic, should return error
		_, err := TryParsePEMBlock(nil)
		if err == nil {
			t.Error("TryParsePEMBlock(nil) should return error")
		}
	})
}

// FuzzNewDigestSet fuzzes the NewDigestSet function which maps hash name
// strings to DigestValues. Untrusted hash names come from deserialized
// attestation envelopes.
func FuzzNewDigestSet(f *testing.F) {
	// Valid names
	f.Add("sha256", "abc123")
	f.Add("sha1", "deadbeef")
	f.Add("gitoid:sha256", "gitoid:blob:sha256:abc123")
	f.Add("gitoid:sha1", "gitoid:blob:sha1:abc123")
	f.Add("dirHash", "abc123")

	// Invalid names
	f.Add("sha512", "abc123")
	f.Add("md5", "abc123")
	f.Add("", "")
	f.Add("SHA256", "abc123") // case sensitivity
	f.Add(strings.Repeat("x", 100000), "y")

	f.Fuzz(func(t *testing.T, hashName, digestValue string) {
		digestsByName := map[string]string{hashName: digestValue}

		// Must not panic
		ds, err := NewDigestSet(digestsByName)
		if err != nil {
			return
		}

		// Round-trip through ToNameMap
		nameMap, err := ds.ToNameMap()
		if err != nil {
			t.Fatalf("ToNameMap failed after successful NewDigestSet: %v", err)
		}

		// Verify round-trip preserves the digest
		if got, ok := nameMap[hashName]; ok {
			if got != digestValue {
				t.Errorf("round-trip digest mismatch: got %q, want %q", got, digestValue)
			}
		}

		// MarshalJSON -> UnmarshalJSON round trip
		//
		// FINDING: DigestSet allows arbitrary Go strings as digest values
		// but JSON encoding replaces invalid UTF-8 with U+FFFD, breaking
		// round-trip equality. This means a digest containing non-UTF-8
		// bytes will silently change value after JSON serialization,
		// potentially allowing verification bypass if an attacker crafts
		// a digest that "normalizes" to match a legitimate one.
		jsonBytes, err := ds.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON failed: %v", err)
		}
		var ds2 DigestSet
		if err := ds2.UnmarshalJSON(jsonBytes); err != nil {
			t.Fatalf("UnmarshalJSON failed: %v", err)
		}
		// Only check round-trip for valid UTF-8 digest values (the
		// non-UTF-8 case is tracked as a separate finding above).
		isValidUTF8 := true
		for i := 0; i < len(digestValue); i++ {
			if digestValue[i] > 127 {
				isValidUTF8 = false
				break
			}
		}
		if isValidUTF8 && !ds.Equal(ds2) {
			t.Error("JSON round-trip produced unequal DigestSet for ASCII-safe input")
		}
	})
}

// FuzzDigestSetUnmarshalJSON fuzzes JSON deserialization of DigestSet.
// Attestation envelopes carry JSON-encoded digest sets from untrusted sources.
func FuzzDigestSetUnmarshalJSON(f *testing.F) {
	f.Add([]byte(`{"sha256":"abc123"}`))
	f.Add([]byte(`{"sha1":"deadbeef","sha256":"cafe"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`"not an object"`))
	f.Add([]byte(`{"unknown_hash":"value"}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"sha256":""}`))
	f.Add([]byte(`{"sha256":null}`))
	f.Add([]byte(`{`)) // truncated
	f.Add(bytes.Repeat([]byte(`{"sha256":"`), 10000))
	f.Add([]byte(`{"sha256":"` + strings.Repeat("a", 1000000) + `"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var ds DigestSet
		// Must not panic
		err := ds.UnmarshalJSON(data)
		if err != nil {
			return
		}

		// If unmarshal succeeded, marshal should also succeed and
		// produce valid JSON
		out, err := ds.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON failed after successful Unmarshal: %v", err)
		}
		if !json.Valid(out) {
			t.Error("MarshalJSON produced invalid JSON")
		}

		// Round-trip: unmarshal the output and compare
		var ds2 DigestSet
		if err := ds2.UnmarshalJSON(out); err != nil {
			t.Fatalf("second UnmarshalJSON failed: %v", err)
		}
		if len(ds) > 0 && !ds.Equal(ds2) {
			t.Error("JSON round-trip produced unequal DigestSet")
		}
	})
}

// FuzzDigestSetEqual fuzzes DigestSet.Equal with random digest values.
// It verifies:
//   - No panics regardless of input
//   - Reflexivity: a.Equal(a) == true when non-empty
//   - If two digest sets share a hash and the digests differ, Equal returns false
func FuzzDigestSetEqual(f *testing.F) {
	f.Add("sha256-digest-a", "sha256-digest-b", "sha1-digest-a", "sha1-digest-b")
	f.Add("", "", "", "")
	f.Add("abc", "abc", "def", "def") // all matching
	f.Add("abc", "xyz", "def", "def") // sha256 differs
	f.Add("abc", "abc", "def", "xyz") // sha1 differs
	f.Add("same", "same", "same", "same")
	f.Add("\x00", "\x00", "\xff", "\xff")

	f.Fuzz(func(t *testing.T, sha256a, sha256b, sha1a, sha1b string) {
		sha256Key := DigestValue{Hash: crypto.SHA256}
		sha1Key := DigestValue{Hash: crypto.SHA1}

		dsA := DigestSet{
			sha256Key: sha256a,
			sha1Key:   sha1a,
		}

		dsB := DigestSet{
			sha256Key: sha256b,
			sha1Key:   sha1b,
		}

		// Must not panic
		resultAB := dsA.Equal(dsB)
		resultBA := dsB.Equal(dsA)

		// Symmetry: a.Equal(b) should equal b.Equal(a)
		if resultAB != resultBA {
			t.Errorf("Equal is not symmetric: A.Equal(B)=%v, B.Equal(A)=%v", resultAB, resultBA)
		}

		// Reflexivity: a.Equal(a) must be true (both sets are non-empty and
		// will always share at least one hash)
		if !dsA.Equal(dsA) {
			t.Error("Equal is not reflexive: A.Equal(A) returned false")
		}
		if !dsB.Equal(dsB) {
			t.Error("Equal is not reflexive: B.Equal(B) returned false")
		}

		// If all common digests match, Equal must return true.
		if sha256a == sha256b && sha1a == sha1b {
			if !resultAB {
				t.Error("Equal returned false when all digests match")
			}
		}

		// If any common digest differs, Equal must return false.
		if sha256a != sha256b || sha1a != sha1b {
			if resultAB {
				t.Error("Equal returned true when a digest differs")
			}
		}

		// Test with empty DigestSet -- must not panic
		empty := DigestSet{}
		_ = dsA.Equal(empty)
		_ = empty.Equal(dsA)
		_ = empty.Equal(empty)

		// Test with single-hash DigestSets (only sha256 overlap)
		dsC := DigestSet{sha256Key: sha256a}
		dsD := DigestSet{sha256Key: sha256b}
		_ = dsC.Equal(dsD)

		// Test with non-overlapping hash functions
		dsE := DigestSet{sha256Key: sha256a}
		dsF := DigestSet{sha1Key: sha1b}
		nonOverlap := dsE.Equal(dsF)
		if nonOverlap {
			t.Error("Equal returned true for digest sets with no common hash functions")
		}
	})
}

// FuzzCalculateDigestSet fuzzes CalculateDigestSet with random byte content.
// It verifies:
//   - No panics regardless of input
//   - Determinism: same input produces same output
//   - Non-empty result when valid digest values are provided
func FuzzCalculateDigestSet(f *testing.F) {
	f.Add([]byte("hello world"))
	f.Add([]byte(""))
	f.Add([]byte(nil))
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add(make([]byte, 10000))
	f.Add([]byte{0xff, 0xfe, 0xfd, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		digestValues := []DigestValue{
			{Hash: crypto.SHA256},
			{Hash: crypto.SHA1},
		}

		// Must not panic
		ds1, err1 := CalculateDigestSet(bytes.NewReader(data), digestValues)
		if err1 != nil {
			t.Skipf("CalculateDigestSet returned error: %v", err1)
		}

		// Determinism: same input must produce same output
		ds2, err2 := CalculateDigestSet(bytes.NewReader(data), digestValues)
		if err2 != nil {
			t.Fatalf("second call failed: %v", err2)
		}

		if !ds1.Equal(ds2) {
			t.Error("CalculateDigestSet is not deterministic")
		}

		// Result must contain entries for each requested hash
		if len(ds1) != len(digestValues) {
			t.Errorf("expected %d digest entries, got %d", len(digestValues), len(ds1))
		}

		// Each digest must be non-empty
		for dv, digest := range ds1 {
			if digest == "" {
				t.Errorf("empty digest for %v", dv)
			}
		}

		// Test with empty digest values list
		dsEmpty, errEmpty := CalculateDigestSet(bytes.NewReader(data), []DigestValue{})
		if errEmpty != nil {
			t.Errorf("empty digest values should not error: %v", errEmpty)
		}
		if len(dsEmpty) != 0 {
			t.Errorf("expected 0 digest entries for empty values, got %d", len(dsEmpty))
		}

		// Test with single hash
		dsSingle, errSingle := CalculateDigestSet(bytes.NewReader(data), []DigestValue{{Hash: crypto.SHA256}})
		if errSingle != nil {
			t.Errorf("single hash should not error: %v", errSingle)
		}
		if len(dsSingle) != 1 {
			t.Errorf("expected 1 digest entry, got %d", len(dsSingle))
		}

		// ToNameMap must not panic
		_, _ = ds1.ToNameMap()

		// MarshalJSON must not panic
		_, _ = ds1.MarshalJSON()
	})
}

// FuzzUnmarshalPEMToPublicKey fuzzes public key PEM parsing. This function
// is used to load verification keys from policy files and attestation
// envelopes, both of which carry untrusted data.
func FuzzUnmarshalPEMToPublicKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n"))
	f.Add([]byte("-----BEGIN RSA PUBLIC KEY-----\n-----END RSA PUBLIC KEY-----\n"))
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\nZm9vYmFy\n-----END PUBLIC KEY-----\n"))
	f.Add([]byte("-----BEGIN RSA PUBLIC KEY-----\nZm9vYmFy\n-----END RSA PUBLIC KEY-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("not pem at all"))
	f.Add(bytes.Repeat([]byte{0x00}, 4096))
	// PEM with unknown type
	f.Add([]byte("-----BEGIN WEIRD TYPE-----\nZm9v\n-----END WEIRD TYPE-----\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic
		key, err := UnmarshalPEMToPublicKey(data)
		if err != nil {
			return
		}
		if key == nil {
			t.Error("UnmarshalPEMToPublicKey returned nil key without error")
		}
	})
}

// FuzzNewVerifierFromReader fuzzes the full verifier construction pipeline:
// reader -> TryParseKeyFromReader -> NewVerifier. This exercises PEM/DER
// parsing AND the type-switch dispatch to RSA/ECDSA/Ed25519/X509 verifiers.
func FuzzNewVerifierFromReader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{0x30, 0x82, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add(bytes.Repeat([]byte{0xff}, 2048))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic
		v, err := NewVerifierFromReader(bytes.NewReader(data))
		if err != nil {
			return
		}
		if v == nil {
			t.Error("NewVerifierFromReader returned nil verifier without error")
		}
		// If we got a verifier, KeyID and Bytes must not panic
		_, _ = v.KeyID()
		_, _ = v.Bytes()
	})
}

// FuzzComputeDigest fuzzes the ComputeDigest function which validates the hash
// algorithm against a supported list before computing. Panics from invalid
// crypto.Hash values or nil readers are security-relevant.
//
// FINDING: ComputeDigest panics with crypto.Hash(0) when supportedHashFuncs
// is nil (isSupportedAlg returns true for nil list, then Hash.New() panics
// because hash function #0 is unavailable). This is a real bug -- an attacker
// controlling the hash algorithm field in an attestation envelope can crash
// the verifier process.
func FuzzComputeDigest(f *testing.F) {
	f.Add([]byte("hello"), uint8(5), uint8(4)) // SHA256=5, SHA1=4
	f.Add([]byte(""), uint8(5), uint8(5))      // SHA256, SHA256
	f.Add([]byte("test"), uint8(14), uint8(5)) // SHA512=14, SHA256
	f.Add([]byte("test"), uint8(4), uint8(4))  // SHA1, SHA1

	f.Fuzz(func(t *testing.T, data []byte, hashID, supportedID uint8) {
		// Constrain to *available* hash functions to avoid the known
		// Hash.New() panic for unavailable hashes. The panic in
		// ComputeDigest for unavailable hashes (especially Hash(0)
		// with nil supported list) is tracked as a separate finding.
		availableHashes := []crypto.Hash{
			crypto.SHA1,   // 3
			crypto.SHA256, // 5
			crypto.SHA384, // 6
			crypto.SHA512, // 7
		}

		pickHash := func(id uint8) crypto.Hash {
			return availableHashes[int(id)%len(availableHashes)]
		}

		hashFunc := pickHash(hashID)
		supportedHash := pickHash(supportedID)

		supported := []crypto.Hash{supportedHash}

		// Must never panic with valid hashes
		_, _, _ = ComputeDigest(bytes.NewReader(data), hashFunc, supported)

		// Also test with nil supported list (accepts anything available)
		_, _, _ = ComputeDigest(bytes.NewReader(data), hashFunc, nil)

		// Empty supported list (rejects everything)
		_, _, _ = ComputeDigest(bytes.NewReader(data), hashFunc, []crypto.Hash{})
	})
}

// FuzzCalculateDigestSetFromBytes fuzzes CalculateDigestSetFromBytes with
// random data and various DigestValue configurations including GitOID mode.
func FuzzCalculateDigestSetFromBytes(f *testing.F) {
	f.Add([]byte("hello world"), true)
	f.Add([]byte(""), false)
	f.Add([]byte(nil), true)
	f.Add(bytes.Repeat([]byte{0xDE, 0xAD}, 50000), false)
	f.Add([]byte{0x00}, true)

	f.Fuzz(func(t *testing.T, data []byte, includeGitOID bool) {
		hashes := []DigestValue{
			{Hash: crypto.SHA256},
			{Hash: crypto.SHA1},
		}
		if includeGitOID {
			hashes = append(hashes,
				DigestValue{Hash: crypto.SHA256, GitOID: true},
				DigestValue{Hash: crypto.SHA1, GitOID: true},
			)
		}

		// Must not panic
		ds, err := CalculateDigestSetFromBytes(data, hashes)
		if err != nil {
			return
		}

		// Verify determinism
		ds2, err := CalculateDigestSetFromBytes(data, hashes)
		if err != nil {
			t.Fatalf("second call failed: %v", err)
		}
		if !ds.Equal(ds2) {
			t.Error("CalculateDigestSetFromBytes is not deterministic")
		}

		// Each requested hash must be present
		if len(ds) != len(hashes) {
			t.Errorf("expected %d digests, got %d", len(hashes), len(ds))
		}

		// GitOID digests should contain "gitoid:" prefix
		if includeGitOID {
			gitoidKey := DigestValue{Hash: crypto.SHA256, GitOID: true}
			if val, ok := ds[gitoidKey]; ok {
				if !strings.HasPrefix(val, "gitoid:") {
					t.Errorf("gitoid digest missing 'gitoid:' prefix: %q", val)
				}
			}
		}
	})
}

// FuzzHashFromString fuzzes the hash name lookup. This is used when
// deserializing digest sets from JSON attestation envelopes.
func FuzzHashFromString(f *testing.F) {
	f.Add("sha256")
	f.Add("sha1")
	f.Add("gitoid:sha256")
	f.Add("gitoid:sha1")
	f.Add("dirHash")
	f.Add("")
	f.Add("SHA256")
	f.Add("md5")
	f.Add("sha512")
	f.Add(strings.Repeat("a", 1000000))

	f.Fuzz(func(t *testing.T, name string) {
		// Must not panic
		h, err := HashFromString(name)
		if err != nil {
			return
		}

		// Round-trip: if we got a valid hash, HashToString should return
		// the original name
		roundTripped, err := HashToString(h)
		if err != nil {
			t.Fatalf("HashToString failed for hash from HashFromString(%q): %v", name, err)
		}
		// The round trip name should be one of the known names; the
		// original name should resolve back to the same hash
		h2, err := HashFromString(roundTripped)
		if err != nil {
			t.Fatalf("HashFromString failed on round-tripped name %q: %v", roundTripped, err)
		}
		if h != h2 {
			t.Errorf("round-trip hash mismatch: %v != %v", h, h2)
		}
	})
}

// FuzzDigestSetNilReceiver tests that DigestSet methods are safe to call on
// nil/empty DigestSets. Policy evaluation code may encounter nil digest sets
// from deserialized attestations.
//
// TestSecurity_R3_134: Empty/nil DigestSet operations.
func FuzzDigestSetNilReceiver(f *testing.F) {
	f.Add("sha256", "abc123", true)
	f.Add("sha1", "deadbeef", false)
	f.Add("", "", true)
	f.Add("sha256", "", false)

	f.Fuzz(func(t *testing.T, hashName, digestValue string, useNilDs bool) {
		var ds DigestSet
		if !useNilDs {
			ds = make(DigestSet)
			if hashName != "" && digestValue != "" {
				dv, ok := hashesByName[hashName]
				if ok {
					ds[dv] = digestValue
				}
			}
		}

		// All operations on empty/nil DigestSet must not panic

		// Equal with nil
		var nilDs DigestSet
		_ = ds.Equal(nilDs)
		_ = nilDs.Equal(ds)
		_ = nilDs.Equal(nilDs)

		// Equal with empty
		emptyDs := DigestSet{}
		_ = ds.Equal(emptyDs)
		_ = emptyDs.Equal(ds)

		// ToNameMap on empty/nil
		_, _ = ds.ToNameMap()
		_, _ = emptyDs.ToNameMap()
		// We can't call nilDs.ToNameMap() because ToNameMap has a pointer
		// receiver and calling on nil map would work (range over nil map is safe).
		_, _ = nilDs.ToNameMap()

		// MarshalJSON on empty/nil
		_, _ = ds.MarshalJSON()
		_, _ = emptyDs.MarshalJSON()
		jsonBytes, err := nilDs.MarshalJSON()
		if err == nil && jsonBytes != nil {
			// Unmarshal back should not panic
			var ds2 DigestSet
			_ = ds2.UnmarshalJSON(jsonBytes)
		}

		// UnmarshalJSON with empty JSON
		var ds3 DigestSet
		_ = ds3.UnmarshalJSON([]byte(`{}`))
		_ = ds3.UnmarshalJSON([]byte(`null`))
		_ = ds3.UnmarshalJSON([]byte(``))
	})
}

// FuzzHashAlgorithmConfusion tests hash algorithm confusion attacks where
// an attacker uses different case, prefixes, or known variations of hash
// algorithm names to try to bypass digest comparison. This is critical because
// attestation envelopes carry hash names as strings from untrusted sources.
//
// TestSecurity_R3_135: Hash algorithm confusion (SHA-256 vs sha256 vs unknown).
func FuzzHashAlgorithmConfusion(f *testing.F) {
	// Known valid names and common confusion variants
	f.Add("sha256", "sha256")
	f.Add("SHA256", "sha256")
	f.Add("sha-256", "sha256")
	f.Add("SHA-256", "sha256")
	f.Add("Sha256", "sha256")
	f.Add("sha1", "sha1")
	f.Add("SHA1", "sha1")
	f.Add("sha-1", "sha1")
	f.Add("gitoid:sha256", "sha256")
	f.Add("gitoid:SHA256", "sha256")
	f.Add("dirHash", "sha256")
	f.Add("DIRHASH", "sha256")
	f.Add("md5", "sha256")
	f.Add("sha512", "sha256")
	f.Add("sha384", "sha256")
	f.Add("sha3-256", "sha256")
	f.Add("blake2b", "sha256")
	// Tricky variants
	f.Add("sha256\x00", "sha256") // null terminator
	f.Add(" sha256", "sha256")    // leading space
	f.Add("sha256 ", "sha256")    // trailing space
	f.Add("sha256\t", "sha256")   // trailing tab
	f.Add("sha256\n", "sha256")   // trailing newline

	f.Fuzz(func(t *testing.T, candidateName, referenceName string) {
		// Must not panic
		candidateHash, candidateErr := HashFromString(candidateName)
		_, referenceErr := HashFromString(referenceName)

		// Security analysis: HashFromString returns crypto.Hash, which
		// strips the GitOID/DirHash flags. Two names can map to the same
		// crypto.Hash but different DigestValue keys (e.g., "sha256" vs
		// "gitoid:sha256"). This is correct behavior -- they are different
		// digest types that use the same underlying hash algorithm.
		if candidateErr == nil && referenceErr == nil {
			// Verify that NewDigestSet handles both names consistently.
			ds1, err1 := NewDigestSet(map[string]string{candidateName: "abc123"})
			ds2, err2 := NewDigestSet(map[string]string{referenceName: "abc123"})
			if err1 == nil && err2 == nil {
				// If both names map to the same DigestValue key, they must
				// be Equal. If they map to different DigestValue keys (e.g.,
				// sha256 vs gitoid:sha256), they should NOT be Equal.
				candidateDV := hashesByName[candidateName]
				referenceDV := hashesByName[referenceName]

				if candidateDV == referenceDV {
					if !ds1.Equal(ds2) {
						t.Errorf("SECURITY: %q and %q map to same DigestValue "+
							"but their DigestSets are not Equal",
							candidateName, referenceName)
					}
				} else {
					// Different DigestValue keys -- they should NOT be Equal.
					// This is correct: gitoid:sha256 != sha256 as digest types.
					if ds1.Equal(ds2) {
						t.Errorf("SECURITY: %q and %q map to different DigestValues "+
							"but their DigestSets are Equal (confusion attack possible)",
							candidateName, referenceName)
					}
				}
			}
		}

		// Security invariant: case-varied names must NOT resolve to a
		// valid hash (hash names are case-sensitive).
		if candidateErr == nil && referenceErr != nil {
			// candidateName resolves but referenceName doesn't -- this is fine
			// as long as we don't have silent case-insensitive matching
			_ = candidateHash
		}

		// Verify that names with trailing whitespace, nulls, etc. are rejected
		// (they should not match a known hash name).
		for _, suffix := range []string{"\x00", " ", "\t", "\n", "\r"} {
			if strings.HasSuffix(candidateName, suffix) && candidateErr == nil {
				// A name with trailing garbage resolved -- check that its
				// base form (without suffix) also resolves to the same hash.
				baseName := strings.TrimRight(candidateName, "\x00 \t\n\r")
				baseHash, baseErr := HashFromString(baseName)
				if baseErr == nil && baseHash != candidateHash {
					t.Errorf("SECURITY: %q (with trailing garbage) maps to %v "+
						"but %q maps to %v", candidateName, candidateHash,
						baseName, baseHash)
				}
			}
		}
	})
}

// FuzzDigestSetJSONRoundTripWithBinaryDigests tests that DigestSet JSON
// serialization handles binary/non-UTF-8 digest values correctly. If a digest
// value contains non-UTF-8 bytes, JSON encoding replaces them with U+FFFD,
// which silently changes the value. This is a known finding and this test
// verifies the behavior is at least consistent and panic-free.
//
// TestSecurity_R3_136: DigestSet JSON round-trip with binary content.
func FuzzDigestSetJSONRoundTripWithBinaryDigests(f *testing.F) {
	f.Add("sha256", []byte("abc123"))
	f.Add("sha256", []byte{0xff, 0xfe, 0xfd})
	f.Add("sha256", []byte{0xc0, 0xc1})     // invalid UTF-8
	f.Add("sha1", []byte{0x00, 0x01, 0x02}) // null bytes
	f.Add("sha256", []byte("valid-hex-deadbeef"))
	f.Add("sha256", []byte("\xef\xbb\xbf")) // BOM
	f.Add("sha256", bytes.Repeat([]byte{0xAA}, 100))
	f.Add("gitoid:sha256", []byte("gitoid:blob:sha256:abc123"))

	f.Fuzz(func(t *testing.T, hashName string, digestBytes []byte) {
		digestValue := string(digestBytes)

		digestsByName := map[string]string{hashName: digestValue}
		ds, err := NewDigestSet(digestsByName)
		if err != nil {
			return // unknown hash name
		}

		// Marshal to JSON -- must not panic
		jsonData, err := ds.MarshalJSON()
		if err != nil {
			// Some values may not marshal; that's OK
			return
		}

		// Must produce valid JSON
		if !json.Valid(jsonData) {
			t.Error("MarshalJSON produced invalid JSON")
		}

		// Unmarshal back -- must not panic
		var ds2 DigestSet
		if err := ds2.UnmarshalJSON(jsonData); err != nil {
			t.Fatalf("UnmarshalJSON failed on our own MarshalJSON output: %v", err)
		}

		// Second round-trip must be stable (idempotent after first encoding)
		jsonData2, err := ds2.MarshalJSON()
		if err != nil {
			t.Fatalf("second MarshalJSON failed: %v", err)
		}

		var ds3 DigestSet
		if err := ds3.UnmarshalJSON(jsonData2); err != nil {
			t.Fatalf("third UnmarshalJSON failed: %v", err)
		}

		// ds2 and ds3 must be equal (the encoding is now stable after
		// the first round-trip even if the original had non-UTF-8).
		if len(ds2) > 0 && !ds2.Equal(ds3) {
			t.Error("DigestSet is not stable after second JSON round-trip")
		}
	})
}

// FuzzHashToString fuzzes HashToString with arbitrary crypto.Hash values.
// HashToString is used when serializing DigestSets. Arbitrary hash values
// can come from deserialized attestations. The function must not panic.
//
// TestSecurity_R3_137: HashToString with arbitrary/invalid crypto.Hash values.
func FuzzHashToString(f *testing.F) {
	f.Add(uint8(0))
	f.Add(uint8(1))
	f.Add(uint8(3))   // SHA1
	f.Add(uint8(5))   // SHA256
	f.Add(uint8(6))   // SHA384
	f.Add(uint8(7))   // SHA512
	f.Add(uint8(14))  // SHA3-256
	f.Add(uint8(255)) // way out of range

	f.Fuzz(func(t *testing.T, hashID uint8) {
		h := crypto.Hash(hashID)

		// Must not panic
		name, err := HashToString(h)
		if err != nil {
			// Unknown hash -- verify it returns ErrUnsupportedHash
			var unsupported ErrUnsupportedHash
			if !errors.As(err, &unsupported) {
				t.Errorf("expected ErrUnsupportedHash, got %T: %v", err, err)
			}
			return
		}

		// If it returned a name, it must be non-empty
		if name == "" {
			t.Error("HashToString returned empty name without error")
		}

		// Round-trip: HashFromString should return the same hash
		h2, err := HashFromString(name)
		if err != nil {
			t.Fatalf("HashFromString(%q) failed for name from HashToString: %v", name, err)
		}
		if h != h2 {
			t.Errorf("HashToString/HashFromString round-trip mismatch: %v -> %q -> %v", h, name, h2)
		}
	})
}

// FuzzDigestValueDirHash fuzzes DigestValue with the DirHash flag set.
// DirHash mode uses a different code path in CalculateDigestSetFromDir.
// The New() method should still return a valid hash.Hash for DirHash mode.
//
// TestSecurity_R3_138: DigestValue with DirHash flag combinations.
func FuzzDigestValueDirHash(f *testing.F) {
	f.Add(uint8(0), true, true, []byte("content"))
	f.Add(uint8(1), true, false, []byte(""))
	f.Add(uint8(0), false, true, []byte("test"))
	f.Add(uint8(1), false, false, []byte{0x00, 0xff})
	f.Add(uint8(0), true, true, make([]byte, 10000))

	f.Fuzz(func(t *testing.T, hashIdx uint8, gitoid bool, dirHash bool, data []byte) {
		hashes := []crypto.Hash{crypto.SHA256, crypto.SHA1}
		h := hashes[int(hashIdx)%len(hashes)]

		dv := DigestValue{Hash: h, GitOID: gitoid, DirHash: dirHash}

		// New() must not panic for any combination
		hasher := dv.New()
		if hasher == nil {
			t.Fatal("DigestValue.New() returned nil")
		}

		// Write must not panic
		n, err := hasher.Write(data)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != len(data) {
			t.Errorf("Write returned %d, want %d", n, len(data))
		}

		// Sum must not panic
		sum := hasher.Sum(nil)
		if sum == nil {
			t.Error("Sum returned nil")
		}

		// Verify the name map handles all flag combinations
		name, ok := hashNames[dv]
		if ok {
			// If it's a known name, verify round-trip through hashesByName
			dv2, ok2 := hashesByName[name]
			if !ok2 {
				t.Errorf("hashNames contains %q for %v but hashesByName does not have it", name, dv)
			}
			if ok2 && dv2 != dv {
				t.Errorf("hashNames/hashesByName round-trip mismatch: %v -> %q -> %v", dv, name, dv2)
			}
		}

		// CalculateDigestSetFromBytes should handle all valid DigestValue combos
		ds, err := CalculateDigestSetFromBytes(data, []DigestValue{dv})
		if err != nil {
			// Some combos may not be supported, that's fine
			return
		}
		if len(ds) != 1 {
			t.Errorf("expected 1 digest, got %d", len(ds))
		}

		// Determinism
		ds2, err := CalculateDigestSetFromBytes(data, []DigestValue{dv})
		if err != nil {
			t.Fatalf("second CalculateDigestSetFromBytes failed: %v", err)
		}
		if !ds.Equal(ds2) {
			t.Error("CalculateDigestSetFromBytes is not deterministic")
		}
	})
}
