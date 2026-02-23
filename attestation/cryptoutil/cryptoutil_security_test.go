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

package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ==========================================================================
// R3-250: CalculateDigestSetFromFile follows symlinks, enabling path traversal
//
// os.Open follows symlinks transparently. A symlink pointing to
// /etc/shadow (or any sensitive file) will be opened and hashed without
// any warning or check. The isHashableFile function does check for
// ModeSymlink, but because os.Open follows symlinks, f.Stat() returns
// the TARGET's mode, not the symlink's. The ModeSymlink branch in
// isHashableFile is dead code.
//
// Severity: MEDIUM -- in supply chain attestation, an attacker who can
// place a symlink in a build directory can cause sensitive file content
// to be included in attestation digests, leaking information about the
// host or causing digest mismatches.
// ==========================================================================

func TestSecurity_R3_250_CalculateDigestSetFromFile_FollowsSymlinks(t *testing.T) {
	// Create a real file
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "target.txt")
	if err := os.WriteFile(targetFile, []byte("secret content"), 0644); err != nil {
		t.Fatalf("failed to write target file: %v", err)
	}

	// Create a symlink to it from a separate directory
	attackDir := filepath.Join(tmpDir, "attack")
	if err := os.Mkdir(attackDir, 0755); err != nil {
		t.Fatalf("failed to create attack dir: %v", err)
	}
	symlinkPath := filepath.Join(attackDir, "innocent.txt")
	if err := os.Symlink(targetFile, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// CalculateDigestSetFromFile should hash the symlink target's content
	// without any check that we are following a symlink. This is the
	// current (vulnerable) behavior.
	hashes := []DigestValue{{Hash: crypto.SHA256}}
	dsSymlink, err := CalculateDigestSetFromFile(symlinkPath, hashes)
	if err != nil {
		t.Fatalf("CalculateDigestSetFromFile on symlink failed: %v", err)
	}
	dsTarget, err := CalculateDigestSetFromFile(targetFile, hashes)
	if err != nil {
		t.Fatalf("CalculateDigestSetFromFile on target failed: %v", err)
	}

	// The digests match because the symlink was transparently followed.
	if !dsSymlink.Equal(dsTarget) {
		t.Fatalf("expected symlink and target to produce identical digests")
	}

	// Verify the ModeSymlink check in isHashableFile is dead code
	f, err := os.Open(symlinkPath)
	if err != nil {
		t.Fatalf("failed to open symlink: %v", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		t.Fatalf("failed to stat opened symlink: %v", err)
	}

	if stat.Mode()&os.ModeSymlink != 0 {
		t.Fatal("unexpected: f.Stat() on opened symlink returned ModeSymlink")
	}
	t.Log("CONFIRMED: os.Open follows symlinks, so f.Stat() returns target's mode. " +
		"The ModeSymlink check in isHashableFile (line 287) is dead code. " +
		"CalculateDigestSetFromFile transparently follows symlinks with no restriction.")
}

// ==========================================================================
// R3-251: isHashableFile mode.Perm().IsDir() is dead code
//
// os.FileMode.Perm() returns only the lower 9 permission bits (rwxrwxrwx).
// os.FileMode.IsDir() checks the ModeDir bit (bit 31). Since Perm() strips
// ModeDir, Perm().IsDir() is ALWAYS false. Directories fall through to
// "return false, nil" and are silently treated as not hashable.
//
// The code clearly intended to check mode.IsDir() (without Perm()).
//
// Severity: LOW -- CalculateDigestSetFromDir exists for directories, so
// this is a correctness bug rather than a security vulnerability.
// ==========================================================================

func TestSecurity_R3_251_IsHashableFile_PermIsDirAlwaysFalse(t *testing.T) {
	// Verify the bug: mode.Perm().IsDir() is always false.
	dirMode := os.ModeDir | os.FileMode(0755)
	if dirMode.Perm().IsDir() {
		t.Fatal("expected mode.Perm().IsDir() to be false, but it was true")
	}
	if !dirMode.IsDir() {
		t.Fatal("expected mode.IsDir() to be true for a directory mode")
	}

	// Now verify with a real directory
	tmpDir := t.TempDir()
	f, err := os.Open(tmpDir)
	if err != nil {
		t.Fatalf("failed to open tmpdir: %v", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}
	if !stat.Mode().IsDir() {
		t.Fatal("tmpdir should have IsDir() == true")
	}
	if stat.Mode().Perm().IsDir() {
		t.Fatal("tmpdir mode.Perm().IsDir() should be false (this is the bug)")
	}

	// Demonstrate the consequence: isHashableFile returns false for directories
	hashable, err := isHashableFile(f)
	if err != nil {
		t.Fatalf("isHashableFile returned error: %v", err)
	}
	// A directory is not IsRegular(), Perm().IsDir() is always false,
	// and ModeSymlink is not set. So it returns false.
	if hashable {
		t.Fatal("expected isHashableFile to return false for directory due to Perm().IsDir() bug")
	}
	t.Log("CONFIRMED: isHashableFile returns false for directories because " +
		"mode.Perm().IsDir() is always false. Fix: use mode.IsDir() instead of mode.Perm().IsDir().")
}

// ==========================================================================
// R3-252: DigestSet.Equal allows hash algorithm downgrade -- additional
// edge case: attacker crafts a DigestSet with ONLY a weak hash that
// collides, while the legitimate set has both weak and strong.
//
// The existing test (R3-128) documents the core bug. This test adds the
// specific scenario where an attacker exploits this in a two-step policy
// by controlling one step's output artifacts.
//
// Additionally: Equal() does not validate that digest strings look like
// valid hex-encoded hashes. An empty string digest is accepted.
//
// Severity: MEDIUM -- weakest-common-hash semantics
// ==========================================================================

func TestSecurity_R3_252_DigestSetEqual_EmptyStringDigestBypass(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}

	// Both sets have SHA256 with empty string digests.
	// This is semantically meaningless but Equal() says they match.
	ds1 := DigestSet{sha256Key: ""}
	ds2 := DigestSet{sha256Key: ""}

	if !ds1.Equal(ds2) {
		t.Fatal("expected Equal to return true for matching empty digests")
	}

	// An attacker who can inject an empty digest into one step's output
	// can match any other step that also has an empty digest for the same hash.
	// There's no validation that digest values are non-empty or well-formed hex.
	t.Log("SECURITY NOTE: DigestSet.Equal accepts empty string digests as valid matches. " +
		"No validation that digest values are non-empty or valid hex. " +
		"An empty-string digest matching another empty-string digest passes Equal().")
}

func TestSecurity_R3_252_DigestSetEqual_MixedGitOIDAndPlainDowngrade(t *testing.T) {
	sha256Plain := DigestValue{Hash: crypto.SHA256, GitOID: false}
	sha256GitOID := DigestValue{Hash: crypto.SHA256, GitOID: true}
	sha1Plain := DigestValue{Hash: crypto.SHA1, GitOID: false}

	// Legitimate set: sha256 plain + sha256 gitoid
	legit := DigestSet{
		sha256Plain:  "aaa111",
		sha256GitOID: "gitoid:blob:sha256:bbb222",
	}

	// Attacker set: only sha1 plain, which the legitimate set doesn't have.
	// This returns false (no common hash). Good.
	attacker := DigestSet{
		sha1Plain: "ccc333",
	}
	if legit.Equal(attacker) {
		t.Fatal("no common hash should return false")
	}

	// But if attacker adds a matching sha256Plain and omits gitoid:
	attacker2 := DigestSet{
		sha256Plain: "aaa111", // matches
		// omits sha256GitOID entirely
	}
	if !legit.Equal(attacker2) {
		t.Fatal("expected Equal to return true since sha256Plain matches")
	}
	t.Log("CONFIRMED: Attacker can omit gitoid:sha256 entry while matching " +
		"only the plain sha256. Equal() returns true because it only checks " +
		"hash algorithms present in BOTH sets.")
}

// ==========================================================================
// R3-253: RSA key size not validated -- no minimum key strength enforced
//
// NewRSASigner and NewRSAVerifier accept any RSA key size including
// dangerously small ones. In a supply chain security context, accepting
// 1024-bit (or even smaller) RSA keys undermines the integrity guarantees.
//
// NIST deprecated 1024-bit RSA in 2013. Keys below 2048 bits should be
// rejected or at minimum trigger a warning.
//
// Severity: MEDIUM -- the code silently accepts weak keys
// ==========================================================================

func TestSecurity_R3_253_RSA_WeakKeySize_1024_Accepted(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate 1024-bit RSA key: %v", err)
	}

	signer := NewRSASigner(priv, crypto.SHA256)
	data := []byte("signed with weak 1024-bit key")
	sig, err := signer.Sign(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Sign with 1024-bit key failed: %v", err)
	}

	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	err = verifier.Verify(bytes.NewReader(data), sig)
	if err != nil {
		t.Fatalf("Verify with 1024-bit key failed: %v", err)
	}

	t.Logf("SECURITY BUG R3-253: 1024-bit RSA key accepted without warning. "+
		"Key size: %d bits. NIST deprecated 1024-bit RSA in 2013. "+
		"Supply chain attestations signed with weak keys can be forged.",
		priv.PublicKey.N.BitLen())
}

func TestSecurity_R3_253_RSA_SHA1_Hash_Accepted(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// SHA1 is considered broken for collision resistance since 2017 (SHAttered).
	// The code does not prevent its use.
	signer := NewRSASigner(priv, crypto.SHA1)
	data := []byte("signed with SHA1 hash")
	sig, err := signer.Sign(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Sign with SHA1 failed: %v", err)
	}

	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA1)
	err = verifier.Verify(bytes.NewReader(data), sig)
	if err != nil {
		t.Fatalf("Verify with SHA1 failed: %v", err)
	}

	t.Log("SECURITY NOTE R3-253: RSA signing with SHA1 hash is accepted. " +
		"SHA1 collision attacks are practical (SHAttered, 2017). " +
		"Consider rejecting SHA1 for signing operations.")
}

// ==========================================================================
// R3-254: RSA PKCS1v15 fallback is a silent signature scheme downgrade
//
// RSAVerifier.Verify first tries PSS, then falls back to PKCS1v15 with
// only a log.Warn. This means an attacker who can intercept and re-sign
// with PKCS1v15 will have the signature accepted. PKCS1v15 is vulnerable
// to Bleichenbacher-style attacks, and the fallback means the verifier
// does not enforce the expected signature scheme.
//
// The comment says "AWS KMS may sign with PKCS1v15 instead of PSS" but
// the fallback is unconditional -- it applies to ALL RSA verification,
// not just AWS KMS contexts.
//
// Severity: MEDIUM -- silent security downgrade on every RSA verification
// ==========================================================================

func TestSecurity_R3_254_RSA_PKCS1v15_FallbackAccepted(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// The PSS signer produces PSS signatures.
	// Create a PKCS1v15 signature manually.
	data := []byte("test PKCS1v15 fallback")
	digest, err := Digest(bytes.NewReader(data), crypto.SHA256)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	pkcs1Sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("SignPKCS1v15 failed: %v", err)
	}

	// The verifier should accept this via fallback even though PSS is the
	// expected scheme.
	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	err = verifier.Verify(bytes.NewReader(data), pkcs1Sig)
	if err != nil {
		t.Fatalf("PKCS1v15 signature was rejected: %v", err)
	}

	t.Log("SECURITY BUG R3-254: RSAVerifier.Verify silently accepts PKCS1v15 " +
		"signatures as a fallback when PSS verification fails. This is an " +
		"unconditional security downgrade. The fallback should be opt-in, " +
		"not a default behavior on every RSA verification.")
}

func TestSecurity_R3_254_RSA_PKCS1v15_FallbackWrongKeyStillRejects(t *testing.T) {
	// Verify the fallback doesn't break wrong-key rejection.
	priv1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key 1: %v", err)
	}
	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key 2: %v", err)
	}

	data := []byte("wrong key test")
	digest, err := Digest(bytes.NewReader(data), crypto.SHA256)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	// Sign with key1 using PKCS1v15
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv1, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("SignPKCS1v15 failed: %v", err)
	}

	// Verify with key2 -- both PSS and PKCS1v15 should fail
	verifier := NewRSAVerifier(&priv2.PublicKey, crypto.SHA256)
	err = verifier.Verify(bytes.NewReader(data), sig)
	if err == nil {
		t.Fatal("CRITICAL: wrong key with PKCS1v15 signature was accepted!")
	}
}

// ==========================================================================
// R3-255: ED25519 Verify reads entire message into memory -- DoS vector
//
// Unlike RSA and ECDSA which hash-then-verify, ED25519 must sign the raw
// message. Both ED25519Signer.Sign and ED25519Verifier.Verify call
// io.ReadAll(r) which reads the ENTIRE message into memory. With a
// malicious io.Reader that produces unbounded data, this causes OOM.
//
// In contrast, RSA/ECDSA use Digest() which streams through hash.Hash
// without buffering the entire message.
//
// Severity: LOW-MEDIUM -- requires attacker to control the data reader
// passed to Verify/Sign, which is typically under application control.
// But if user-supplied payloads are signed, this is exploitable.
// ==========================================================================

func TestSecurity_R3_255_ED25519_ReadsEntireMessage(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ED25519 key: %v", err)
	}

	// Demonstrate that ED25519Verifier calls io.ReadAll.
	// We use a LimitedReader to show it reads everything.
	// A real attacker could use an io.Reader that never returns io.EOF.
	largeData := make([]byte, 5*1024*1024) // 5 MB
	if _, err := rand.Read(largeData); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	verifier := NewED25519Verifier(pub)
	// This will read all 5MB into memory, then fail signature verification.
	err = verifier.Verify(bytes.NewReader(largeData), make([]byte, 64))
	if err == nil {
		t.Fatal("expected verification to fail with random signature")
	}

	t.Log("SECURITY NOTE R3-255: ED25519Verifier.Verify uses io.ReadAll " +
		"which buffers the entire message in memory. Unlike RSA/ECDSA which " +
		"stream through a hash function, ED25519 must read all data. " +
		"No size limit is enforced. An io.Reader producing unbounded data " +
		"will cause OOM.")
}

// ==========================================================================
// R3-256: TryParseKeyFromReader silently ignores subsequent PEM blocks
//
// When given input with multiple PEM blocks (e.g., a certificate chain),
// TryParseKeyFromReader only parses the FIRST block and silently discards
// the rest. This means:
// 1. Certificate chains are truncated to the leaf cert.
// 2. An attacker who prepends a malicious PEM block before a legitimate
//    one can hijack the parsed key.
//
// The code even has a comment acknowledging this:
//   "We may want to handle files with multiple PEM blocks in them, but for now..."
//
// Severity: MEDIUM -- chain truncation can cause verification bypass if
// intermediate/root certs are concatenated and only the leaf is parsed.
// ==========================================================================

func TestSecurity_R3_256_TryParseKeyFromReader_OnlyFirstPEMBlock(t *testing.T) {
	// Generate two different RSA keys
	priv1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key 1: %v", err)
	}
	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key 2: %v", err)
	}

	pubDER1, err := x509.MarshalPKIXPublicKey(&priv1.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal key 1: %v", err)
	}
	pubDER2, err := x509.MarshalPKIXPublicKey(&priv2.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal key 2: %v", err)
	}

	pem1 := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER1})
	pem2 := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER2})

	// Concatenate: attacker's key first, legitimate key second
	combined := append(pem1, pem2...)

	parsed, err := TryParseKeyFromReader(bytes.NewReader(combined))
	if err != nil {
		t.Fatalf("TryParseKeyFromReader failed: %v", err)
	}

	// Verify only the first key was parsed
	parsedPub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", parsed)
	}
	if parsedPub.N.Cmp(priv1.PublicKey.N) != 0 {
		t.Fatal("expected the FIRST key to be parsed")
	}
	if parsedPub.N.Cmp(priv2.PublicKey.N) == 0 {
		t.Fatal("expected the second key to be ignored")
	}

	t.Log("CONFIRMED R3-256: TryParseKeyFromReader only parses the first PEM block. " +
		"Subsequent blocks (certificate chain, additional keys) are silently discarded. " +
		"An attacker who can prepend a PEM block can hijack the parsed key.")
}

func TestSecurity_R3_256_TryParseKeyFromReader_CertChainTruncation(t *testing.T) {
	// Build root -> leaf chain, concatenate as PEM
	rootPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate,
		&rootPriv.PublicKey, rootPriv)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}

	leafPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Leaf Cert"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert,
		&leafPriv.PublicKey, rootPriv)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}

	// Concatenate leaf + root cert PEMs (common practice for chains)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	chainPEM := append(leafPEM, rootPEM...)

	// TryParseCertificate only returns the first cert
	parsed, err := TryParseCertificate(chainPEM)
	if err != nil {
		t.Fatalf("TryParseCertificate failed: %v", err)
	}

	if parsed.Subject.CommonName != "Leaf Cert" {
		t.Fatalf("expected leaf cert, got: %s", parsed.Subject.CommonName)
	}

	t.Log("CONFIRMED R3-256: Certificate chain PEM is truncated to the first cert. " +
		"Root and intermediate certificates in a concatenated chain are silently discarded.")
}

// ==========================================================================
// R3-257: DirhHashSha256 follows symlinks within directories
//
// When hashing a directory, DirhHashSha256 uses an open() callback that
// calls os.Open, which follows symlinks. A symlink inside the hashed
// directory pointing outside the tree will include the external file's
// content in the hash. This can:
// 1. Cause the directory hash to include sensitive external files.
// 2. Allow an attacker to make two different directory trees produce
//    the same hash by pointing symlinks at the same targets.
//
// Additionally, the function skips directories when opened via
// symlink, but only if the opened result is an *os.File and IsDir().
// Non-file symlink targets (e.g., FIFOs, sockets) may cause errors.
//
// Severity: MEDIUM -- directory hash integrity can be manipulated
// ==========================================================================

func TestSecurity_R3_257_DirhHashSha256_FollowsSymlinks(t *testing.T) {
	// Create a directory with a file
	tmpDir := t.TempDir()
	contentDir := filepath.Join(tmpDir, "content")
	if err := os.Mkdir(contentDir, 0755); err != nil {
		t.Fatalf("failed to create content dir: %v", err)
	}

	// Create a file outside the hashed directory
	externalFile := filepath.Join(tmpDir, "external_secret.txt")
	if err := os.WriteFile(externalFile, []byte("external secret data"), 0644); err != nil {
		t.Fatalf("failed to write external file: %v", err)
	}

	// Create a symlink inside the content dir pointing to external file
	symlinkInDir := filepath.Join(contentDir, "link_to_external.txt")
	if err := os.Symlink(externalFile, symlinkInDir); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	// Also create a regular file in content dir
	regularFile := filepath.Join(contentDir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte("regular content"), 0644); err != nil {
		t.Fatalf("failed to write regular file: %v", err)
	}

	// Use DirhHashSha256 with the two files (simulating directory walk)
	files := []string{"link_to_external.txt", "regular.txt"}
	openFn := func(name string) (io.ReadCloser, error) {
		return os.Open(filepath.Join(contentDir, name))
	}

	hash, err := DirhHashSha256(files, openFn)
	if err != nil {
		t.Fatalf("DirhHashSha256 failed: %v", err)
	}

	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	// The symlink was followed and the external file content was hashed.
	// Now hash the directory with the symlink replaced by the actual content.
	if err := os.Remove(symlinkInDir); err != nil {
		t.Fatalf("failed to remove symlink: %v", err)
	}
	if err := os.WriteFile(symlinkInDir, []byte("external secret data"), 0644); err != nil {
		t.Fatalf("failed to replace symlink with file: %v", err)
	}

	hashDirect, err := DirhHashSha256(files, openFn)
	if err != nil {
		t.Fatalf("DirhHashSha256 (direct) failed: %v", err)
	}

	if hash != hashDirect {
		t.Fatalf("expected symlink and direct file to produce same hash, got %q vs %q", hash, hashDirect)
	}

	t.Log("CONFIRMED R3-257: DirhHashSha256 follows symlinks transparently. " +
		"A symlink inside the hashed directory pointing to an external file " +
		"will include that external file's content in the directory hash. " +
		"This can be exploited to include sensitive data or manipulate hashes.")
}

func TestSecurity_R3_257_DirhHashSha256_NewlineInFilename(t *testing.T) {
	// The function correctly rejects filenames with newlines.
	files := []string{"file\nwith\nnewlines.txt"}
	openFn := func(name string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("content")), nil
	}

	_, err := DirhHashSha256(files, openFn)
	if err == nil {
		t.Fatal("expected error for filename with newlines")
	}
	if !strings.Contains(err.Error(), "newlines are not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ==========================================================================
// R3-258: isSupportedAlg nil vs empty has dangerous semantic difference
//
// isSupportedAlg(alg, nil) returns true (accept ALL algorithms).
// isSupportedAlg(alg, []crypto.Hash{}) returns false (accept NONE).
//
// This semantic difference between nil and empty slice is a footgun.
// If a caller forgets to initialize the supported hashes list, nil is
// passed and ALL hash algorithms are accepted, including weak ones.
// ComputeDigest passes supportedHashFuncs directly to isSupportedAlg.
//
// Severity: LOW -- requires caller to pass nil supportedHashFuncs
// ==========================================================================

func TestSecurity_R3_258_IsSupportedAlg_NilAcceptsEverything(t *testing.T) {
	// nil means "accept all"
	if !isSupportedAlg(crypto.SHA1, nil) {
		t.Fatal("expected isSupportedAlg(SHA1, nil) == true")
	}
	if !isSupportedAlg(crypto.SHA256, nil) {
		t.Fatal("expected isSupportedAlg(SHA256, nil) == true")
	}
	if !isSupportedAlg(crypto.MD5, nil) {
		t.Fatal("expected isSupportedAlg(MD5, nil) == true")
	}

	// Empty slice means "accept none"
	if isSupportedAlg(crypto.SHA256, []crypto.Hash{}) {
		t.Fatal("expected isSupportedAlg(SHA256, []) == false")
	}

	// Demonstrate the footgun via ComputeDigest
	data := bytes.NewReader([]byte("test"))
	_, _, err := ComputeDigest(data, crypto.SHA1, nil)
	if err != nil {
		t.Fatalf("ComputeDigest with nil supported hashes should accept SHA1: %v", err)
	}

	t.Log("SECURITY NOTE R3-258: isSupportedAlg(alg, nil) returns true for ALL " +
		"algorithms including weak ones (MD5, SHA1). This is a dangerous default. " +
		"nil and empty slice have completely different semantics.")
}

// ==========================================================================
// R3-259: X509Verifier from X509Signer.Verifier() may lack roots
//
// When X509Signer.Verifier() is called, it creates an X509Verifier by:
// 1. Getting the inner signer's Verifier (e.g., RSAVerifier)
// 2. Wrapping it in X509Verifier with cert, roots, intermediates from the signer
//
// However, the returned X509Verifier has trustedTime set to zero (the
// zero value of time.Time). When trustedTime is zero, x509.Certificate.Verify
// uses the CURRENT system time. This is generally fine, but if the cert
// was issued with a very short validity window, there's a TOCTOU issue
// between signing and verification.
//
// More critically: if the X509Signer was created without roots
// (roots == nil), the X509Verifier will also have nil roots, causing
// cert.Verify to use the system root pool. This means the verification
// trust anchor changes depending on the host's CA store.
//
// Severity: LOW-MEDIUM -- trust anchor inconsistency
// ==========================================================================

func TestSecurity_R3_259_X509Signer_VerifierTrustAnchorPropagation(t *testing.T) {
	// Create a self-signed cert that acts as its own root
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	// Create X509Signer WITH roots
	baseSigner := NewRSASigner(priv, crypto.SHA256)
	x509Signer, err := NewX509Signer(baseSigner, cert, nil, []*x509.Certificate{cert})
	if err != nil {
		t.Fatalf("failed to create X509Signer: %v", err)
	}

	// Get verifier from signer
	verifier, err := x509Signer.Verifier()
	if err != nil {
		t.Fatalf("X509Signer.Verifier() failed: %v", err)
	}

	// The verifier should be an X509Verifier
	x509Verifier, ok := verifier.(*X509Verifier)
	if !ok {
		t.Fatalf("expected *X509Verifier, got %T", verifier)
	}

	// Verify that roots were propagated
	if x509Verifier.Roots() == nil {
		t.Fatal("SECURITY BUG: X509Signer.Verifier() did not propagate roots")
	}
	if len(x509Verifier.Roots()) != 1 {
		t.Fatalf("expected 1 root, got %d", len(x509Verifier.Roots()))
	}

	// Now create WITHOUT roots and verify the behavior
	signerNoRoots, err := NewX509Signer(baseSigner, cert, nil, nil)
	if err != nil {
		t.Fatalf("failed to create X509Signer without roots: %v", err)
	}

	verifierNoRoots, err := signerNoRoots.Verifier()
	if err != nil {
		t.Fatalf("Verifier() failed: %v", err)
	}

	x509VerifierNoRoots, ok := verifierNoRoots.(*X509Verifier)
	if !ok {
		t.Fatalf("expected *X509Verifier, got %T", verifierNoRoots)
	}

	if x509VerifierNoRoots.Roots() != nil {
		t.Log("Roots were set even though X509Signer had nil roots")
	} else {
		t.Log("SECURITY NOTE R3-259: X509Signer with nil roots creates " +
			"X509Verifier with nil roots. When Verify() is called, " +
			"cert.Verify uses system root pool, making trust anchor " +
			"dependent on host CA store. This is not necessarily a bug " +
			"but is a subtle trust model inconsistency.")
	}

	// Verify trustedTime is zero in the returned verifier
	// (it's not exported, but we can check behavior)
	data := []byte("trust anchor test")
	sig, err := x509Signer.Sign(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify should work since the cert is currently valid
	err = verifier.Verify(bytes.NewReader(data), sig)
	if err != nil {
		t.Logf("FINDING R3-259: X509Signer.Verifier() produced a verifier "+
			"that fails chain validation: %v", err)
	}
}

// ==========================================================================
// R3-250b: CalculateDigestSetFromFile does not restrict path traversal
//
// There is no validation that the path is within an expected directory.
// Absolute paths and paths with ".." components are accepted.
// ==========================================================================

func TestSecurity_R3_250_CalculateDigestSetFromFile_PathTraversal(t *testing.T) {
	// Create a file in a known location
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("super secret"), 0644); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	// Create a subdirectory to work from
	workDir := filepath.Join(tmpDir, "work", "dir")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatalf("failed to create work dir: %v", err)
	}

	// Use path traversal to reach the secret file
	traversalPath := filepath.Join(workDir, "..", "..", "secret.txt")
	hashes := []DigestValue{{Hash: crypto.SHA256}}

	ds, err := CalculateDigestSetFromFile(traversalPath, hashes)
	if err != nil {
		t.Fatalf("path traversal was rejected (unexpected): %v", err)
	}

	// Also hash via the direct path
	dsDirect, err := CalculateDigestSetFromFile(secretFile, hashes)
	if err != nil {
		t.Fatalf("direct path failed: %v", err)
	}

	if !ds.Equal(dsDirect) {
		t.Fatal("expected traversal path and direct path to produce same digest")
	}

	t.Log("CONFIRMED R3-250: CalculateDigestSetFromFile does not validate paths. " +
		"Path traversal with '..' components is accepted, allowing hashing of " +
		"files outside the intended directory tree.")
}

// ==========================================================================
// R3-252b: DigestSet JSON injection -- unknown hash names are rejected
// but valid hash names with malicious digest values are accepted.
// ==========================================================================

func TestSecurity_R3_252_DigestSet_JSONMaliciousDigestValues(t *testing.T) {
	// DigestSet accepts any string as a digest value.
	// Injection of special characters, very long strings, etc.
	testCases := []struct {
		name   string
		digest string
	}{
		{"null_bytes", "abc\x00def"},
		{"very_long", strings.Repeat("a", 1024*1024)},
		{"unicode", "\u0000\uffff"},
		{"json_injection", `{"nested": true}`},
		{"html_injection", "<script>alert(1)</script>"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ds := DigestSet{
				DigestValue{Hash: crypto.SHA256}: tc.digest,
			}

			jsonBytes, err := ds.MarshalJSON()
			if err != nil {
				// Some values may fail JSON marshaling (e.g., invalid UTF-8)
				t.Logf("MarshalJSON failed for %q: %v", tc.name, err)
				return
			}

			var restored DigestSet
			err = restored.UnmarshalJSON(jsonBytes)
			if err != nil {
				t.Logf("UnmarshalJSON failed for %q: %v", tc.name, err)
				return
			}

			// The digest value survives JSON round-trip without validation
			restoredDigest := restored[DigestValue{Hash: crypto.SHA256}]
			if restoredDigest != tc.digest {
				t.Logf("digest value changed during roundtrip for %q", tc.name)
			}
		})
	}

	t.Log("SECURITY NOTE R3-252: DigestSet accepts arbitrary strings as digest " +
		"values. No validation that values are hex-encoded, non-empty, or of " +
		"expected length for the hash algorithm.")
}

// ==========================================================================
// R3-253b: NewSigner accepts ED25519 private key ignoring hash option
//
// When NewSigner is called with an ed25519.PrivateKey, it creates an
// ED25519Signer which IGNORES the SignWithHash option. ED25519 uses its
// own internal hash. But the caller might think they're getting SHA512
// when they pass SignWithHash(crypto.SHA512). This is a silent mismatch.
// ==========================================================================

func TestSecurity_R3_253_NewSigner_ED25519_IgnoresHashOption(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ED25519 key: %v", err)
	}

	// Create signer with explicitly requesting SHA512
	signer, err := NewSigner(priv, SignWithHash(crypto.SHA512))
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// The signer works, but SHA512 is silently ignored.
	data := []byte("ed25519 hash option test")
	sig, err := signer.Sign(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	verifier, err := signer.Verifier()
	if err != nil {
		t.Fatalf("Verifier failed: %v", err)
	}

	err = verifier.Verify(bytes.NewReader(data), sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Create another signer with SHA256 option -- should produce identical results
	signer2, err := NewSigner(priv, SignWithHash(crypto.SHA256))
	if err != nil {
		t.Fatalf("NewSigner2 failed: %v", err)
	}

	sig2, err := signer2.Sign(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Sign2 failed: %v", err)
	}

	// Both signatures should verify against the same verifier
	// (because hash option is ignored for ED25519)
	err = verifier.Verify(bytes.NewReader(data), sig2)
	if err != nil {
		t.Fatalf("Verify2 failed: %v", err)
	}

	t.Log("CONFIRMED R3-253: NewSigner with ed25519.PrivateKey silently ignores " +
		"SignWithHash option. SignWithHash(crypto.SHA512) has no effect. " +
		"This is technically correct (ED25519 has a fixed hash) but the " +
		"caller has no way to know their option was ignored.")
}

// ==========================================================================
// R3-254b: UnmarshalPEMToPublicKey ignores PEM block type for PKIX parsing
//
// When the PEM type is "PUBLIC KEY", UnmarshalPEMToPublicKey calls
// x509.ParsePKIXPublicKey. But it only checks the type string, not
// that the DER bytes actually contain a public key. If someone puts
// private key DER bytes inside a "PUBLIC KEY" PEM block, the behavior
// depends on what x509.ParsePKIXPublicKey does with them.
// ==========================================================================

func TestSecurity_R3_254_UnmarshalPEMToPublicKey_PrivateKeyInPublicKeyPEM(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Put PKCS8 private key DER inside a "PUBLIC KEY" PEM type
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}

	mislabeledPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: privDER,
	})

	_, err = UnmarshalPEMToPublicKey(mislabeledPEM)
	if err == nil {
		t.Log("SECURITY NOTE R3-254: Private key DER inside 'PUBLIC KEY' PEM was " +
			"accepted by UnmarshalPEMToPublicKey. Check what type was returned.")
	} else {
		t.Logf("Private key DER in PUBLIC KEY PEM correctly rejected: %v", err)
	}
}

// ==========================================================================
// R3-258b: NewX509Verifier accepts certificate with wrong key type
//
// NewX509Verifier creates the inner verifier from cert.PublicKey.
// If NewVerifier doesn't support the key type, it returns an error.
// But there's no check that the certificate's key usage permits
// digital signatures.
// ==========================================================================

func TestSecurity_R3_258_X509Verifier_CertWithoutDigitalSignatureKeyUsage(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create a cert with only KeyEncipherment (no DigitalSignature)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "No Signing Cert"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment, // NOT DigitalSignature
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	// NewX509Verifier does NOT check key usage
	verifier, err := NewX509Verifier(cert, nil, []*x509.Certificate{cert}, time.Time{})
	if err != nil {
		t.Fatalf("NewX509Verifier rejected cert without DigitalSignature: %v", err)
	}

	// The verifier was created, but should it have been?
	_ = verifier
	t.Log("SECURITY NOTE R3-258: NewX509Verifier does not check that the " +
		"certificate's KeyUsage includes DigitalSignature. A cert with only " +
		"KeyEncipherment is accepted as a verifier. This could allow " +
		"verification with inappropriately used certificates.")
}

