// Copyright 2022 The Witness Contributors
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

package timestamp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"
)

type TSPTimestamper struct {
	url                string
	hash               crypto.Hash
	requestCertificate bool
}

type TSPTimestamperOption func(*TSPTimestamper)

// TimestampWithUrl sets the TSA URL. The URL is validated at construction time
// rather than at request time so that invalid or non-HTTPS URLs fail early.
// Security: accepting arbitrary URLs without validation could allow SSRF attacks
// or accidentally send timestamp requests over plaintext HTTP, leaking artifact
// hashes to a network observer.
func TimestampWithUrl(rawURL string) TSPTimestamperOption {
	return func(t *TSPTimestamper) {
		t.url = rawURL
	}
}

// validateURL checks that the timestamp authority URL is well-formed and uses HTTPS.
// HTTP is permitted for localhost, loopback, and private network addresses (RFC 1918)
// to support local development and Docker-based CI simulation.
func validateURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid timestamp authority URL: %w", err)
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		if !isLocalOrPrivate(host) {
			return fmt.Errorf("timestamp authority URL must use HTTPS, got %q", u.Scheme)
		}
	}
	if u.Host == "" {
		return fmt.Errorf("timestamp authority URL has no host")
	}
	return nil
}

// isLocalOrPrivate returns true if the host is localhost, loopback, or a private network address.
func isLocalOrPrivate(host string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	// RFC 1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	// Also loopback 127.0.0.0/8 and link-local 169.254.0.0/16
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func TimestampWithHash(h crypto.Hash) TSPTimestamperOption {
	return func(t *TSPTimestamper) {
		t.hash = h
	}
}

func TimestampWithRequestCertificate(requestCertificate bool) TSPTimestamperOption {
	return func(t *TSPTimestamper) {
		t.requestCertificate = requestCertificate
	}
}

func NewTimestamper(opts ...TSPTimestamperOption) TSPTimestamper {
	t := TSPTimestamper{
		hash:               crypto.SHA256,
		requestCertificate: true,
	}

	for _, opt := range opts {
		opt(&t)
	}

	return t
}

func (t TSPTimestamper) Timestamp(ctx context.Context, r io.Reader) ([]byte, error) {
	if err := validateURL(t.url); err != nil {
		return nil, err
	}

	tsq, err := timestamp.CreateRequest(r, &timestamp.RequestOptions{
		Hash:         t.hash,
		Certificates: t.requestCertificate,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", t.url, bytes.NewReader(tsq))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/timestamp-query")
	// Bound the RFC3161 TSA request: a bare http.Client{} has no Timeout, so a
	// timestamp endpoint that stalls would hang the signing leg (which runs before
	// the upload) until the CI job timeout. The request is tiny; 30s is ample.
	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
	default:
		return nil, fmt.Errorf("request to timestamp authority failed: %v", resp.Status)
	}
	// Limit response size to prevent OOM from a malicious/compromised TSA.
	// TSP responses are typically a few KB; 1MB is very generous.
	const maxTSAResponseSize = 1 << 20 // 1MB
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxTSAResponseSize))
	if err != nil {
		return nil, err
	}

	timestamp, err := timestamp.ParseResponse(bodyBytes)
	if err != nil {
		return nil, err
	}

	return timestamp.RawToken, nil
}

type TSPVerifier struct {
	certChain *x509.CertPool
	// roots retains the trusted certificate slice passed to VerifyWithCerts
	// (the CertPool above discards the originals). It is exposed via
	// TrustedRoots() so callers can run trust diagnostics — e.g. detecting a
	// same-CN/different-key mismatch between the TSA token's signer chain and
	// these trusted roots — WITHOUT changing verification behavior.
	roots []*x509.Certificate
	hash  crypto.Hash
}

type TSPVerifierOption func(*TSPVerifier)

func VerifyWithCerts(certs []*x509.Certificate) TSPVerifierOption {
	return func(t *TSPVerifier) {
		t.certChain = x509.NewCertPool()
		t.roots = make([]*x509.Certificate, 0, len(certs))
		for _, cert := range certs {
			t.certChain.AddCert(cert)
			t.roots = append(t.roots, cert)
		}
	}
}

// TrustedRoots returns the trusted timestamp-authority certificates this
// verifier was configured with (via VerifyWithCerts). It is read-only
// diagnostic metadata; the returned slice must not be mutated.
func (v TSPVerifier) TrustedRoots() []*x509.Certificate {
	return v.roots
}

// TokenCertificates parses an RFC 3161 timestamp token (the raw TSR bytes
// stored in a DSSE signature timestamp) and returns the X.509 certificates
// embedded in it — i.e. the TSA's signing chain. It is a best-effort
// diagnostic helper: it performs NO verification and returns an error only
// when the bytes cannot be parsed as PKCS#7. Used to compare the TSA chain
// that actually produced a timestamp against the policy's trusted TSA roots.
func TokenCertificates(tsrData []byte) ([]*x509.Certificate, error) {
	p7, err := pkcs7.Parse(tsrData)
	if err != nil {
		return nil, err
	}
	return p7.Certificates, nil
}

func VerifyWithHash(h crypto.Hash) TSPVerifierOption {
	return func(t *TSPVerifier) {
		t.hash = h
	}
}

func NewVerifier(opts ...TSPVerifierOption) TSPVerifier {
	v := TSPVerifier{
		hash: crypto.SHA256,
	}

	for _, opt := range opts {
		opt(&v)
	}

	return v
}

func (v TSPVerifier) Verify(ctx context.Context, tsrData, signedData io.Reader) (time.Time, error) {
	if v.certChain == nil {
		return time.Time{}, fmt.Errorf("timestamp verification requires certificate chain: use VerifyWithCerts option")
	}

	tsrBytes, err := io.ReadAll(tsrData)
	if err != nil {
		return time.Time{}, err
	}

	ts, err := timestamp.Parse(tsrBytes)
	if err != nil {
		return time.Time{}, err
	}

	// Use the hash algorithm from the TSP token itself, not the verifier's default.
	// The TSA hashed the data with whatever algorithm was in the request; we must
	// re-hash with the same algorithm to get a matching digest. Using v.hash would
	// silently fail when timestamper and verifier use different algorithms.
	tokenHash := ts.HashAlgorithm
	if !tokenHash.Available() {
		return time.Time{}, fmt.Errorf("timestamp token uses unavailable hash algorithm: %v", tokenHash)
	}

	hashedData, err := cryptoutil.Digest(signedData, tokenHash)
	if err != nil {
		return time.Time{}, err
	}

	if !bytes.Equal(ts.HashedMessage, hashedData) {
		return time.Time{}, fmt.Errorf("signed payload does not match timestamped payload")
	}

	p7, err := pkcs7.Parse(tsrBytes)
	if err != nil {
		return time.Time{}, err
	}

	// Require the signer cert to carry id-kp-timeStamping (RFC 3161 §2.3: the TSA
	// signing cert MUST have the timeStamping EKU). pkcs7.VerifyWithChain defaults
	// KeyUsages to ExtKeyUsageAny, which would let a non-timestamping cert from the
	// same CA (e.g. a code-signing or TLS leaf) vouch for signing time.
	// Finding F (#5747).
	//
	// We do this in two layers:
	//  1. Pin KeyUsages to timeStamping in the chain build via VerifyWithOpts.
	//     This rejects a signer whose EKU extension is present but excludes
	//     timeStamping (e.g. codeSigning only).
	//  2. Explicitly require the timeStamping EKU on the signer leaf. Go's x509
	//     treats a leaf with NO ExtKeyUsage extension as valid for any usage, so
	//     the chain check alone would still accept an EKU-less signer; this
	//     explicit presence check closes that loophole.
	signer := p7.GetOnlySigner()
	if signer == nil {
		return time.Time{}, fmt.Errorf("timestamp token must have exactly one signer")
	}
	// RFC 3161 §2.3: the TSA signing certificate must assert id-kp-timeStamping
	// as its SOLE extended key usage. A multi-purpose leaf (e.g.
	// timeStamping + serverAuth) must be rejected, otherwise a CA-issued cert
	// that is not exclusively a timestamping cert could forge timestamps
	// (GHSA-5qp5-ph6r-qj9f).
	//
	// NOTE: RFC 3161 §2.3 also says this extension "must be critical", but that
	// is intentionally NOT enforced here. Go's x509.CreateCertificate marks the
	// EKU extension non-critical when set via the ExtKeyUsage field, so the
	// platform's own TSA cert — and most real-world TSA certs — carry a
	// non-critical EKU. Enforcing criticality would reject every previously
	// issued timestamp (the token embeds that cert) for no additional protection:
	// requiring timeStamping to be the SOLE EKU already closes the dual-purpose
	// cert vector.
	if !timestampingIsSoleEKU(signer) {
		return time.Time{}, fmt.Errorf("timestamp token signer certificate must carry id-kp-timeStamping as its only extended key usage")
	}

	intermediates := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		intermediates.AddCert(cert)
	}
	verifyOpts := x509.VerifyOptions{
		Roots:         v.certChain,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if err := p7.VerifyWithOpts(verifyOpts); err != nil {
		return time.Time{}, err
	}

	return ts.Time, nil
}

// timestampingIsSoleEKU reports whether id-kp-timeStamping is the certificate's
// ONLY extended key usage. RFC 3161 §2.3 requires the TSA signing certificate
// to assert this EKU and no other; a multi-purpose leaf (or one with no EKU at
// all, or with unrecognized EKUs alongside) must fail closed.
func timestampingIsSoleEKU(cert *x509.Certificate) bool {
	return len(cert.ExtKeyUsage) == 1 &&
		cert.ExtKeyUsage[0] == x509.ExtKeyUsageTimeStamping &&
		len(cert.UnknownExtKeyUsage) == 0
}
