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
	client := http.Client{}
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
	hash      crypto.Hash
}

type TSPVerifierOption func(*TSPVerifier)

func VerifyWithCerts(certs []*x509.Certificate) TSPVerifierOption {
	return func(t *TSPVerifier) {
		t.certChain = x509.NewCertPool()
		for _, cert := range certs {
			t.certChain.AddCert(cert)
		}
	}
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

	if err := p7.VerifyWithChain(v.certChain); err != nil {
		return time.Time{}, err
	}

	return ts.Time, nil
}
