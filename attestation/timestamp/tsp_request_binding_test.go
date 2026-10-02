// jade:ring local

// Copyright 2026 The Witness Contributors
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
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/stretchr/testify/require"
)

// The requester binds a TSA response to its own request (RFC 3161 §2.2,
// §2.4.1, §2.4.2). Each case below is a TSA (or a network position in front
// of one) that returns a correctly signed token which does NOT answer the
// request that was sent. Every one of them must be refused before the token
// reaches a signed envelope.

// tsaTamper rewrites the honest answer to one request.
type tsaTamper func(req *timestamp.Request, ts *timestamp.Timestamp)

// bindingTSA is an RFC 3161 responder over plain HTTP on loopback (validateURL
// permits that) that signs with a real timeStamping leaf under caCert, after
// letting tamper rewrite the TSTInfo. It records every request it parsed.
type bindingTSA struct {
	srv    *httptest.Server
	caCert *x509.Certificate

	mu       sync.Mutex
	requests []*timestamp.Request
	replay   []byte // when set, served verbatim instead of a fresh response
	last     []byte
}

func newBindingTSA(t *testing.T, tamper tsaTamper) *bindingTSA {
	t.Helper()
	caCert, caKey := makeRedgateCA(t)
	leaf, leafKey := makeRedgateLeafCriticalEKU(t, caCert, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})
	b := &bindingTSA{caCert: caCert}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req, err := timestamp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.requests = append(b.requests, req)
		replay := b.replay
		b.mu.Unlock()
		if replay != nil {
			_, _ = w.Write(replay)
			return
		}
		resp, err := signBindingResponse(req, leaf, leafKey, tamper)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		b.mu.Lock()
		b.last = resp
		b.mu.Unlock()
		_, _ = w.Write(resp)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func signBindingResponse(req *timestamp.Request, leaf *x509.Certificate, key *ecdsa.PrivateKey, tamper tsaTamper) ([]byte, error) {
	ts := &timestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Nonce:             req.Nonce,
		Time:              time.Now().UTC(),
		Accuracy:          time.Second,
		SerialNumber:      big.NewInt(time.Now().UnixNano()),
		Policy:            asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
		AddTSACertificate: true,
	}
	if tamper != nil {
		tamper(req, ts)
	}
	return ts.CreateResponseWithOpts(leaf, key, crypto.SHA256)
}

func (b *bindingTSA) timestamper() TSPTimestamper {
	return NewTimestamper(TimestampWithUrl(b.srv.URL))
}

func (b *bindingTSA) seen() []*timestamp.Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*timestamp.Request(nil), b.requests...)
}

func sha256Of(t *testing.T, data []byte) []byte {
	t.Helper()
	h := crypto.SHA256.New()
	_, err := h.Write(data)
	require.NoError(t, err)
	return h.Sum(nil)
}

// An honest TSA's token is returned, and it verifies against the TSA root at
// policy-verification time: the binding checks reject nothing legitimate.
func TestRequestBinding_HonestResponseAccepted(t *testing.T) {
	tsa := newBindingTSA(t, nil)
	payload := []byte("honest-payload")

	token, err := tsa.timestamper().Timestamp(context.Background(), bytes.NewReader(payload))
	require.NoError(t, err)

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{tsa.caCert}))
	genTime, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	require.NoError(t, err)
	require.False(t, genTime.IsZero())
}

// RFC 3161 §4 item 6: "Using a nonce always allows to detect replays, and
// hence its use is RECOMMENDED." Every request carries a fresh, positive,
// large nonce, and the imprint of exactly the data handed to Timestamp.
func TestRequestBinding_RequestCarriesFreshNonceAndImprint(t *testing.T) {
	tsa := newBindingTSA(t, nil)
	payload := []byte("nonce-payload")
	ts := tsa.timestamper()

	for i := 0; i < 2; i++ {
		_, err := ts.Timestamp(context.Background(), bytes.NewReader(payload))
		require.NoError(t, err)
	}
	reqs := tsa.seen()
	require.Len(t, reqs, 2)
	for _, r := range reqs {
		require.NotNil(t, r.Nonce, "request must carry a nonce")
		require.Equal(t, 1, r.Nonce.Sign(), "nonce must be positive")
		require.Greater(t, r.Nonce.BitLen(), 64, "nonce must be large")
		require.Equal(t, crypto.SHA256, r.HashAlgorithm)
		require.Equal(t, sha256Of(t, payload), r.HashedMessage)
	}
	require.NotEqual(t, 0, reqs[0].Nonce.Cmp(reqs[1].Nonce), "each request draws a new nonce")
}

// Every tamper is a validly signed token from the trusted TSA that answers a
// different question than the one asked.
func TestRequestBinding_MismatchedResponsesRefused(t *testing.T) {
	cases := map[string]tsaTamper{
		// RFC 3161 §2.4.2: "The nonce field MUST be present if it was present
		// in the TimeStampReq."
		"nonce omitted": func(_ *timestamp.Request, ts *timestamp.Timestamp) { ts.Nonce = nil },
		// "... In such a case it MUST equal the value provided in the
		// TimeStampReq structure."
		"nonce off by one": func(req *timestamp.Request, ts *timestamp.Timestamp) {
			if req.Nonce != nil {
				ts.Nonce = new(big.Int).Add(req.Nonce, big.NewInt(1))
			}
		},
		"nonce zero": func(_ *timestamp.Request, ts *timestamp.Timestamp) { ts.Nonce = big.NewInt(0) },
		// RFC 3161 §2.2: the requester "SHALL verify that the TimeStampToken
		// contains ... the correct data imprint".
		"token for a different message imprint": func(_ *timestamp.Request, ts *timestamp.Timestamp) {
			h := crypto.SHA256.New()
			_, _ = h.Write([]byte("some other datum"))
			ts.HashedMessage = h.Sum(nil)
		},
		"imprint truncated": func(req *timestamp.Request, ts *timestamp.Timestamp) {
			ts.HashedMessage = append([]byte(nil), req.HashedMessage[:len(req.HashedMessage)-1]...)
		},
		// "... and the correct hash algorithm OID."
		"different hash algorithm": func(_ *timestamp.Request, ts *timestamp.Timestamp) {
			ts.HashAlgorithm = crypto.SHA384
			h := crypto.SHA384.New()
			_, _ = h.Write([]byte("binding-payload"))
			ts.HashedMessage = h.Sum(nil)
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			tsa := newBindingTSA(t, tamper)
			token, err := tsa.timestamper().Timestamp(context.Background(), bytes.NewReader([]byte("binding-payload")))
			require.Error(t, err, "a token that does not answer the request must be refused")
			require.Nil(t, token)
		})
	}
}

// A network position that replays an earlier, honest response for the same
// datum: genuine signature, genuine imprint, stale nonce. RFC 3161 §4 item 6
// names exactly this ("a middleman is replaying legitimate TS responses").
func TestRequestBinding_ReplayedResponseRefused(t *testing.T) {
	tsa := newBindingTSA(t, nil)
	payload := []byte("replayed-payload")
	ts := tsa.timestamper()

	_, err := ts.Timestamp(context.Background(), bytes.NewReader(payload))
	require.NoError(t, err)

	tsa.mu.Lock()
	tsa.replay = tsa.last
	tsa.mu.Unlock()

	token, err := ts.Timestamp(context.Background(), bytes.NewReader(payload))
	require.Error(t, err, "a replayed response carries the previous request's nonce")
	require.Nil(t, token)
}

// A reader that fails with something other than io.EOF must surface the
// error. timestamp.CreateRequest's read loop exits only on io.EOF, so before
// Timestamp hashed the data itself this case spun forever.
func TestRequestBinding_ReaderErrorSurfaces(t *testing.T) {
	tsa := newBindingTSA(t, nil)
	done := make(chan error, 1)
	go func() {
		_, err := tsa.timestamper().Timestamp(context.Background(), failingReader{})
		done <- err
	}()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Timestamp did not return on a failing reader")
	}
	require.Empty(t, tsa.seen(), "no request is sent for data that could not be read")
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// The verifier side of the same bindings, offline (TestTSP covers them only
// against a live public TSA). These guard enforcement that already exists.

// RFC 5280 §6.1.1 (d): trust anchor information "is trusted because it was
// delivered to the path processing procedure by some trustworthy out-of-band
// procedure." A token whose chain ends at a root the verifier was not given
// is refused, even though it is self-consistent.
func TestVerifierBinding_UnanchoredRootRefused(t *testing.T) {
	signerCA, signerCAKey := makeRedgateCA(t)
	leaf, leafKey := makeRedgateLeafCriticalEKU(t, signerCA, signerCAKey, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})
	payload := []byte("unanchored-payload")
	token := makeRedgateToken(t, leaf, leafKey, payload)

	otherRoot, _ := makeRedgateCA(t) // same subject name, different key
	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{otherRoot}))
	_, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	require.Error(t, err, "a chain to a root that was not configured must not verify")

	// Control: the same token verifies under its real root.
	v = NewVerifier(VerifyWithCerts([]*x509.Certificate{signerCA}))
	_, err = v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	require.NoError(t, err)
}

// A valid token for one payload presented as the timestamp of another.
func TestVerifierBinding_DifferentMessageImprintRefused(t *testing.T) {
	ca, caKey := makeRedgateCA(t)
	leaf, leafKey := makeRedgateLeafCriticalEKU(t, ca, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})
	token := makeRedgateToken(t, leaf, leafKey, []byte("payload A"))

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{ca}))
	_, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader([]byte("payload B")))
	require.Error(t, err)
}
