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

// jade:ring local

package cli

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	tsp "github.com/digitorus/timestamp"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/timestamp"
)

// The approval-envelope fixture builds what the platform builds when it signs
// a Pushgate policy-assignment approval for the approving human
// (judge-api/cmd/server/cmd/handlers_pushgate_approvals.go): one DSSE
// signature by a keyless leaf under a Fulcio-style intermediate, stamped by an
// RFC 3161 TSA. The TSA answers over loopback HTTP through
// timestamp.NewTimestamper, the client `cilock run` uses, so the token takes
// the production request path instead of being assembled in memory.
//
// It returns only the trust a verifier must supply itself, the Fulcio root and
// the TSA root. The intermediate rides inside the envelope, where the
// platform's Fulcio signer puts it, so a verifier that passes has found both
// anchors on its own.

// approvalEnvelopeTestIssuer stands in for the platform's email OIDC issuer
// (EmbeddedFulcio.EmailIssuerURL).
const approvalEnvelopeTestIssuer = "https://platform.example.test/oidc"

// oidTestAssurance is the platform Fulcio fork's assurance-level extension
// (subtrees/fulcio/pkg/identity/email/principal.go OIDAuthenticatorAssuranceLevel).
var oidTestAssurance = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 100}

type approvalEnvelopeFixture struct {
	JSON         []byte // the envelope as the edge stores and serves it; decode a fresh copy per use
	Leaf         *x509.Certificate
	Intermediate *x509.Certificate
	FulcioRoot   *x509.Certificate
	TSARoot      *x509.Certificate
}

type approvalEnvelopeOptions struct {
	emails      []string
	uris        []string
	issuer      string
	acr         string
	payloadType string
	signedAt    time.Time
	sharedRoot  bool
}

type approvalEnvelopeOption func(*approvalEnvelopeOptions)

// withLeafEmails replaces the leaf's email SANs; no arguments leaves none.
func withLeafEmails(emails ...string) approvalEnvelopeOption {
	return func(o *approvalEnvelopeOptions) { o.emails = emails }
}

// withLeafURIs adds URI SANs, the shape of a platform agent leaf
// (spiffe://<td>/tenant/<t>/agent/<a>, judge-api/pkg/fulcioca/agent_principal.go).
func withLeafURIs(uris ...string) approvalEnvelopeOption {
	return func(o *approvalEnvelopeOptions) { o.uris = uris }
}

// withLeafIssuer sets the Fulcio issuer extensions; "" omits them.
func withLeafIssuer(issuer string) approvalEnvelopeOption {
	return func(o *approvalEnvelopeOptions) { o.issuer = issuer }
}

// withLeafAssurance stamps the assurance extension with acr, as the fork does
// from the signing token's acr claim.
func withLeafAssurance(acr string) approvalEnvelopeOption {
	return func(o *approvalEnvelopeOptions) { o.acr = acr }
}

func withPayloadType(payloadType string) approvalEnvelopeOption {
	return func(o *approvalEnvelopeOptions) { o.payloadType = payloadType }
}

// withSignedAt fixes the TSA's genTime and the leaf's ten-minute validity to
// `at`. A past time yields a leaf that has since expired, which is what a
// stored approval is when someone verifies it later.
func withSignedAt(at time.Time) approvalEnvelopeOption {
	return func(o *approvalEnvelopeOptions) { o.signedAt = at }
}

// withTSAUnderFulcioRoot issues the TSA leaf from the Fulcio root: production,
// where release.yml bakes one Platform Root CA as both anchors.
func withTSAUnderFulcioRoot() approvalEnvelopeOption {
	return func(o *approvalEnvelopeOptions) { o.sharedRoot = true }
}

func newApprovalEnvelopeFixture(t *testing.T, payload []byte, opts ...approvalEnvelopeOption) *approvalEnvelopeFixture {
	t.Helper()
	o := approvalEnvelopeOptions{
		emails:      []string{"approver@example.com"},
		issuer:      approvalEnvelopeTestIssuer,
		payloadType: "application/vnd.in-toto+json",
	}
	for _, opt := range opts {
		opt(&o)
	}
	at := o.signedAt
	if at.IsZero() {
		at = time.Now()
	}

	caTpl := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"TestifySec"}},
			NotBefore:             at.Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
	}
	root, rootKey := issueTestCert(t, caTpl(1, "Test Platform Root CA"), nil, nil)
	interTpl := caTpl(2, "Test Fulcio Intermediate CA")
	interTpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	inter, interKey := issueTestCert(t, interTpl, root, rootKey)

	leafTpl := &x509.Certificate{
		SerialNumber:   big.NewInt(3),
		NotBefore:      at.Add(-time.Minute),
		NotAfter:       at.Add(10 * time.Minute),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		EmailAddresses: o.emails,
	}
	for _, raw := range o.uris {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		leafTpl.URIs = append(leafTpl.URIs, u)
	}
	if o.issuer != "" {
		exts, err := certificate.Extensions{Issuer: o.issuer}.Render()
		require.NoError(t, err)
		leafTpl.ExtraExtensions = exts
	}
	if o.acr != "" {
		der, err := asn1.MarshalWithParams(o.acr, "utf8")
		require.NoError(t, err)
		leafTpl.ExtraExtensions = append(leafTpl.ExtraExtensions, pkix.Extension{Id: oidTestAssurance, Value: der})
	}
	leaf, leafKey := issueTestCert(t, leafTpl, inter, interKey)

	var tsa *testTSA
	if o.sharedRoot {
		tsa = newTestTSA(t, at, root, rootKey)
	} else {
		tsa = newTestTSA(t, at, nil, nil)
	}
	srv := httptest.NewServer(tsa.handler(t, o.signedAt))
	defer srv.Close()

	signer, err := cryptoutil.NewSigner(leafKey,
		cryptoutil.SignWithCertificate(leaf), cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}))
	require.NoError(t, err)
	env, err := dsse.Sign(o.payloadType, bytes.NewReader(payload),
		dsse.SignWithSigners(signer),
		dsse.SignWithTimestampers(timestamp.NewTimestamper(timestamp.TimestampWithUrl(srv.URL))))
	require.NoError(t, err)
	raw, err := json.Marshal(env)
	require.NoError(t, err)
	return &approvalEnvelopeFixture{JSON: raw, Leaf: leaf, Intermediate: inter, FulcioRoot: root, TSARoot: tsa.Root}
}

// handler serves RFC 3161 over HTTP. A zero `at` stamps the current time.
func (a *testTSA) handler(t *testing.T, at time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		var req *tsp.Request
		if err == nil {
			req, err = tsp.ParseRequest(body)
		}
		var resp []byte
		if err == nil {
			genTime := at
			if genTime.IsZero() {
				genTime = time.Now()
			}
			resp, err = a.respond(&tsp.Timestamp{
				HashAlgorithm: req.HashAlgorithm, HashedMessage: req.HashedMessage, Time: genTime, Nonce: req.Nonce,
			})
		}
		if err != nil {
			t.Errorf("fixture TSA: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(resp)
	})
}

// files writes the envelope and the two anchors as the PEM files
// --policy-ca-roots and --policy-timestamp-servers read.
func (f *approvalEnvelopeFixture) files(t *testing.T, dir string) (envelope, caRoots, tsaRoots string) {
	t.Helper()
	envelope = filepath.Join(dir, "approval.json")
	caRoots = filepath.Join(dir, "fulcio-roots.pem")
	tsaRoots = filepath.Join(dir, "tsa-roots.pem")
	require.NoError(t, os.WriteFile(envelope, f.JSON, 0o600))
	require.NoError(t, os.WriteFile(caRoots, certPEM(t, f.FulcioRoot), 0o600))
	require.NoError(t, os.WriteFile(tsaRoots, certPEM(t, f.TSARoot), 0o600))
	return envelope, caRoots, tsaRoots
}

const approvalFixturePayload = `{"_type":"https://in-toto.io/Statement/v1",` +
	`"subject":[{"name":"connection","digest":{"sha256":"00"}}],` +
	`"predicateType":"https://pushgate.dev/attestations/policy-assignment-approval/v1","predicate":{}}`

func verifyUnderAnchors(env dsse.Envelope, fulcioRoot, tsaRoot *x509.Certificate) ([]dsse.CheckedVerifier, error) {
	return env.Verify(dsse.VerifyWithRoots(fulcioRoot),
		dsse.VerifyWithTimestampVerifiers(timestamp.NewVerifier(timestamp.VerifyWithCerts([]*x509.Certificate{tsaRoot}))))
}

func storedApprovalEnvelope(t *testing.T, f *approvalEnvelopeFixture) dsse.Envelope {
	t.Helper()
	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(f.JSON, &env))
	return env
}

func TestApprovalEnvelopeFixture_VerifiesOnlyUnderItsOwnAnchors(t *testing.T) {
	f := newApprovalEnvelopeFixture(t, []byte(approvalFixturePayload))
	other := newApprovalEnvelopeFixture(t, []byte(approvalFixturePayload))
	env := storedApprovalEnvelope(t, f)
	require.Len(t, env.Signatures, 1)
	assert.Equal(t, "application/vnd.in-toto+json", env.PayloadType)
	assert.Equal(t, approvalFixturePayload, string(env.Payload))

	require.Len(t, env.Signatures[0].Intermediates, 1)
	carried, err := cryptoutil.TryParseCertificate(env.Signatures[0].Intermediates[0])
	require.NoError(t, err)
	assert.True(t, carried.Equal(f.Intermediate), "the envelope carries the intermediate, as the platform signer does")

	checked, err := verifyUnderAnchors(env, f.FulcioRoot, f.TSARoot)
	require.NoError(t, err)
	require.Len(t, checked, 1)
	require.Len(t, checked[0].VerifiedTimestamps, 1)
	signedAt := checked[0].VerifiedTimestamps[0]
	assert.True(t, !signedAt.Before(f.Leaf.NotBefore) && !signedAt.After(f.Leaf.NotAfter),
		"the TSA time %s must fall inside the leaf's validity", signedAt)

	noIntermediate := env
	noIntermediate.Signatures = []dsse.Signature{env.Signatures[0]}
	noIntermediate.Signatures[0].Intermediates = nil
	for name, verify := range map[string]func() ([]dsse.CheckedVerifier, error){
		"another TSA root":    func() ([]dsse.CheckedVerifier, error) { return verifyUnderAnchors(env, f.FulcioRoot, other.TSARoot) },
		"another Fulcio root": func() ([]dsse.CheckedVerifier, error) { return verifyUnderAnchors(env, other.FulcioRoot, f.TSARoot) },
		"no TSA verifier":     func() ([]dsse.CheckedVerifier, error) { return env.Verify(dsse.VerifyWithRoots(f.FulcioRoot)) },
		"intermediate stripped": func() ([]dsse.CheckedVerifier, error) {
			return verifyUnderAnchors(noIntermediate, f.FulcioRoot, f.TSARoot)
		},
	} {
		_, err := verify()
		assert.Error(t, err, "%s: every anchor the fixture returns must be load-bearing", name)
	}
}

func TestApprovalEnvelopeFixture_LeafShapesAreValidlySigned(t *testing.T) {
	const spiffe = "spiffe://td/tenant/t/agent/a"
	const aal2 = "urn:testifysec:params:acr:nist-800-63b:aal2"
	human := []string{"approver@example.com"}
	cases := []struct {
		name   string
		opts   []approvalEnvelopeOption
		emails []string
		uris   []string
		issuer string
		acr    string
	}{
		{"platform human", nil, human, nil, approvalEnvelopeTestIssuer, ""},
		{"agent SPIFFE leaf", []approvalEnvelopeOption{withLeafEmails(), withLeafURIs(spiffe)}, nil, []string{spiffe}, approvalEnvelopeTestIssuer, ""},
		{"two email SANs", []approvalEnvelopeOption{withLeafEmails("a@example.com", "b@example.com")}, []string{"a@example.com", "b@example.com"}, nil, approvalEnvelopeTestIssuer, ""},
		{"email plus URI", []approvalEnvelopeOption{withLeafURIs(spiffe)}, human, []string{spiffe}, approvalEnvelopeTestIssuer, ""},
		{"assurance URN", []approvalEnvelopeOption{withLeafAssurance(aal2)}, human, nil, approvalEnvelopeTestIssuer, aal2},
		{"legacy bare assurance", []approvalEnvelopeOption{withLeafAssurance("aal1")}, human, nil, approvalEnvelopeTestIssuer, "aal1"},
		{"no issuer", []approvalEnvelopeOption{withLeafIssuer("")}, human, nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newApprovalEnvelopeFixture(t, []byte(approvalFixturePayload), tc.opts...)
			env := storedApprovalEnvelope(t, f)
			_, err := verifyUnderAnchors(env, f.FulcioRoot, f.TSARoot)
			require.NoError(t, err, "a refusal of this shape must be a refusal of the shape, not of the signature")

			leaf, err := cryptoutil.TryParseCertificate(env.Signatures[0].Certificate)
			require.NoError(t, err)
			assert.Equal(t, tc.emails, leaf.EmailAddresses)
			uris := make([]string, 0, len(leaf.URIs))
			for _, u := range leaf.URIs {
				uris = append(uris, u.String())
			}
			assert.ElementsMatch(t, tc.uris, uris)
			exts, err := certificate.ParseExtensions(leaf.Extensions)
			require.NoError(t, err)
			assert.Equal(t, tc.issuer, exts.Issuer)

			acr := make([]pkix.Extension, 0, 1)
			for _, e := range leaf.Extensions {
				if e.Id.Equal(oidTestAssurance) {
					acr = append(acr, e)
				}
			}
			if tc.acr == "" {
				assert.Empty(t, acr)
				return
			}
			require.Len(t, acr, 1)
			assert.False(t, acr[0].Critical)
			var decoded asn1.RawValue
			rest, err := asn1.Unmarshal(acr[0].Value, &decoded)
			require.NoError(t, err)
			assert.Empty(t, rest)
			assert.Equal(t, asn1.TagUTF8String, decoded.Tag, "the fork encodes the level as a DER UTF8String")
			assert.Equal(t, tc.acr, string(decoded.Bytes))
		})
	}
}

func TestApprovalEnvelopeFixture_TimestampOutlivesTheLeaf(t *testing.T) {
	signedAt := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	f := newApprovalEnvelopeFixture(t, []byte(approvalFixturePayload), withSignedAt(signedAt))
	env := storedApprovalEnvelope(t, f)
	require.True(t, time.Now().After(f.Leaf.NotAfter), "the leaf must have expired before this verify")

	checked, err := verifyUnderAnchors(env, f.FulcioRoot, f.TSARoot)
	require.NoError(t, err)
	assert.WithinDuration(t, signedAt, checked[0].VerifiedTimestamps[0], time.Second)

	_, err = env.Verify(dsse.VerifyWithRoots(f.FulcioRoot), dsse.VerifyWithCurrentTimeFallback())
	assert.Error(t, err, "at the wall clock the leaf has expired; only the TSA time may carry it")
}

func TestApprovalEnvelopeFixture_TrustFilesAndSharedRoot(t *testing.T) {
	f := newApprovalEnvelopeFixture(t, []byte(approvalFixturePayload), withPayloadType("application/json"))
	require.False(t, f.TSARoot.Equal(f.FulcioRoot))
	envPath, caPath, tsaPath := f.files(t, t.TempDir())

	raw, err := os.ReadFile(envPath)
	require.NoError(t, err)
	assert.Equal(t, f.JSON, raw)
	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(raw, &env))
	assert.Equal(t, "application/json", env.PayloadType)
	caPEM, err := os.ReadFile(caPath)
	require.NoError(t, err)
	roots, intermediates, err := splitPEMCertsBySelfSigned(caPEM)
	require.NoError(t, err)
	require.Len(t, roots, 1)
	assert.Empty(t, intermediates)
	tsaPEM, err := os.ReadFile(tsaPath)
	require.NoError(t, err)
	tsaCerts, err := parsePEMCerts(tsaPEM)
	require.NoError(t, err)
	require.Len(t, tsaCerts, 1)
	_, err = verifyUnderAnchors(env, roots[0], tsaCerts[0])
	require.NoError(t, err, "the files must carry the anchors the way cilock verify loads them")

	shared := newApprovalEnvelopeFixture(t, []byte(approvalFixturePayload), withTSAUnderFulcioRoot())
	assert.True(t, shared.TSARoot.Equal(shared.FulcioRoot))
	_, err = verifyUnderAnchors(storedApprovalEnvelope(t, shared), shared.FulcioRoot, shared.FulcioRoot)
	require.NoError(t, err)
}
