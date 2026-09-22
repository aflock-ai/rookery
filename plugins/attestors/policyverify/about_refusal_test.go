// jade:ring local
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

package policyverify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/policysig"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// These rows run through the attestor's Attest, the entry every cilock, Judge
// and Pushgate verification goes through (design 3.6, revision 4.3: "Rows
// R27f and PV8 run through policyverify.Attest, not the bare engine, so the
// test exercises the decoder the product uses").

// abImage is the image the build step produced: the build collection names it
// as a subject; the source scan does not.
var abImage = func() string {
	sum := sha256.Sum256([]byte("about-refusal-image"))
	return hex.EncodeToString(sum[:])
}()

const abImageSubject = "https://example.com/oci/v1/imageid:"

type abKey struct {
	signer   cryptoutil.Signer
	verifier cryptoutil.Verifier
	keyID    string
	pem      []byte
}

func newABKey(t *testing.T) abKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	pem, err := cryptoutil.PublicPemBytes(&priv.PublicKey)
	require.NoError(t, err)
	return abKey{signer: cryptoutil.NewECDSASigner(priv, crypto.SHA256), verifier: verifier, keyID: keyID, pem: pem}
}

// abBuild signs a build collection at commit that produced abImage: the image
// is a statement subject, and the git attestation records commithash and
// parenthash edges exactly as pvSigned does.
func abBuild(t *testing.T, k abKey, commit, parent string) dsse.Envelope {
	t.Helper()
	env := pvSigned(t, k.signer, "build", commit, parent, 0)
	var stmt intoto.Statement
	require.NoError(t, json.Unmarshal(env.Payload, &stmt))
	stmt.Subject = append(stmt.Subject, intoto.Subject{Name: abImageSubject + abImage, Digest: map[string]string{"sha256": abImage}})
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	signed, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(k.signer))
	require.NoError(t, err)
	return signed
}

// abPolicy is the build and secrets policy of uriAttest as the signed bytes an
// author's file holds, with edit applied to the document first.
func abPolicy(t *testing.T, k abKey, edit func(doc map[string]any)) []byte {
	t.Helper()
	fn := []policy.Functionary{{Type: "publickey", PublicKeyID: k.keyID}}
	pol := policy.Policy{
		PublicKeys: map[string]policy.PublicKey{k.keyID: {KeyID: k.keyID, Key: k.pem}},
		Steps: map[string]policy.Step{
			"build": {Name: "build", Functionaries: fn, Attestations: []policy.Attestation{{Type: pvBuildType}}},
			"secrets": {Name: "secrets", Functionaries: fn, Attestations: []policy.Attestation{{
				Type: pvScanType,
				RegoPolicies: []policy.RegoPolicy{{Name: "no-findings", Module: []byte(`package pvsecrets

deny[msg] {
	count(input.findings) > 0
	msg := "secretscan findings"
}
`)}},
			}}},
		},
	}
	pol.Expires.Time = time.Now().Add(time.Hour)
	raw, err := json.Marshal(pol)
	require.NoError(t, err)
	if edit == nil {
		return raw
	}
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	edit(doc)
	raw, err = json.Marshal(doc)
	require.NoError(t, err)
	return raw
}

func abStep(doc map[string]any, name string) map[string]any {
	return doc["steps"].(map[string]any)[name].(map[string]any)
}

func abAbout(value string) func(doc map[string]any) {
	return func(doc map[string]any) { abStep(doc, "secrets")["about"] = value }
}

// abRecorder records every digest the verify submits to a search.
type abRecorder struct {
	inner    source.Sourcer
	mu       sync.Mutex
	searched []string
}

func (r *abRecorder) Search(ctx context.Context, name string, digests, atts []string) ([]source.CollectionEnvelope, error) {
	r.mu.Lock()
	r.searched = append(r.searched, digests...)
	r.mu.Unlock()
	return r.inner.Search(ctx, name, digests, atts)
}

func (r *abRecorder) SearchByPredicateType(ctx context.Context, pts, digests []string) ([]source.StatementEnvelope, error) {
	r.mu.Lock()
	r.searched = append(r.searched, digests...)
	r.mu.Unlock()
	return r.inner.SearchByPredicateType(ctx, pts, digests)
}

func (r *abRecorder) searchedAny(substr string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.searched {
		if strings.Contains(d, substr) {
			return true
		}
	}
	return false
}

type abRun struct {
	att *Attestor
	rec *abRecorder
	err error
}

// abAttest signs policyJSON under payloadType and runs the real attestor over
// envs, seeded with seeds, optionally bound to a commit.
func abAttest(t *testing.T, k abKey, payloadType string, policyJSON []byte, envs map[string]dsse.Envelope, seeds []cryptoutil.DigestSet, binding string) abRun {
	t.Helper()
	polEnv, err := dsse.Sign(payloadType, bytes.NewReader(policyJSON), dsse.SignWithSigners(k.signer))
	require.NoError(t, err)
	mem := source.NewMemorySource()
	for ref, env := range envs {
		require.NoError(t, mem.LoadEnvelope(ref, env))
	}
	rec := &abRecorder{inner: mem}

	a := New()
	a.SetPolicyEnvelope(polEnv)
	a.SetPolicyVerificationOptions(policysig.NewVerifyPolicySignatureOptions(
		policysig.VerifyWithPolicyVerifiers([]cryptoutil.Verifier{k.verifier})))
	a.SetSubjectDigests(seeds)
	a.SetCollectionSource(rec)
	a.SetCommitBinding(binding)
	actx, err := attestation.NewContext("about-refusal", nil)
	require.NoError(t, err)
	return abRun{att: a, rec: rec, err: a.Attest(actx)}
}

func sha1Seed(v string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA1}: v}
}

func imageSeed() cryptoutil.DigestSet {
	return cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: abImage}
}

func requireRefusedBy(t *testing.T, err error, reason string) {
	t.Helper()
	require.Error(t, err)
	var refused policy.ErrPolicyRefused
	require.True(t, errors.As(err, &refused), "want policy.ErrPolicyRefused(%s), got: %v", reason, err)
	require.Equal(t, reason, refused.Reason)
	require.Contains(t, err.Error(), reason)
}

// R27f = PV8, through the attestor. Each arm is refused before any evidence
// is read. The corpus is one the policy PASSES on when accepted (C's own build
// and a clean scan, seeded by C), so an arm whose refusal is lost turns into a
// PASS, not into a coincidental FAIL: that is what M27f2 (the attestor back to
// json.Unmarshal) does to the unknown-type and unknown-field arms.
func TestR27f_PolicyVersionRefusalsThroughTheAttestor(t *testing.T) {
	k := newABKey(t)
	corpus := map[string]dsse.Envelope{
		"C-build":         abBuild(t, k, pvC, pvP),
		"C-secrets-clean": pvSigned(t, k.signer, "secrets", pvC, pvP, 0),
	}
	seeds := []cryptoutil.DigestSet{sha1Seed(pvC)}

	t.Run("control: v0.2 with about: source is accepted and passes", func(t *testing.T) {
		r := abAttest(t, k, uriPolicyV02, abPolicy(t, k, abAbout("source")), corpus, seeds, "")
		require.NoError(t, r.err)
		require.Equal(t, slsa.PassedVerificationResult, r.att.VerificationResult)
		require.Equal(t, uriPolicyV02, r.att.Policy.URI)
	})
	t.Run("control: the same policy without the v0.3 member, under v0.2, passes", func(t *testing.T) {
		r := abAttest(t, k, uriPolicyV02, abPolicy(t, k, nil), corpus, seeds, "")
		require.NoError(t, r.err)
		require.Equal(t, slsa.PassedVerificationResult, r.att.VerificationResult)
	})

	refusals := []struct {
		name        string
		payloadType string
		edit        func(doc map[string]any)
		reason      string // "" means a decode error, not a named refusal
		wantErrText string
	}{
		{"aflock v0.1 with about: source", uriPolicyV01, abAbout("source"), policy.ReasonAboutNeedsPolicyV02, ""},
		{"legacy witness v0.1 with about: source", uriPolicyLegacyV01, abAbout("source"), policy.ReasonAboutNeedsPolicyV02, ""},
		{"v0.2 with about: seed", uriPolicyV02, abAbout("seed"), policy.ReasonAboutUnknownValue, ""},
		{"unknown type v0.3 carrying a v0.3 restriction", "https://aflock.ai/policy/v0.3",
			func(doc map[string]any) { abStep(doc, "secrets")["seedMatch"] = "recomputed" }, policy.ReasonPolicyTypeUnknown, ""},
		{"v0.2 with an unknown member", uriPolicyV02,
			func(doc map[string]any) { abStep(doc, "secrets")["links"] = []any{map[string]any{"from": "build"}} }, "", `unknown field "links"`},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			r := abAttest(t, k, tc.payloadType, abPolicy(t, k, tc.edit), corpus, seeds, "")
			if tc.reason != "" {
				requireRefusedBy(t, r.err, tc.reason)
			} else {
				require.Error(t, r.err)
				require.Contains(t, r.err.Error(), tc.wantErrText)
			}
			require.Empty(t, r.rec.searched, "refused before any evidence is searched")
			require.Empty(t, r.att.StepResults())
			require.Empty(t, r.att.VerificationResult, "no verdict is written for a refused policy")
		})
	}
}

// About is a grant of reach, not a requirement, and today it grants nothing:
// the fail-closed direction, through the attestor.
//
// The corpus: C's build produced the image and records a commithash edge to
// C; C's clean secrets scan names C (sha1) but not the image. Seeded with the
// image alone, the only qualifying source evidence is reachable only through
// the build's commit. Until the declared source link lands (LA-4), an
// about: source step gets depth-0 witnesses only, so this FAILS, and the
// commit is never submitted to a search. A policy's About therefore cannot
// make a step PASS on evidence the same step without About would not reach.
//
// The control seeds C as well (the two-seed interim): then the step PASSES on
// the same scan, so the FAIL above is about reach, not a broken fixture.
//
// LA-4 must revisit this row: it is where the link, if it applies to this
// shape, turns FAIL into PASS on purpose.
func TestAboutSource_EvidenceOnlyThroughTheBuildsCommitFailsToday(t *testing.T) {
	k := newABKey(t)
	corpus := map[string]dsse.Envelope{
		"C-build":         abBuild(t, k, pvC, pvP),
		"C-secrets-clean": pvSigned(t, k.signer, "secrets", pvC, pvP, 0),
	}
	policies := []struct {
		name        string
		payloadType string
		edit        func(doc map[string]any)
	}{
		{"v0.2 with about: source", uriPolicyV02, abAbout("source")},
		{"v0.2 without about", uriPolicyV02, nil},
		{"aflock v0.1 without about", uriPolicyV01, nil},
	}
	for _, binding := range []string{"", pvC} {
		for _, p := range policies {
			t.Run(p.name+"/binding="+binding, func(t *testing.T) {
				r := abAttest(t, k, p.payloadType, abPolicy(t, k, p.edit), corpus, []cryptoutil.DigestSet{imageSeed()}, binding)
				require.NoError(t, r.err)
				require.Equal(t, slsa.FailedVerificationResult, r.att.VerificationResult,
					"the source scan is reachable only through the build's commit, which is not followed")
				results := r.att.StepResults()
				require.Len(t, results["build"].Passed, 1, "the image seed reaches the build that produced it")
				require.Empty(t, results["secrets"].Passed, "no depth-0 witness for the source step")
				require.True(t, r.rec.searchedAny(abImage), "the instrument sees the seed search")
				require.False(t, r.rec.searchedAny(pvC), "the build's commit must never become a search seed")

				control := abAttest(t, k, p.payloadType, abPolicy(t, k, p.edit), corpus,
					[]cryptoutil.DigestSet{imageSeed(), sha1Seed(pvC)}, binding)
				require.NoError(t, control.err)
				require.Equal(t, slsa.PassedVerificationResult, control.att.VerificationResult,
					"seeded with C too, the same scan is a qualifying witness")
				require.Len(t, control.att.StepResults()["secrets"].Passed, 1)
			})
		}
	}
}
