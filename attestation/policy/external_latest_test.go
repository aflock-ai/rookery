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

package policy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// The vectors of `nested_closes_holes` in formal/cilock-evaluators
// CilockEvaluators/Nested.lean, in seconds from a common epoch. Random cases
// run against that model in TestFormalDifferentialVSA.

var (
	digestVex    = strings.Repeat("a", 64)
	digestGithub = strings.Repeat("b", 64)
	epoch        = time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)
)

type childVSA struct {
	digest string
	passed bool
	tsa    *int // seconds after epoch; nil = no TSA time
}

func at(s int) *int { return &s }

// patchedPass runs one external over child VSAs the way verifyExternalAttestations
// does in nested mode: admit, record each candidate's verdict, let the latest decide.
func patchedPass(t *testing.T, now int, ext ExternalAttestation, vsas []childVSA) bool {
	t.Helper()
	return judgeNested(t, time.Second, now, ext, vsas)
}

func judgeNested(t *testing.T, unit time.Duration, now int, ext ExternalAttestation, vsas []childVSA) bool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	v := cryptoutil.NewECDSAVerifier(&key.PublicKey, crypto.SHA256)
	kid, err := v.KeyID()
	require.NoError(t, err)

	er := ExternalResult{Name: ext.Name}
	var cands []latestCandidate
	for i, c := range vsas {
		// An honest signer: the signed timeVerified is the moment the token
		// was taken (an untimed VSA still claims one; it has no token).
		signed := epoch
		if c.tsa != nil {
			signed = epoch.Add(time.Duration(*c.tsa) * unit)
		}
		env := source.StatementEnvelope{
			Reference: fmt.Sprintf("vsa-%d", i),
			Envelope: dsse.Envelope{Payload: []byte(fmt.Sprintf(`{"predicate":{"timeVerified":%q,"policy":{"digest":{"sha256":%q}}},"n":%d}`,
				signed.UTC().Format(time.RFC3339), c.digest, i))},
		}
		if c.tsa != nil {
			env.VerifiedTimestampsByKeyID = map[string][]time.Time{kid: {epoch.Add(time.Duration(*c.tsa) * unit)}}
		}
		tm, unbound, err := admitExternal(ext, env, []cryptoutil.Verifier{v}, epoch.Add(time.Duration(now)*unit))
		if unbound || err != nil {
			continue
		}
		cands = append(cands, latestCandidate{key: envelopeKey(env), at: tm, passed: c.passed})
		if c.passed {
			er.Passed = append(er.Passed, PassedExternal{Envelope: env})
		} else {
			er.Rejected = append(er.Rejected, RejectedExternal{Envelope: env, Reason: fmt.Errorf("rego deny")})
		}
	}
	decideLatest(&er, cands)
	return er.Analyze()
}

func child(name, digest string) ExternalAttestation {
	return ExternalAttestation{Name: name, ChildPolicyDigest: digest, TimestampConstraint: &TimestampConstraint{MaxAge: "86400s"}}
}

func TestNestedClosesStockHoles(t *testing.T) {
	vex, gh := child("vex", digestVex), child("github", digestGithub)
	both := []childVSA{{digestVex, true, at(100)}, {digestGithub, false, at(100)}}

	// (a) one child's passing VSA no longer satisfies another child's external.
	require.True(t, patchedPass(t, 150, vex, both))
	require.False(t, patchedPass(t, 150, gh, both), "a passing VSA of another child masked the failing one")

	// (b) a child VSA without a TSA time never decides.
	require.False(t, patchedPass(t, 150, vex, []childVSA{{digestVex, true, nil}}))

	// (c) an older passing VSA does not mask a newer failing one.
	require.False(t, patchedPass(t, 150, vex, []childVSA{{digestVex, true, at(10)}, {digestVex, false, at(20)}}))
	require.True(t, patchedPass(t, 150, vex, []childVSA{{digestVex, false, at(10)}, {digestVex, true, at(20)}}), "a newer pass supersedes an older failure")

	// Outside maxAge nothing is admitted.
	require.False(t, patchedPass(t, 100000, vex, []childVSA{{digestVex, true, at(10)}}))

	// A tie at the latest time fails if any of them failed, in either order.
	require.False(t, patchedPass(t, 150, vex, []childVSA{{digestVex, true, at(20)}, {digestVex, false, at(20)}}))
	require.False(t, patchedPass(t, 150, vex, []childVSA{{digestVex, false, at(20)}, {digestVex, true, at(20)}}))
}

// The attacker's capability: a DSSE signature's timestamps are not signed, so
// anyone who can download an envelope can re-publish the same signature bytes
// with a fresh token. Ordered by TSA time, the old passing VSA would outrank
// the newer failing one. It decides at its signed timeVerified instead, and a
// signed time after the token's is refused.
func TestNestedSignedTimeDecidesNotTheToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	v := cryptoutil.NewECDSAVerifier(&key.PublicKey, crypto.SHA256)
	kid, err := v.KeyID()
	require.NoError(t, err)
	vex := child("vex", digestVex)
	now := epoch.Add(3600 * time.Second)
	vsa := func(ref string, passed bool, signed, stamped int) (latestCandidate, PassedExternal, error) {
		env := source.StatementEnvelope{
			Reference: ref,
			Envelope: dsse.Envelope{Payload: []byte(fmt.Sprintf(`{"predicate":{"timeVerified":%q,"policy":{"digest":{"sha256":%q}}},"passed":%v}`,
				epoch.Add(time.Duration(signed)*time.Second).UTC().Format(time.RFC3339), digestVex, passed))},
			VerifiedTimestampsByKeyID: map[string][]time.Time{kid: {epoch.Add(time.Duration(stamped) * time.Second)}},
		}
		at, unbound, err := admitExternal(vex, env, []cryptoutil.Verifier{v}, now)
		require.False(t, unbound)
		return latestCandidate{key: envelopeKey(env), at: at, passed: passed}, PassedExternal{Envelope: env}, err
	}

	oldPass, oldEnv, err := vsa("old-pass", true, 10, 10)
	require.NoError(t, err)
	newFail, _, err := vsa("new-fail", false, 20, 20)
	require.NoError(t, err)
	restamped, restampedEnv, err := vsa("old-pass-restamped", true, 10, 3500)
	require.NoError(t, err)
	require.Equal(t, oldPass.at, restamped.at, "a fresh token must not move the signed time")

	er := ExternalResult{Name: "vex", Passed: []PassedExternal{oldEnv, restampedEnv}}
	decideLatest(&er, []latestCandidate{oldPass, newFail, restamped})
	require.False(t, er.Analyze(), "the re-stamped old pass outranked the newer failure")

	_, _, err = vsa("forward-dated", true, 3500, 20)
	require.ErrorContains(t, err, "after its own RFC3161 time")

	// A stale verdict with a fresh token is judged by its signed time too.
	stale := ExternalAttestation{Name: "vex", ChildPolicyDigest: digestVex, TimestampConstraint: &TimestampConstraint{MaxAge: "1000s"}}
	env := source.StatementEnvelope{
		Reference: "stale-restamped",
		Envelope: dsse.Envelope{Payload: []byte(fmt.Sprintf(`{"predicate":{"timeVerified":%q,"policy":{"digest":{"sha256":%q}}}}`,
			epoch.Add(10*time.Second).UTC().Format(time.RFC3339), digestVex))},
		VerifiedTimestampsByKeyID: map[string][]time.Time{kid: {epoch.Add(3500 * time.Second)}},
	}
	_, _, err = admitExternal(stale, env, []cryptoutil.Verifier{v}, now)
	require.ErrorContains(t, err, "signed timeVerified")

	// No signed time, no candidate.
	env.Envelope.Payload = []byte(fmt.Sprintf(`{"predicate":{"policy":{"digest":{"sha256":%q}}}}`, digestVex))
	_, _, err = admitExternal(vex, env, []cryptoutil.Verifier{v}, now)
	require.ErrorContains(t, err, "predicate.timeVerified")
}

func TestNestedOnlyLatestStaysPassed(t *testing.T) {
	older := source.StatementEnvelope{Reference: "old", Envelope: dsse.Envelope{Payload: []byte("1")}}
	newer := source.StatementEnvelope{Reference: "new", Envelope: dsse.Envelope{Payload: []byte("2")}}
	er := ExternalResult{Passed: []PassedExternal{{Envelope: older}, {Envelope: newer}}}
	decideLatest(&er, []latestCandidate{{envelopeKey(older), epoch, true}, {envelopeKey(newer), epoch.Add(time.Hour), true}})
	require.Len(t, er.Passed, 1)
	require.Equal(t, "new", er.Passed[0].Envelope.Reference, "steps reading input.external must see the current child VSA")
	require.Len(t, er.Rejected, 1)
	require.Contains(t, er.Rejected[0].Reason.Error(), "superseded")
}

func TestNestedValidate(t *testing.T) {
	require.NoError(t, ExternalAttestation{ChildPolicyDigest: digestVex}.ValidateNested())
	require.Error(t, ExternalAttestation{ChildPolicyDigest: "ABC"}.ValidateNested())
	require.Error(t, ExternalAttestation{TimestampConstraint: &TimestampConstraint{MaxAge: "-1h"}}.ValidateNested())
	require.False(t, ExternalAttestation{}.latestDecides(), "stock externals keep stock semantics")
}
