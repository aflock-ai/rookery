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

package policy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func mt(t time.Time) *metav1.Time { m := metav1.NewTime(t); return &m }

func TestTimestampConstraintValidate(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		c       *TimestampConstraint
		wantErr string
	}{
		{"nil constraint is valid", nil, ""},
		{"empty constraint rejected", &TimestampConstraint{}, "at least one of"},
		{"maxAge only", &TimestampConstraint{MaxAge: "720h"}, ""},
		{"bad maxAge", &TimestampConstraint{MaxAge: "30 days"}, "not a valid Go duration"},
		{"negative maxAge", &TimestampConstraint{MaxAge: "-1h"}, "must be positive"},
		{"zero maxAge", &TimestampConstraint{MaxAge: "0s"}, "must be positive"},
		{"window ok", &TimestampConstraint{NotBefore: mt(now.Add(-time.Hour)), NotAfter: mt(now)}, ""},
		{"inverted window", &TimestampConstraint{NotBefore: mt(now), NotAfter: mt(now.Add(-time.Hour))}, "is after notAfter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestTimestampConstraintCheck(t *testing.T) {
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-24 * time.Hour)
	stale := now.Add(-45 * 24 * time.Hour)
	future := now.Add(24 * time.Hour)

	tests := []struct {
		name    string
		c       *TimestampConstraint
		ts      []time.Time
		wantErr string
	}{
		{"nil constraint always passes (even without timestamps)", nil, nil, ""},
		{"fail-closed: constraint set but no verified TSA timestamp", &TimestampConstraint{MaxAge: "720h"}, nil, "fail-closed"},
		{"maxAge pass", &TimestampConstraint{MaxAge: "720h"}, []time.Time{fresh}, ""},
		{"maxAge expired", &TimestampConstraint{MaxAge: "720h"}, []time.Time{stale}, "exceeding the policy's maxAge"},
		{"earliest timestamp governs: re-timestamped stale evidence still fails maxAge", &TimestampConstraint{MaxAge: "720h"}, []time.Time{fresh, stale}, "exceeding the policy's maxAge"},
		{"window pass", &TimestampConstraint{NotBefore: mt(now.Add(-48 * time.Hour)), NotAfter: mt(now)}, []time.Time{fresh}, ""},
		{"window miss: too old", &TimestampConstraint{NotBefore: mt(now.Add(-48 * time.Hour)), NotAfter: mt(now)}, []time.Time{stale}, "before the policy's notBefore"},
		{"window miss: future timestamp beyond notAfter", &TimestampConstraint{NotBefore: mt(now.Add(-48 * time.Hour)), NotAfter: mt(now)}, []time.Time{future}, "after the policy's notAfter"},
		{"combined window + maxAge pass", &TimestampConstraint{NotBefore: mt(now.Add(-48 * time.Hour)), MaxAge: "720h"}, []time.Time{fresh}, ""},
		{"unparseable maxAge fails closed at check time", &TimestampConstraint{MaxAge: "bogus"}, []time.Time{fresh}, "not a valid Go duration"},
		{"future TSA timestamp cannot satisfy maxAge (fail-closed)", &TimestampConstraint{MaxAge: "720h"}, []time.Time{future}, "future-dated evidence cannot satisfy maxAge"},
		{"small clock skew within allowance passes maxAge", &TimestampConstraint{MaxAge: "720h"}, []time.Time{now.Add(2 * time.Minute)}, ""},
		{"future timestamp just past skew allowance rejected", &TimestampConstraint{MaxAge: "720h"}, []time.Time{now.Add(6 * time.Minute)}, "future-dated evidence cannot satisfy maxAge"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.Check(tt.ts, now)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

// TestPolicyValidateRejectsBadTimestampConstraint proves a malformed
// constraint fails at policy load, not at verify time.
func TestPolicyValidateRejectsBadTimestampConstraint(t *testing.T) {
	p := Policy{
		Steps: map[string]Step{
			"scan": {
				Name:                "scan",
				TimestampConstraint: &TimestampConstraint{MaxAge: "30 days"},
			},
		},
	}
	err := p.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `step "scan"`)
	assert.Contains(t, err.Error(), "not a valid Go duration")
}

// TestCheckFunctionariesEnforcesTimestampConstraint proves the verifier-level
// wiring: a collection that passes functionary validation is still rejected
// when the step's timestampConstraint is unsatisfied, and the rejection
// reason names the constraint. Uses a nil-functionary-free fake: we exercise
// checkFunctionaries with a statement that has a passing verifier and a
// permissive functionary, varying only VerifiedTimestamps.
func TestCheckFunctionariesEnforcesTimestampConstraint(t *testing.T) {
	now := time.Now()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	makeStatement := func(ts []time.Time) source.CollectionVerificationResult {
		byKey := map[string][]time.Time{}
		if len(ts) > 0 {
			byKey[keyID] = ts
		}
		return source.CollectionVerificationResult{
			CollectionEnvelope: source.CollectionEnvelope{
				Statement: intoto.Statement{PredicateType: attestation.CollectionType},
			},
			Verifiers:                 []cryptoutil.Verifier{verifier},
			VerifiedTimestampsByKeyID: byKey,
		}
	}

	step := Step{
		Name:                "scan",
		Functionaries:       []Functionary{{PublicKeyID: keyID}},
		TimestampConstraint: &TimestampConstraint{MaxAge: "720h"},
	}

	t.Run("fresh TSA timestamp passes", func(t *testing.T) {
		res := step.checkFunctionaries([]source.CollectionVerificationResult{makeStatement([]time.Time{now.Add(-time.Hour)})}, nil)
		assert.Len(t, res.Passed, 1)
		assert.Empty(t, res.Rejected)
	})

	t.Run("stale TSA timestamp rejected", func(t *testing.T) {
		res := step.checkFunctionaries([]source.CollectionVerificationResult{makeStatement([]time.Time{now.Add(-31 * 24 * time.Hour)})}, nil)
		assert.Empty(t, res.Passed)
		require.Len(t, res.Rejected, 1)
		assert.Contains(t, res.Rejected[0].Reason.Error(), "timestamp constraint failed for step scan")
	})

	t.Run("no verified TSA timestamp rejected fail-closed", func(t *testing.T) {
		res := step.checkFunctionaries([]source.CollectionVerificationResult{makeStatement(nil)}, nil)
		assert.Empty(t, res.Passed)
		require.Len(t, res.Rejected, 1)
		assert.True(t, strings.Contains(res.Rejected[0].Reason.Error(), "fail-closed"), res.Rejected[0].Reason.Error())
	})

	t.Run("fresh timestamp on a NON-functionary signature cannot satisfy the constraint", func(t *testing.T) {
		// Multi-signature envelope: the functionary's signature is
		// untimestamped, but another (accepted-signature, non-functionary)
		// verifier carries a fresh TSA token. The constraint must still
		// fail closed for the functionary-matched signature.
		otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		otherVerifier := cryptoutil.NewECDSAVerifier(&otherPriv.PublicKey, crypto.SHA256)
		otherKeyID, err := otherVerifier.KeyID()
		require.NoError(t, err)

		stmt := source.CollectionVerificationResult{
			CollectionEnvelope: source.CollectionEnvelope{
				Statement: intoto.Statement{PredicateType: attestation.CollectionType},
			},
			Verifiers: []cryptoutil.Verifier{verifier, otherVerifier},
			VerifiedTimestampsByKeyID: map[string][]time.Time{
				otherKeyID: {now.Add(-time.Hour)},
			},
		}
		res := step.checkFunctionaries([]source.CollectionVerificationResult{stmt}, nil)
		assert.Empty(t, res.Passed)
		require.Len(t, res.Rejected, 1)
		assert.Contains(t, res.Rejected[0].Reason.Error(), "fail-closed")
	})

	t.Run("no constraint leaves behavior unchanged", func(t *testing.T) {
		unconstrained := Step{Name: "scan", Functionaries: step.Functionaries}
		res := unconstrained.checkFunctionaries([]source.CollectionVerificationResult{makeStatement(nil)}, nil)
		assert.Len(t, res.Passed, 1)
		assert.Empty(t, res.Rejected)
	})
}
