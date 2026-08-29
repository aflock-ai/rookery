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

package dsse

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/stretchr/testify/require"
)

// THE GATE THAT OUTRAN ITS CERTIFICATE. A Fulcio leaf lives about ten
// minutes; a signing step that starts after the leaf expired still produces
// a signature, and the TSA still stamps it, so the envelope carries a
// timestamp that verifies and a certificate that was dead at that time. This
// is the most common way a real-world attestation is definitively invalid,
// and the verifier used to report it as "no valid timestamps found" — the
// timestamp was fine; the certificate was not valid at it — dropping the
// x509 cause on the floor at Debug level. The error must name what happened,
// with the two times, so the platform can put "certificate expired at X
// before signing at Y" in a signed verdict rather than "retry".
func TestVerify_CertExpiredBeforeTimestampedSigning_NamesTheExpiry(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	// Valid for one hour, ending an hour ago: expired at now-1h.
	root, leaf, leafPriv := failClosedCertChain(t, now.Add(-2*time.Hour), time.Hour)

	// The timestamper says the signature was made NOW, an hour after expiry.
	ft := timestamp.FakeTimestamper{T: now}

	s, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf))
	require.NoError(t, err)

	env, err := Sign("test", bytes.NewReader([]byte("late-payload")),
		SignWithSigners(s),
		SignWithTimestampers(ft))
	require.NoError(t, err)

	_, err = env.Verify(
		VerifyWithRoots(root),
		VerifyWithThreshold(1),
		VerifyWithTimestampVerifiers(ft),
	)
	require.Error(t, err, "a certificate that expired before the timestamped signing time must not verify")

	var noSigs ErrNoMatchingSigs
	require.True(t, errors.As(err, &noSigs), "the failure must be ErrNoMatchingSigs, got %T: %v", err, err)
	require.NotEmpty(t, noSigs.Verifiers, "the rejected signature must be reported, not dropped")

	var expired ErrCertNotValidAtSigningTime
	found := false
	for _, v := range noSigs.Verifiers {
		if errors.As(v.Error, &expired) {
			found = true
			break
		}
	}
	require.True(t, found, "the per-signature error must be ErrCertNotValidAtSigningTime, got: %v", err)
	require.Equal(t, now, expired.SignedAt.UTC().Truncate(time.Second).In(now.Location()),
		"the error must carry the timestamped signing time")
	require.Equal(t, leaf.NotAfter.Truncate(time.Second), expired.NotAfter.Truncate(time.Second),
		"the error must carry the certificate's NotAfter")
	require.Contains(t, expired.Error(), "certificate expired at",
		"the message must say the certificate expired, not that no timestamp was valid")
	require.Contains(t, err.Error(), "certificate expired at",
		"the top-level error must surface the expiry through ErrNoMatchingSigs")
	require.False(t, strings.Contains(err.Error(), "no valid timestamps found"),
		"the timestamp WAS valid; the message must not blame it: %v", err)
}

// A certificate whose window had not yet OPENED at the timestamped time is the
// same class of definitive failure, said the other way round.
func TestVerify_CertNotYetValidAtTimestampedSigning_SaysNotYetValid(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	root, leaf, leafPriv := failClosedCertChain(t, now.Add(time.Hour), time.Hour)
	ft := timestamp.FakeTimestamper{T: now}

	s, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf))
	require.NoError(t, err)
	env, err := Sign("test", bytes.NewReader([]byte("early-payload")),
		SignWithSigners(s), SignWithTimestampers(ft))
	require.NoError(t, err)

	_, err = env.Verify(VerifyWithRoots(root), VerifyWithThreshold(1), VerifyWithTimestampVerifiers(ft))
	require.Error(t, err)
	require.Contains(t, err.Error(), "not yet valid", "got: %v", err)
	var noSigs ErrNoMatchingSigs
	require.True(t, errors.As(err, &noSigs))
	var early ErrCertNotValidAtSigningTime
	found := false
	for _, v := range noSigs.Verifiers {
		if errors.As(v.Error, &early) {
			found = true
		}
	}
	require.True(t, found)
	require.Equal(t, leaf.NotBefore.Truncate(time.Second), early.NotBefore.Truncate(time.Second))
}
