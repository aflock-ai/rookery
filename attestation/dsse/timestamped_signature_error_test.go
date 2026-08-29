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
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"
)

// ErrCertNotValidAtSigningTime CARRIES DATES, and dates that name the wrong
// certificate are worse than no dates: they are a specific, checkable, false
// statement about which credential died and when. Its Error() also PICKS THE
// DIAGNOSIS by comparing SignedAt to those dates, so the wrong pair does not
// merely misreport the times — it can invert "expired" into "not yet valid".
//
// x509 reports which certificate failed in CertificateInvalidError.Cert, and
// for a chain that may be an INTERMEDIATE while the leaf is still comfortably
// inside its own window. These pin the rule: the structured error is produced
// only from the certificate that actually failed, and only when that
// certificate's own dates explain the failure.

func certValid(notBefore, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}
}

// The reported shape: an intermediate expired, the leaf did not. The error
// must name the INTERMEDIATE's window.
func TestTimestampedSignatureError_UsesTheCertificateThatActuallyFailed(t *testing.T) {
	signedAt := time.Date(2026, 8, 27, 10, 12, 0, 0, time.UTC)

	// The leaf is alive at signing time. If the leaf's dates were used, no
	// structured error would be produced at all.
	leaf := certValid(signedAt.Add(-5*time.Minute), signedAt.Add(5*time.Minute))
	// The intermediate expired an hour before signing.
	intermediate := certValid(signedAt.Add(-48*time.Hour), signedAt.Add(-time.Hour))

	err := timestampedSignatureError(leaf, signedAt,
		x509.CertificateInvalidError{Cert: intermediate, Reason: x509.Expired})

	var got ErrCertNotValidAtSigningTime
	if !errors.As(err, &got) {
		t.Fatalf("an expired intermediate must still be reported as a signing-time validity failure, got %T: %v", err, err)
	}
	if !got.NotAfter.Equal(intermediate.NotAfter) {
		t.Fatalf("the error must carry the FAILED certificate's expiry %s, got %s (leaf's is %s)",
			intermediate.NotAfter, got.NotAfter, leaf.NotAfter)
	}
	if !got.NotBefore.Equal(intermediate.NotBefore) {
		t.Fatalf("the error must carry the FAILED certificate's NotBefore %s, got %s", intermediate.NotBefore, got.NotBefore)
	}
}

// THE DIAGNOSIS INVERSION. Error() chooses its wording by comparing SignedAt
// to NotAfter. Take the leaf's dates from a leaf that is not yet valid, while
// the certificate that actually failed had EXPIRED, and the message flips to
// exactly the wrong claim.
func TestTimestampedSignatureError_DoesNotInvertTheDiagnosis(t *testing.T) {
	signedAt := time.Date(2026, 8, 27, 10, 12, 0, 0, time.UTC)

	// A leaf whose window starts AFTER signing: on the leaf's dates, the
	// verdict would read "not yet valid".
	leaf := certValid(signedAt.Add(time.Hour), signedAt.Add(2*time.Hour))
	// The certificate that actually failed had expired.
	intermediate := certValid(signedAt.Add(-48*time.Hour), signedAt.Add(-time.Hour))

	err := timestampedSignatureError(leaf, signedAt,
		x509.CertificateInvalidError{Cert: intermediate, Reason: x509.Expired})

	msg := err.Error()
	if strings.Contains(msg, "not yet valid") {
		t.Fatalf("the failed certificate EXPIRED; reporting the leaf's window inverts the diagnosis: %s", msg)
	}
	if !strings.Contains(msg, "expired at 2026-08-27T09:12:00Z") {
		t.Fatalf("the message must name the failed certificate's expiry: %s", msg)
	}
}

// A STRUCTURED ERROR ONLY WHEN ITS OWN FIELDS EXPLAIN THE FAILURE. x509 can
// reach Expired by a route these dates do not account for; claiming a
// validity window that CONTAINS the signing time would be self-contradictory
// evidence — the reader can see the time is inside the window and yet is told
// the window is the reason.
func TestTimestampedSignatureError_KeepsTheCauseWhenTheDatesDoNotExplainIt(t *testing.T) {
	signedAt := time.Date(2026, 8, 27, 10, 12, 0, 0, time.UTC)
	alive := certValid(signedAt.Add(-time.Hour), signedAt.Add(time.Hour))

	cause := x509.CertificateInvalidError{Cert: alive, Reason: x509.Expired}
	err := timestampedSignatureError(alive, signedAt, cause)

	var got ErrCertNotValidAtSigningTime
	if errors.As(err, &got) {
		t.Fatalf("signing time %s is inside [%s, %s]; those dates cannot be the reason, so the "+
			"original cause must be preserved instead of a self-contradictory window: %+v",
			signedAt, alive.NotBefore, alive.NotAfter, got)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("the original x509 cause must survive: %v", err)
	}
}

// With no certificate named in the error, the leaf is the only candidate and
// the same "must explain it" rule applies.
func TestTimestampedSignatureError_FallsBackToTheLeafWhenNoneIsNamed(t *testing.T) {
	signedAt := time.Date(2026, 8, 27, 10, 12, 0, 0, time.UTC)
	dead := certValid(signedAt.Add(-48*time.Hour), signedAt.Add(-time.Hour))

	err := timestampedSignatureError(dead, signedAt, x509.CertificateInvalidError{Reason: x509.Expired})

	var got ErrCertNotValidAtSigningTime
	if !errors.As(err, &got) {
		t.Fatalf("with no cert named, the leaf's own expiry still explains the failure: %T %v", err, err)
	}
	if !got.NotAfter.Equal(dead.NotAfter) {
		t.Fatalf("want the leaf's expiry %s, got %s", dead.NotAfter, got.NotAfter)
	}
}

// A non-Expired reason is never dressed up as a validity-window failure.
func TestTimestampedSignatureError_LeavesOtherReasonsAlone(t *testing.T) {
	signedAt := time.Date(2026, 8, 27, 10, 12, 0, 0, time.UTC)
	dead := certValid(signedAt.Add(-48*time.Hour), signedAt.Add(-time.Hour))

	err := timestampedSignatureError(dead, signedAt,
		x509.CertificateInvalidError{Cert: dead, Reason: x509.CANotAuthorizedForThisName})

	var got ErrCertNotValidAtSigningTime
	if errors.As(err, &got) {
		t.Fatalf("an authorization failure is not a validity-window failure: %+v", got)
	}
}
