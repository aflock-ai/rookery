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
//
// ============================================================================
// Fail-closed acceptance tests for #5746 (cert-constraint matching).
//
// Each test asserts the CORRECT, FAIL-CLOSED behavior. They were RED against
// the pre-fix code and pass once the constraints.go fixes land. They are the
// inverse of the (now-flipped) characterization tests in
// constraints_adversarial_test.go and run in the DEFAULT suite (no build tag)
// so the CI/merge-queue gate enforces them.
//
//   F1  duplicate constraints must NOT collapse via map dedup
//   F4  a subset of required values must FAIL
//   F5  an empty single-value constraint must NOT mean allow-all
//   F11 empty-string normalization applies at all positions
//   F14 CertConstraint.Check short-circuits on the first failure
// ============================================================================

package policy

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// F1 (#5746, HIGH) — constraints.go checkCertConstraint
// Fail-closed contract: duplicate constraints must NOT collapse via map dedup.
// constraints=[A,A] requires TWO matching cert values; values=[A] must FAIL.
// ---------------------------------------------------------------------------
func TestRed_F1_DuplicateConstraintsMustNotCollapse(t *testing.T) {
	err := checkCertConstraint("org", []string{"ACME", "ACME"}, []string{"ACME"})
	assert.Error(t, err,
		"duplicate constraints [ACME,ACME] must not be deduplicated; a cert with only one ACME must fail")

	err = checkCertConstraint("org", []string{"A", "A", "B"}, []string{"A", "B"})
	assert.Error(t, err,
		"constraints [A,A,B] require three values; cert with [A,B] must fail (no silent dedup)")
}

// ---------------------------------------------------------------------------
// F4 (#5746, HIGH) — constraints.go checkCertConstraint (AllowAll path)
// Fail-closed contract: a single empty-string constraint must NOT behave like
// "allow any". With the duplicate-collapse fixed (F1), a subset of required
// values must be rejected. Here: constraint requires two DISTINCT values but
// the cert presents only one — must FAIL (no subset acceptance).
// ---------------------------------------------------------------------------
func TestRed_F4_SubsetMatchMustFail(t *testing.T) {
	// Cert is missing one of two required, distinct constraint values.
	err := checkCertConstraint("org", []string{"ACME", "Globex"}, []string{"ACME"})
	assert.Error(t, err, "cert missing required constraint value 'Globex' must fail")

	// And the duplicate-constraint subset vector (folds finding F1's exploit):
	err = checkCertConstraint("org", []string{"ACME", "ACME"}, []string{"ACME"})
	assert.Error(t, err, "two required ACME values not satisfied by a single cert ACME")
}

// ---------------------------------------------------------------------------
// F5 (#5746, HIGH) — constraints.go checkCertConstraintGlob
// Fail-closed contract: an EMPTY single-value constraint must NOT default to
// "allow all". A policy author who forgets/empties CommonName must NOT silently
// accept an attacker-controlled CN.
// ---------------------------------------------------------------------------
func TestRed_F5_EmptyGlobConstraintMustNotAllowAll(t *testing.T) {
	err := checkCertConstraintGlob("common name", "", "evil-cn.attacker.com")
	assert.Error(t, err,
		"an empty CommonName constraint must fail closed, not allow any value; require explicit '*' to allow all")
}

// ---------------------------------------------------------------------------
// F11 (#5746, MEDIUM) — constraints.go checkCertConstraint
// Fail-closed contract: empty-string normalization must apply to all positions,
// not just index 0. constraints=["", "real"] with cert values=["real"] (no
// empty value) must be treated as requiring "real" only; it must NOT require the
// cert to literally present an empty value. Asserts the cert that presents
// exactly "real" is accepted when "" is normalized away.
// ---------------------------------------------------------------------------
func TestRed_F11_EmptyStringNormalizationAllPositions(t *testing.T) {
	err := checkCertConstraint("org", []string{"", "real"}, []string{"real"})
	assert.NoError(t, err,
		"an empty-string constraint element must normalize away at any position; cert presenting only 'real' should pass")
}

// ---------------------------------------------------------------------------
// F14 (#5746, HIGH) — constraints.go CertConstraint.Check (short-circuit)
// Fail-closed contract: Check must short-circuit on the first failing
// constraint and NOT run the remaining checks (avoids cert-detail leakage via
// accumulated errors + needless trust-bundle work). On a cert that fails the
// CommonName check, Check must surface exactly ONE underlying error, not many.
// ---------------------------------------------------------------------------
func TestRed_F14_CheckShortCircuitsOnFirstFailure(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "wrong-cn", []string{"WrongOrg"}, []string{"wrong@email.com"}, []string{"wrong.dns"})
	verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	cc := CertConstraint{
		CommonName:    "expected-cn",
		Organizations: []string{"ExpectedOrg"},
		Emails:        []string{"expected@email.com"},
		DNSNames:      []string{"expected.dns"},
		Roots:         []string{"root1"},
	}
	err = cc.Check(verifier, map[string]TrustBundle{"root1": {Root: ca}})
	require.Error(t, err)

	var constraintErr ErrConstraintCheckFailed
	if assert.ErrorAs(t, err, &constraintErr) {
		assert.LessOrEqual(t, len(constraintErr.errs), 1,
			"Check must short-circuit on the first failing constraint and not accumulate every check's error")
	}
}
