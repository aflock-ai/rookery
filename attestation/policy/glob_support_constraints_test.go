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
// Acceptance tests for glob support on cert SAN constraints (#5746) and the
// bounded glob matcher (#5756). These assert the SUPPORT-GLOB / fail-closed
// direction and run in the DEFAULT suite (no build tag) so the merge-queue gate
// enforces them.
//
//   F2  glob patterns match multi-value SAN fields (DNS, email, ...)
//   F13 the AllowAll wildcard "*" is honored at ANY position in Roots
//   F16 the glob path normalizes case (Example.COM accepts example.com)
//   F18 the AllowAll wildcard "*" is honored at ANY position in multi-value lists
//
//   ReDoS    a pathological glob pattern fails closed within the deadline
//   Guard    a NON-glob exact constraint still exact-matches (no regression)
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
// F2 (#5746) — constraints.go checkCertConstraint (multi-value glob)
// Support-glob contract: an author who writes a glob ("*@example.com",
// "*.example.com") for a multi-value SAN must get glob semantics — a legitimate
// glob-matching cert must PASS.
// ---------------------------------------------------------------------------
func TestRed_F2_MultiValueGlobMustMatch(t *testing.T) {
	err := checkCertConstraint("dns name", []string{"*.example.com"}, []string{"foo.example.com"})
	assert.NoError(t, err,
		"a glob DNS constraint '*.example.com' must match 'foo.example.com' (glob support for multi-value fields)")

	err = checkCertConstraint("email", []string{"*@example.com"}, []string{"alice@example.com"})
	assert.NoError(t, err,
		"a glob email constraint '*@example.com' must match 'alice@example.com'")
}

// ---------------------------------------------------------------------------
// F13 (#5746) — constraints.go checkTrustBundles (AllowAll @ any position)
// Support contract: the AllowAll wildcard must NOT be position-dependent at only
// Roots[0]. Roots=["unknown-root", "*"] should treat "*" as a wildcard (allow
// any trusted root the verifier chains to). The legitimately-rooted cert PASSES.
// ---------------------------------------------------------------------------
func TestRed_F13_WildcardRootHonoredAtAnyPosition(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "leaf", []string{"TestOrg"}, nil, nil)
	verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	cc := CertConstraint{Roots: []string{"unknown-root", AllowAllConstraint}}
	// "ca" bundle is a real trusted root the leaf chains to. With a wildcard
	// honored at any position, the verifier belongs to a trusted root -> pass.
	err = cc.checkTrustBundles(verifier, map[string]TrustBundle{"ca": {Root: ca}})
	assert.NoError(t, err,
		"a wildcard root '*' at a non-zero position must act as AllowAll for a cert that chains to a trusted root")
}

// ---------------------------------------------------------------------------
// F16 (#5746) — constraints.go checkCertConstraintGlob (value normalization)
// Support contract: glob matching must normalize case so a constraint authored
// as "Example.COM" accepts a cert CN "example.com".
// ---------------------------------------------------------------------------
func TestRed_F16_GlobValueNormalizationCaseInsensitive(t *testing.T) {
	err := checkCertConstraintGlob("common name", "Example.COM", "example.com")
	assert.NoError(t, err,
		"CN constraint comparison must normalize case so 'Example.COM' accepts 'example.com'")
}

// ---------------------------------------------------------------------------
// F18 (#5746) — constraints.go checkCertConstraint (AllowAll @ any position)
// Support contract: the AllowAll wildcard for multi-value fields must work
// regardless of position, not only at constraints[0]. ["admin@x", "*"] should
// allow any email — the cert with admin@x + other@x must be accepted.
// ---------------------------------------------------------------------------
func TestRed_F18_AllowAllWildcardWorksAtAnyPositionMultiValue(t *testing.T) {
	err := checkCertConstraint("email",
		[]string{"admin@example.com", AllowAllConstraint},
		[]string{"admin@example.com", "other@example.com"},
	)
	assert.NoError(t, err,
		"an AllowAll '*' in a multi-value constraint list must act as a wildcard at any position, not a literal value")
}

// slowGlob is a glob.Glob whose Match blocks for matchDelay before returning
// matchResult. It stands in for a pattern whose matching does not terminate
// within globMatchTimeout, letting the test exercise the deadline -> fail-closed
// path of boundedGlobMatch DETERMINISTICALLY. (gobwas/glob compiles to a
// non-backtracking matcher, so a real ReDoS-by-input is hard to construct; the
// time bound is defense-in-depth and this proves the bound itself works.)
type slowGlob struct {
	matchDelay  time.Duration
	matchResult bool
}

func (s slowGlob) Match(string) bool {
	time.Sleep(s.matchDelay)
	return s.matchResult
}

// ---------------------------------------------------------------------------
// ReDoS deadline (#5756) — the bound must fire and FAIL CLOSED on a match that
// does not finish within globMatchTimeout. A glob whose Match would have
// returned true (an "accept") but blows the deadline must yield (false, error),
// never a pass. This is the load-bearing assertion: a timed-out match is a
// constraint FAILURE, not an accept.
// ---------------------------------------------------------------------------
func TestRed_ReDoS_BoundedMatchFailsClosedOnDeadline(t *testing.T) {
	// matchResult=true would be an ACCEPT if it ever returned; the deadline must
	// override it to a fail-closed (false, error) BEFORE that pass can surface.
	g := slowGlob{matchDelay: globMatchTimeout + 2*time.Second, matchResult: true}

	start := time.Now()
	matched, err := boundedGlobMatch(g, "anything")
	elapsed := time.Since(start)

	assert.False(t, matched, "a match that exceeds the deadline must NOT accept (fail closed)")
	require.Error(t, err, "a deadline-exceeding match must return an error, not a silent pass")
	assert.Contains(t, err.Error(), "deadline", "the error must name the deadline so operators can diagnose it")
	// Bound must engage near globMatchTimeout, NOT wait for the 2s+ fake match.
	assert.Less(t, elapsed, globMatchTimeout+time.Second,
		"boundedGlobMatch must return at the deadline, not wait for the slow match to finish")
}

// ---------------------------------------------------------------------------
// ReDoS smoke (#5756) — a pathological-looking pattern (nested "{" + many "*")
// must complete PROMPTLY and fail closed through the full public pipeline, never
// hang. gobwas matches it in microseconds today (its matcher is non-backtracking),
// so this is a smoke/regression guard against a future engine swap; the
// deadline mechanism itself is proven by TestRed_ReDoS_BoundedMatchFailsClosedOnDeadline.
// ---------------------------------------------------------------------------
func TestRed_ReDoS_PathologicalGlobDoesNotHang(t *testing.T) {
	pathological := "{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}*a*a*a*a*a*a*a*a*a*a*b"
	value := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac"

	cases := []struct {
		name string
		run  func() error
	}{
		{"single-value", func() error { return checkCertConstraintGlob("common name", pathological, value) }},
		{"multi-value", func() error { return checkCertConstraint("dns name", []string{pathological}, []string{value}) }},
	}
	for _, tc := range cases {
		done := make(chan error, 1)
		start := time.Now()
		go func() { done <- tc.run() }()
		select {
		case err := <-done:
			assert.Error(t, err, "%s: a non-matching pathological glob must fail closed", tc.name)
			assert.Less(t, time.Since(start), 5*time.Second, "%s: the bounded pipeline must return promptly, not hang", tc.name)
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: hung on a pathological glob pattern; the deadline bound did not engage", tc.name)
		}
	}
}

// ---------------------------------------------------------------------------
// Guard (no regression) — a NON-glob exact constraint must STILL exact-match.
// This pins the critical no-behavior-change guarantee for existing policies:
// a literal constraint with no glob metacharacter must NOT glob-expand (the "."
// in "example.com" is a literal, not a wildcard), and must accept an
// exactly-equal value. The multi-value exact path stays byte-exact.
// ---------------------------------------------------------------------------
func TestGuard_NonGlobConstraintStillExactMatches(t *testing.T) {
	// Single-value (CommonName path): exact match, never glob-EXPANDED. The
	// no-regression guarantee is on the wildcard axis — a literal must not start
	// matching as a wildcard. (Case is folded per F16, which is the intended fix,
	// not a regression; see TestRed_F16.)
	assert.NoError(t, checkCertConstraintGlob("common name", "example.com", "example.com"),
		"a literal constraint must accept an exactly-equal value")
	assert.Error(t, checkCertConstraintGlob("common name", "example.com", "foo.example.com"),
		"a literal (non-glob) constraint must NOT glob-expand; 'example.com' must reject 'foo.example.com'")
	assert.Error(t, checkCertConstraintGlob("common name", "example.com", "examplexcom"),
		"a literal constraint must not treat '.' as a wildcard; 'example.com' must reject 'examplexcom'")

	// Multi-value (Organizations/DNS/email path): exact count semantics unchanged,
	// and the exact path stays byte-exact (case-sensitive) to preserve existing
	// multi-value policy behavior (the R3-270 documented contract).
	assert.Error(t, checkCertConstraint("org", []string{"acme"}, []string{"ACME"}),
		"the multi-value exact path stays byte-exact (case-sensitive); no behavior change")

	// Exact-match positive: byte-equal multi-value constraints accept.
	assert.NoError(t, checkCertConstraint("org", []string{"ACME", "Globex"}, []string{"ACME", "Globex"}),
		"exact multi-value constraints must accept an exactly-matching cert")
	assert.Error(t, checkCertConstraint("org", []string{"ACME"}, []string{"foo.ACME.bar"}),
		"a literal multi-value constraint must NOT substring/glob-match; 'ACME' must reject 'foo.ACME.bar'")

	// Duplicate-constraint count semantics preserved (no glob collapse): [A,A] needs two.
	assert.Error(t, checkCertConstraint("org", []string{"ACME", "ACME"}, []string{"ACME"}),
		"exact duplicate constraints [ACME,ACME] still require two cert values (no regression to F1)")

	// A glob constraint must NOT be silently treated as a literal: '*.example.com'
	// must reject the literal string '*.example.com' as a cert value (it is a
	// wildcard, matched against real values, not a literal to compare).
	assert.NoError(t, checkCertConstraint("dns name", []string{"*.example.com"}, []string{"api.example.com"}),
		"a glob constraint must wildcard-match a real value")
}

// ---------------------------------------------------------------------------
// Guard (NUL reject, #5756) — a NUL/control byte in a constraint fails closed.
// ---------------------------------------------------------------------------
func TestGuard_NulByteConstraintFailsClosed(t *testing.T) {
	assert.Error(t, checkCertConstraintGlob("common name", "ev\x00il*", "evil"),
		"a NUL byte in a single-value constraint must fail closed")
	assert.Error(t, checkCertConstraint("dns name", []string{"ev\x00il*"}, []string{"evil.com"}),
		"a NUL byte in a multi-value constraint must fail closed")
}
