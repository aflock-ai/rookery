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

package policy

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/gobwas/glob"
	"github.com/sigstore/fulcio/pkg/certificate"
)

const (
	AllowAllConstraint = "*"

	// globMatchTimeout bounds a single glob match against a ReDoS-style
	// pathological pattern (#5756). gobwas/glob has no internal time bound, and
	// this PR EXPANDS glob usage to every multi-value SAN field, so an untrusted
	// or hand-fat-fingered pattern (nested "{" + many "*") could spin. A match
	// that exceeds this deadline is treated as a constraint FAILURE (fail closed),
	// never an accept. The bound is generous (a legitimate cert-field match is
	// sub-millisecond) so it does not false-positive on real policies.
	globMatchTimeout = 250 * time.Millisecond
)

// globMetaChars are the glob metacharacters that switch a constraint value from
// exact-match to glob-match. A constraint that contains NONE of these still
// exact-matches (no behavior change for existing exact policies — critical).
const globMetaChars = "*?{["

// containsGlobMeta reports whether s contains any glob metacharacter. Used both
// to decide the glob-vs-exact path for cert SAN constraints and to guard the
// glob engine in checkExtensions so non-glob constraints skip it entirely.
func containsGlobMeta(s string) bool {
	return strings.ContainsAny(s, globMetaChars)
}

// hasNonPrintable reports whether s contains a NUL byte or any other
// non-printable rune. A NUL (or other control char) in a constraint is treated
// as a reject (fail closed) — it is never a legitimate cert-field value and was
// a fuzz finding (#5756 secondary). It also keeps such bytes out of the glob
// engine, where they can drive degenerate matching.
func hasNonPrintable(s string) bool {
	for _, r := range s {
		if r == 0 || !unicode.IsPrint(r) {
			return true
		}
	}
	return false
}

// boundedGlobMatch runs safeGlobMatch under a deadline. A pattern that exceeds
// globMatchTimeout is reported as a non-match with a timeout error, so the
// caller fails the constraint closed (#5756). The recover() in safeGlobMatch
// still guards panics; this guards a hang.
func boundedGlobMatch(g glob.Glob, s string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), globMatchTimeout)
	defer cancel()

	type result struct {
		matched bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		matched, err := safeGlobMatch(g, s)
		done <- result{matched, err}
	}()

	select {
	case r := <-done:
		return r.matched, r.err
	case <-ctx.Done():
		// Fail closed: a match that does not finish within the deadline is a
		// constraint FAILURE, not an accept. The goroutine is abandoned (it will
		// finish and write to the buffered channel, then be GC'd) — we never read
		// its late result, so a timed-out match can never flip to a pass.
		return false, fmt.Errorf("glob match exceeded %s deadline (possible ReDoS pattern); failing closed", globMatchTimeout)
	}
}

// +kubebuilder:object:generate=true
type CertConstraint struct {
	CommonName    string                 `json:"commonname" jsonschema:"title=Common Name,description=Expected certificate common name (supports glob patterns with *)"`
	DNSNames      []string               `json:"dnsnames" jsonschema:"title=DNS Names,description=Expected DNS subject alternative names"`
	Emails        []string               `json:"emails" jsonschema:"title=Emails,description=Expected email subject alternative names"`
	Organizations []string               `json:"organizations" jsonschema:"title=Organizations,description=Expected organization names in the certificate subject"`
	URIs          []string               `json:"uris" jsonschema:"title=URIs,description=Expected URI subject alternative names"`
	Roots         []string               `json:"roots" jsonschema:"title=Roots,description=IDs of trusted root certificates from the policy's roots map (use * to allow all)"`
	Extensions    certificate.Extensions `json:"extensions" jsonschema:"title=Extensions,description=Fulcio certificate extension constraints (supports glob patterns)"`
}

func (cc CertConstraint) Check(verifier *cryptoutil.X509Verifier, trustBundles map[string]TrustBundle) error {
	cert := verifier.Certificate()

	// Short-circuit on the FIRST failing constraint (F14, #5746): do not run the
	// remaining checks. Accumulating every check's error both does needless work
	// (the trust-bundle check can be expensive) and leaks cert detail via a fan of
	// error messages. Surface exactly one underlying error, wrapped so callers can
	// still match ErrConstraintCheckFailed.
	if err := checkCertConstraintGlob("common name", cc.CommonName, cert.Subject.CommonName); err != nil {
		return ErrConstraintCheckFailed{[]error{err}}
	}

	if err := checkCertConstraint("dns name", cc.DNSNames, cert.DNSNames); err != nil {
		return ErrConstraintCheckFailed{[]error{err}}
	}

	if err := checkCertConstraint("email", cc.Emails, cert.EmailAddresses); err != nil {
		return ErrConstraintCheckFailed{[]error{err}}
	}

	if err := checkCertConstraint("organization", cc.Organizations, cert.Subject.Organization); err != nil {
		return ErrConstraintCheckFailed{[]error{err}}
	}

	if err := checkCertConstraint("uri", cc.URIs, urisToStrings(cert.URIs)); err != nil {
		return ErrConstraintCheckFailed{[]error{err}}
	}

	if err := cc.checkTrustBundles(verifier, trustBundles); err != nil {
		return ErrConstraintCheckFailed{[]error{err}}
	}

	if err := cc.checkExtensions(cert.Extensions); err != nil {
		return ErrConstraintCheckFailed{[]error{err}}
	}

	return nil
}

func (cc CertConstraint) checkTrustBundles(verifier *cryptoutil.X509Verifier, trustBundles map[string]TrustBundle) error { //nolint:gocognit
	// Honor an AllowAll wildcard ("*") at ANY position in the Roots list, not
	// only at index 0 (F13/F18, #5746). A policy author who writes
	// ["specific-root", "*"] means "allow any trusted root the verifier chains
	// to", not "require a literal '*' root ID". When a "*" is present, accept the
	// cert if it belongs to ANY supplied trust bundle.
	if hasAllowAll(cc.Roots) { //nolint:nestif // mirror of the pre-fix wildcard branch; depth is inherent to the two-mode lookup
		for _, bundle := range trustBundles {
			if err := verifier.BelongsToRoot(bundle.Root); err == nil {
				return nil
			}
		}
	} else {
		for _, rootID := range cc.Roots {
			if bundle, ok := trustBundles[rootID]; ok {
				if err := verifier.BelongsToRoot(bundle.Root); err == nil {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("cert doesn't belong to any root specified by constraint %+q", cc.Roots)
}

// hasAllowAll reports whether the AllowAllConstraint ("*") appears anywhere in
// the list. Used so the wildcard is honored at any position (F13/F18, #5746),
// not just index 0.
func hasAllowAll(in []string) bool {
	for _, s := range in {
		if s == AllowAllConstraint {
			return true
		}
	}
	return false
}

func (cc CertConstraint) checkExtensions(ext []pkix.Extension) error {
	extensions, err := certificate.ParseExtensions(ext)
	if err != nil {
		return fmt.Errorf("error parsing fulcio cert extensions: %w", err)
	}

	fields := reflect.VisibleFields(reflect.TypeOf(cc.Extensions))
	for _, field := range fields {
		constraintField := reflect.ValueOf(cc.Extensions).FieldByName(field.Name)
		constraint := constraintField.String()
		if constraint == "" {
			log.Debugf("No constraint for field %s, allowing all values", field.Name)
			continue
		}

		// Reject a NUL/control byte in the constraint (fail closed, #5756). It is
		// never a legitimate extension value and can drive degenerate glob matching.
		if hasNonPrintable(constraint) {
			return fmt.Errorf("cert field %s constraint %+q contains a non-printable byte; failing closed", field.Name, constraint)
		}

		extensionsField := reflect.ValueOf(extensions).FieldByName(field.Name)
		value := extensionsField.String()

		// Guard the glob engine the same way checkCertConstraintGlob does (#5756):
		// only invoke gobwas when the constraint actually contains a glob
		// metacharacter. A plain literal exact-matches, skipping the engine (and
		// its ReDoS surface) entirely.
		if !containsGlobMeta(constraint) {
			if constraint != value {
				return fmt.Errorf("cert field %s doesn't match constraint %+q", field.Name, constraint)
			}
			continue
		}

		fieldGlob, err := glob.Compile(constraint)
		if err != nil {
			return fmt.Errorf("invalid glob pattern %+q for cert field %s: %w", constraint, field.Name, err)
		}
		log.Warnf("cert field %s matched via GLOB pattern %+q (not exact match); confirm this is intended", field.Name, constraint)
		matched, matchErr := boundedGlobMatch(fieldGlob, value)
		if matchErr != nil {
			return fmt.Errorf("glob match error for cert field %s with pattern %+q: %w", field.Name, constraint, matchErr)
		}
		if !matched {
			return fmt.Errorf("cert field %s doesn't match constraint %+q", field.Name, constraint)
		}
	}

	return nil
}

func urisToStrings(uris []*url.URL) []string {
	res := make([]string, 0, len(uris))
	for _, uri := range uris {
		res = append(res, uri.String())
	}

	return res
}

// checkCertConstraintGlob checks a single-value cert attribute against a constraint
// that may contain glob patterns (e.g., "*.example.com" matches "foo.example.com").
// The AllowAllConstraint ("*") matches everything. An EMPTY constraint fails closed:
// a forgotten/blank CommonName must NOT silently accept any value — the author must
// opt in to "allow any" explicitly with "*" (F5, #5746).
//
//nolint:unparam // attribute is the shared error-message vocabulary (mirrors checkCertConstraint); kept for symmetry though today's sole caller passes "common name"
func checkCertConstraintGlob(attribute, constraint, value string) error {
	if constraint == AllowAllConstraint {
		return nil
	}

	// Fail closed on an empty constraint: an unset attribute reads like "allow any"
	// but must not be — require the explicit AllowAllConstraint ("*") to allow all.
	if constraint == "" {
		return fmt.Errorf("cert %s constraint is empty, which fails closed; set the expected value or %q to allow any", attribute, AllowAllConstraint)
	}

	// Reject a NUL/control byte in the constraint (fail closed, #5756): never a
	// legitimate value, and it can drive degenerate glob matching.
	if hasNonPrintable(constraint) {
		return fmt.Errorf("cert %s constraint %q contains a non-printable byte; failing closed", attribute, constraint)
	}

	// Use the glob engine whenever the constraint carries ANY glob metacharacter
	// (*, ?, {, [), not only "*" (#5746). A constraint with NO glob char still
	// exact-matches below — it is never glob-EXPANDED (so a literal "example.com"
	// never matches "foo.example.com"; the no-regression guarantee is on the
	// wildcard axis). Both paths case-fold the comparison (F16, #5746) because the
	// single-value cert identity field (CommonName) is case-insensitive per RFC,
	// so an author's "Example.COM" must accept a cert "example.com".
	if containsGlobMeta(constraint) {
		g, err := glob.Compile(normalizeGlobValue(constraint))
		if err != nil {
			return fmt.Errorf("invalid glob pattern %q for cert %s: %w", constraint, attribute, err)
		}
		log.Warnf("cert %s constraint %q is being matched via GLOB (not exact match); confirm this is intended", attribute, constraint)
		matched, matchErr := boundedGlobMatch(g, normalizeGlobValue(value))
		if matchErr != nil {
			return fmt.Errorf("glob match error for cert %s with pattern %q: %w", attribute, constraint, matchErr)
		}
		if !matched {
			return fmt.Errorf("cert %s %q doesn't match constraint %q", attribute, value, constraint)
		}
		return nil
	}

	// Exact (non-glob) match, case-folded (F16, #5746) — never glob-expanded.
	if normalizeGlobValue(constraint) != normalizeGlobValue(value) {
		return fmt.Errorf("cert %s %q doesn't match constraint %q", attribute, value, constraint)
	}
	return nil
}

func checkCertConstraint(attribute string, constraints, values []string) error {
	// Honor the AllowAllConstraint ("*") at ANY position, not only when it is the
	// sole element (F13/F18, #5746). A list like ["admin@x", "*"] means "allow any
	// value"; "*" must not be treated as a literal cert value to match.
	if hasAllowAll(constraints) {
		return nil
	}

	// Reject a NUL/control byte in any constraint (fail closed, #5756). It is never
	// a legitimate SAN value and can drive degenerate glob matching.
	for _, c := range constraints {
		if hasNonPrintable(c) {
			return fmt.Errorf("cert %s constraint %+q contains a non-printable byte; failing closed", attribute, c)
		}
	}

	// Normalize empty-string elements away at ALL positions, not just index 0
	// (F11, #5746). An empty string carries no SAN identity, so a constraint like
	// ["", "real"] means "require real"; the cert is not forced to present a
	// literal empty value. The same normalization applies to the cert's values.
	constraints = dropEmpty(constraints)
	values = dropEmpty(values)

	if len(constraints) == 0 && len(values) > 0 {
		// An empty list-constraint forbids ALL of this SAN type, so a cert that
		// presents one is rejected. Name the value(s) and the fix — a null/empty
		// constraint reads like "allow any" but does the opposite.
		return fmt.Errorf("cert presents %s %+q but the policy's %s constraint is empty, which forbids all; add the value to the functionary's certConstraint %s list (or %q to allow any)",
			attribute, values, attribute, attribute, AllowAllConstraint)
	}

	// Split constraints into EXACT (no glob metachar) and GLOB. Exact constraints
	// keep the existing count-based semantics so there is NO behavior change for
	// existing exact policies (critical): duplicate constraints are not collapsed
	// (F1, #5746) and a subset of required values still fails (F4, #5746). Glob
	// constraints are matched via the glob engine (F2, #5746).
	exact := make([]string, 0, len(constraints))
	globs := make([]string, 0)
	for _, c := range constraints {
		if containsGlobMeta(c) {
			globs = append(globs, c)
		} else {
			exact = append(exact, c)
		}
	}

	// Phase 1: satisfy every EXACT constraint with a distinct cert value. The
	// count map preserves duplicate-constraint semantics (F1/F4). Values consumed
	// here are removed from the pool so a glob does not double-count them.
	unmet := make(map[string]int, len(exact))
	for _, c := range exact {
		unmet[c]++
	}
	remainingValues := make([]string, 0, len(values))
	for _, value := range values {
		if unmet[value] > 0 {
			unmet[value]--
			continue
		}
		remainingValues = append(remainingValues, value)
	}
	for c, remaining := range unmet {
		if remaining > 0 {
			return fmt.Errorf("cert %s(s) %+q did not satisfy exact constraint %q (need %d more match(es)); constraints %+q",
				attribute, values, c, remaining, constraints)
		}
	}

	// Phase 2: each remaining cert value must match at least one as-yet-unconsumed
	// GLOB constraint, and every glob constraint must consume exactly one value.
	// This preserves the fail-closed count contract for globs (N glob constraints
	// require N distinct matching values) while adding wildcard matching (F2).
	if err := matchGlobConstraints(attribute, globs, remainingValues, constraints, values); err != nil {
		return err
	}

	return nil
}

// matchGlobConstraints greedily assigns each cert value to a distinct unused
// glob constraint. Each glob must consume exactly one value, and every value
// must be consumed (no unexpected SAN). Matching is fail-closed: a leftover
// value or an unsatisfied glob is an error. Normalization (case-fold) is applied
// to BOTH sides for the glob path, consistent with checkCertConstraintGlob's
// F16 fix; the exact path (phase 1) stays byte-exact to avoid any regression.
//
// The assignment is greedy, not a full bipartite matching: with multiple
// overlapping globs a valid assignment could in theory be missed. That errs
// toward REJECTION (fail closed), never a false accept, and cert SAN lists in
// practice carry a single glob, so the greedy pass is sufficient and safe.
func matchGlobConstraints(attribute string, globs, values, allConstraints, allValues []string) error {
	if len(globs) == 0 {
		if len(values) > 0 {
			return fmt.Errorf("cert has an unexpected %s %+q given constraints %+q", attribute, values, allConstraints)
		}
		return nil
	}

	compiled, err := compileGlobs(attribute, globs)
	if err != nil {
		return err
	}

	usedGlob := make([]bool, len(globs))
	for _, value := range values {
		if err := assignValueToGlob(attribute, value, globs, compiled, usedGlob, allConstraints); err != nil {
			return err
		}
	}

	for i, used := range usedGlob {
		if !used {
			return fmt.Errorf("cert %s(s) %+q did not satisfy glob constraint %q; constraints %+q", attribute, allValues, globs[i], allConstraints)
		}
	}

	return nil
}

// compileGlobs compiles each glob pattern once (normalized for the F16 case
// fold) and warns that the field is matched via glob, not exact. A NUL/non-
// printable byte was already rejected upstream, so the engine only sees
// printable patterns here.
func compileGlobs(attribute string, globs []string) ([]glob.Glob, error) {
	compiled := make([]glob.Glob, len(globs))
	for i, pattern := range globs {
		log.Warnf("cert %s constraint %q is being matched via GLOB (not exact match); confirm this is intended", attribute, pattern)
		g, err := glob.Compile(normalizeGlobValue(pattern))
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern %q for cert %s: %w", pattern, attribute, err)
		}
		compiled[i] = g
	}
	return compiled, nil
}

// assignValueToGlob marks the first as-yet-unused glob that matches value as
// used. It fails closed: a value matched by no remaining glob is an unexpected
// SAN, and a match-engine timeout (#5756) is surfaced as an error.
func assignValueToGlob(attribute, value string, globs []string, compiled []glob.Glob, usedGlob []bool, allConstraints []string) error {
	for i, g := range compiled {
		if usedGlob[i] {
			continue
		}
		matched, matchErr := boundedGlobMatch(g, normalizeGlobValue(value))
		if matchErr != nil {
			return fmt.Errorf("glob match error for cert %s with pattern %q: %w", attribute, globs[i], matchErr)
		}
		if matched {
			usedGlob[i] = true
			return nil
		}
	}
	return fmt.Errorf("cert has an unexpected %s %q given constraints %+q", attribute, value, allConstraints)
}

// normalizeGlobValue applies the case-fold normalization used on the glob path
// (F16, #5746) so an author's "Example.COM" pattern accepts a cert value of
// "example.com". It is applied to the single-value CommonName comparison
// (RFC-case-insensitive) on both its glob and exact paths, and to the glob path
// of multi-value SAN matching — but NOT to the multi-value EXACT phase, which
// stays byte-exact to preserve existing multi-value policy behavior.
func normalizeGlobValue(s string) string {
	return strings.ToLower(s)
}

// dropEmpty returns a copy of in with all empty-string elements removed. It is
// used to normalize cert-constraint and cert-value lists so a stray empty string
// (e.g. an author's blank list entry) does not require the cert to present a
// literal empty value at that position.
func dropEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// safeGlobMatch wraps glob.Match with panic recovery. The gobwas/glob library
// can panic on certain patterns that compile successfully but trigger out-of-bounds
// access during matching (e.g., "0*,{*,"). We treat panics as match failures.
func safeGlobMatch(g glob.Glob, s string) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			matched = false
			err = fmt.Errorf("glob match panicked (likely invalid pattern): %v", r)
		}
	}()
	return g.Match(s), nil
}
