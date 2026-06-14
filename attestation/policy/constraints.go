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
	"crypto/x509/pkix"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/gobwas/glob"
	"github.com/sigstore/fulcio/pkg/certificate"
)

const (
	AllowAllConstraint = "*"
)

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
	if len(cc.Roots) == 1 && cc.Roots[0] == AllowAllConstraint { //nolint:nestif
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

func (cc CertConstraint) checkExtensions(ext []pkix.Extension) error {
	extensions, err := certificate.ParseExtensions(ext)
	if err != nil {
		return fmt.Errorf("error parsing fulcio cert extensions: %w", err)
	}

	fields := reflect.VisibleFields(reflect.TypeOf(cc.Extensions))
	for _, field := range fields {
		constraintField := reflect.ValueOf(cc.Extensions).FieldByName(field.Name)
		if constraintField.String() == "" {
			log.Debugf("No constraint for field %s, allowing all values", field.Name)
			continue
		}
		extensionsField := reflect.ValueOf(extensions).FieldByName(field.Name)

		fieldGlob, err := glob.Compile(constraintField.String())
		if err != nil {
			return fmt.Errorf("invalid glob pattern %+q for cert field %s: %w", constraintField.String(), field.Name, err)
		}
		matched, matchErr := safeGlobMatch(fieldGlob, extensionsField.String())
		if matchErr != nil {
			return fmt.Errorf("glob match error for cert field %s with pattern %+q: %w", field.Name, constraintField.String(), matchErr)
		}
		if !matched {
			return fmt.Errorf("cert field %s doesn't match constraint %+q", field.Name, constraintField.String())
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
func checkCertConstraintGlob(attribute, constraint, value string) error {
	if constraint == AllowAllConstraint {
		return nil
	}

	// Fail closed on an empty constraint: an unset attribute reads like "allow any"
	// but must not be — require the explicit AllowAllConstraint ("*") to allow all.
	if constraint == "" {
		return fmt.Errorf("cert %s constraint is empty, which fails closed; set the expected value or %q to allow any", attribute, AllowAllConstraint)
	}

	if strings.Contains(constraint, "*") {
		g, err := glob.Compile(constraint)
		if err != nil {
			return fmt.Errorf("invalid glob pattern %q for cert %s: %w", constraint, attribute, err)
		}
		matched, matchErr := safeGlobMatch(g, value)
		if matchErr != nil {
			return fmt.Errorf("glob match error for cert %s with pattern %q: %w", attribute, constraint, matchErr)
		}
		if !matched {
			return fmt.Errorf("cert %s %q doesn't match constraint %q", attribute, value, constraint)
		}
		return nil
	}

	// Exact match for non-glob constraints
	if constraint != value {
		return fmt.Errorf("cert %s %q doesn't match constraint %q", attribute, value, constraint)
	}
	return nil
}

func checkCertConstraint(attribute string, constraints, values []string) error {
	// If our only constraint is the AllowAllConstraint it's a pass.
	if len(constraints) == 1 && constraints[0] == AllowAllConstraint { //nolint:gosec // G602: len check guards index
		return nil
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

	// Count occurrences so duplicate constraints are NOT silently collapsed
	// (F1, #5746): constraints=[ACME,ACME] requires TWO matching cert values.
	// A subset of required values must FAIL (F4, #5746): N distinct required
	// values need N distinct cert matches.
	unmet := make(map[string]int, len(constraints))
	for _, constraint := range constraints {
		unmet[constraint]++
	}

	for _, value := range values {
		if unmet[value] <= 0 {
			return fmt.Errorf("cert has an unexpected %s %s given constraints %+q", attribute, value, constraints)
		}

		unmet[value]--
	}

	for _, remaining := range unmet {
		if remaining > 0 {
			return fmt.Errorf("cert with %s(s) %+q did not pass all constraints %+q", attribute, values, constraints)
		}
	}

	return nil
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
