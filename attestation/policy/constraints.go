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
	errs := make([]error, 0)
	cert := verifier.Certificate()

	if err := checkCertConstraintGlob("common name", cc.CommonName, cert.Subject.CommonName); err != nil {
		errs = append(errs, err)
	}

	if err := checkCertConstraint("dns name", cc.DNSNames, cert.DNSNames); err != nil {
		errs = append(errs, err)
	}

	if err := checkCertConstraint("email", cc.Emails, cert.EmailAddresses); err != nil {
		errs = append(errs, err)
	}

	if err := checkCertConstraint("organization", cc.Organizations, cert.Subject.Organization); err != nil {
		errs = append(errs, err)
	}

	if err := checkCertConstraint("uri", cc.URIs, urisToStrings(cert.URIs)); err != nil {
		errs = append(errs, err)
	}

	if err := cc.checkTrustBundles(verifier, trustBundles); err != nil {
		errs = append(errs, err)
	}

	if err := cc.checkExtensions(cert.Extensions); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return ErrConstraintCheckFailed{errs}
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
// An empty constraint allows any value. The AllowAllConstraint ("*") matches everything.
func checkCertConstraintGlob(attribute, constraint, value string) error {
	if constraint == "" || constraint == AllowAllConstraint {
		return nil
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
	// If our only constraint is the AllowAllConstraint it's a pass
	if len(constraints) == 1 && constraints[0] == AllowAllConstraint { //nolint:gosec // G602: len check guards index
		return nil
	}

	// treat a single empty string the same as a constraint on an empty attribute
	if len(constraints) == 1 && constraints[0] == "" { //nolint:gosec // G602: len check guards index
		constraints = []string{}
	}

	if len(values) == 1 && values[0] == "" { //nolint:gosec // G602: len check guards index
		values = []string{}
	}

	if len(constraints) == 0 && len(values) > 0 {
		return fmt.Errorf("not expecting any %s(s), but cert has %d %s(s)", attribute, len(values), attribute)
	}

	unmet := make(map[string]struct{})
	for _, constraint := range constraints {
		unmet[constraint] = struct{}{}
	}

	for _, value := range values {
		if _, ok := unmet[value]; !ok {
			return fmt.Errorf("cert has an unexpected %s %s given constraints %+q", attribute, value, constraints)
		}

		delete(unmet, value)
	}

	if len(unmet) > 0 {
		return fmt.Errorf("cert with %s(s) %+q did not pass all constraints %+q", attribute, values, constraints)
	}

	return nil
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
