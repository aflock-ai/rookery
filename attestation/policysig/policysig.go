// Copyright 2023 The Witness Contributors
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

package policysig

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/sigstore/fulcio/pkg/certificate"
)

type VerifyPolicySignatureOptions struct {
	policyVerifiers            []cryptoutil.Verifier
	policyTimestampAuthorities []timestamp.TimestampVerifier
	policyCARoots              []*x509.Certificate
	policyCAIntermediates      []*x509.Certificate
	policyCommonName           string
	policyDNSNames             []string
	policyEmails               []string
	policyOrganizations        []string
	policyURIs                 []string
	fulcioCertExtensions       certificate.Extensions
	// certConstraintsSet records whether the caller explicitly configured
	// certificate-identity constraints via VerifyWithPolicyCertConstraints. It
	// distinguishes "caller opted into X.509 policy-signer identity matching"
	// from the all-wildcard default, so an unconstrained CA cert is refused
	// rather than trusted (GHSA-mpvw-hw8p-7x27).
	certConstraintsSet bool
}

type Option func(*VerifyPolicySignatureOptions)

func VerifyWithPolicyVerifiers(policyVerifiers []cryptoutil.Verifier) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.policyVerifiers = append(vo.policyVerifiers, policyVerifiers...)
	}
}

func VerifyWithPolicyTimestampAuthorities(authorities []timestamp.TimestampVerifier) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.policyTimestampAuthorities = authorities
	}
}

func VerifyWithPolicyCARoots(roots []*x509.Certificate) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.policyCARoots = roots
	}
}

func VerifyWithPolicyCAIntermediates(intermediates []*x509.Certificate) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.policyCAIntermediates = intermediates
	}
}

func NewVerifyPolicySignatureOptions(opts ...Option) *VerifyPolicySignatureOptions {
	vo := &VerifyPolicySignatureOptions{
		policyCommonName:    "*",
		policyDNSNames:      []string{"*"},
		policyOrganizations: []string{"*"},
		policyURIs:          []string{"*"},
		policyEmails:        []string{"*"},
	}

	for _, opt := range opts {
		opt(vo)
	}

	return vo
}

func VerifyWithPolicyFulcioCertExtensions(extensions certificate.Extensions) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.fulcioCertExtensions = extensions
	}
}

func VerifyWithPolicyCertConstraints(commonName string, dnsNames []string, emails []string, organizations []string, uris []string) Option {
	return func(vo *VerifyPolicySignatureOptions) {
		vo.policyCommonName = commonName
		vo.policyDNSNames = dnsNames
		vo.policyEmails = emails
		vo.policyOrganizations = organizations
		vo.policyURIs = uris
		// The caller has explicitly opted into X.509 policy-signer identity
		// matching (even if the values are wildcards — that is their explicit
		// choice). This gates the unconstrained-signer refusal below.
		vo.certConstraintsSet = true
	}
}

// extensionsPinIdentity reports whether the caller configured at least one
// Fulcio certificate extension constraint that actually PINS identity — a
// concrete value, not empty and not the all-wildcard "*". Only such a
// constraint is a valid opt-in to X.509 policy-signer trust without SAN
// constraints (GHSA-mpvw-hw8p-7x27).
//
// A wildcard-only extension (e.g. certificate.Extensions{Issuer: "*"}) is NOT a
// pin: downstream constraint matching glob-accepts "*", so treating it as an
// opt-in would let any cert chaining to a trusted CA be accepted as a policy
// signer — exactly the bypass this guard exists to prevent.
func extensionsPinIdentity(vo *VerifyPolicySignatureOptions) bool {
	rv := reflect.ValueOf(vo.fulcioCertExtensions)
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		if f.Kind() != reflect.String {
			continue
		}
		if s := f.String(); s != "" && s != policy.AllowAllConstraint {
			return true
		}
	}
	return false
}

func allWildcard(vo *VerifyPolicySignatureOptions) bool {
	isWild := func(s string) bool { return s == "*" }
	isWildSlice := func(ss []string) bool { return len(ss) == 1 && ss[0] == "*" }
	return isWild(vo.policyCommonName) &&
		isWildSlice(vo.policyDNSNames) &&
		isWildSlice(vo.policyEmails) &&
		isWildSlice(vo.policyOrganizations) &&
		isWildSlice(vo.policyURIs)
}

func VerifyPolicySignature(ctx context.Context, envelope dsse.Envelope, vo *VerifyPolicySignatureOptions) error {
	if allWildcard(vo) {
		log.Warn("policy signature verification is using all-wildcard certificate constraints; any certificate from a trusted CA will be accepted as a policy signer — use VerifyWithPolicyCertConstraints to restrict")
	}
	passedPolicyVerifiers, err := envelope.Verify(dsse.VerifyWithVerifiers(vo.policyVerifiers...), dsse.VerifyWithTimestampVerifiers(vo.policyTimestampAuthorities...), dsse.VerifyWithRoots(vo.policyCARoots...), dsse.VerifyWithIntermediates(vo.policyCAIntermediates...))
	if err != nil {
		return fmt.Errorf("could not verify policy: %w", err)
	}

	var passed bool
	for _, verifier := range passedPolicyVerifiers {
		// On the success path dsse.Envelope.Verify returns the FULL slice of
		// CheckedVerifiers — including entries whose own signature FAILED
		// (Error != nil) so long as the overall threshold was met by other
		// signatures. Trusting a failed verifier's cert identity is fail-open
		// (#5747 C): a corrupted signature whose cert still chains to a trusted
		// root and matches the configured constraints would confer trust. Skip
		// them, mirroring source/verified.go:115.
		if verifier.Error != nil {
			continue
		}
		kid, err := verifier.Verifier.KeyID()
		if err != nil {
			return fmt.Errorf("could not get verifier key id: %w", err)
		}

		f, trustBundle, skip := policyFunctionaryForVerifier(vo, verifier, kid)
		if skip {
			continue
		}

		if err := f.Validate(verifier.Verifier, trustBundle); err != nil {
			log.Debugf("Policy Verifier %s failed to match supplied constraints: %v, continuing...", kid, err)
			continue
		}
		passed = true
	}

	if !passed {
		// The signature(s) chained to a trusted root, but no signer's
		// cert identity matched the configured constraints. Surface the
		// ACTUAL identities so the operator knows exactly what to pass.
		if hint := policyVerifierIdentityHint(passedPolicyVerifiers); hint != "" {
			return fmt.Errorf("policy signature verified against a trusted CA root, but the signer identity matched no configured policy verifier.\n"+
				"  signer identity: %s\n"+
				"  fix: pass --policy-uris (and/or --policy-emails) matching the URI/email above; --policy-fulcio-oidc-issuer defaults to GitHub Actions", hint)
		}
		return fmt.Errorf("no policy verifiers passed verification: the policy signature chained to a trusted root, " +
			"but no signer matched the configured identity constraints (set --policy-uris / --policy-emails to the signer's SAN)")
	}

	return nil
}

// policyFunctionaryForVerifier builds the policy.Functionary (and its trust
// bundle) used to validate a single policy-signature verifier. The bool return
// is true when the verifier must be SKIPPED: an X.509 (keyless) signer with no
// configured identity constraints or Fulcio extensions is refused rather than
// trusted on the strength of chaining to a CA root alone (GHSA-mpvw-hw8p-7x27).
func policyFunctionaryForVerifier(vo *VerifyPolicySignatureOptions, verifier dsse.CheckedVerifier, kid string) (policy.Functionary, map[string]policy.TrustBundle, bool) {
	trustBundle := make(map[string]policy.TrustBundle)
	x509v, ok := verifier.Verifier.(*cryptoutil.X509Verifier)
	if !ok {
		return policy.Functionary{Type: "key", PublicKeyID: kid}, trustBundle, false
	}

	if !vo.certConstraintsSet && !extensionsPinIdentity(vo) {
		log.Warnf("policy signer %s presents an X.509 identity but no certificate constraints or Fulcio extensions were configured; refusing to trust an unconstrained CA cert as a policy signer (use VerifyWithPolicyCertConstraints / VerifyWithPolicyFulcioCertExtensions)", kid)
		return policy.Functionary{}, nil, true
	}

	rootIDs := make([]string, 0, len(vo.policyCARoots))
	for _, root := range vo.policyCARoots {
		id := base64.StdEncoding.EncodeToString(root.Raw)
		rootIDs = append(rootIDs, id)
		trustBundle[id] = policy.TrustBundle{Root: root}
	}

	// Resolve each SAN-list constraint through the signer-path empty-list
	// relaxation (see effectivePolicySignerSANList): an empty --policy-* list
	// matched against a cert field the leaf does not carry stays a no-op pass
	// under R3_181 enforcement (#6266/#6454), provided the signer identity is
	// genuinely pinned by some other concrete constraint.
	pinned := signerIdentityPinned(vo)
	cert := x509v.Certificate()
	var certURIs, certDNS, certEmails, certOrgs []string
	if cert != nil {
		certURIs = make([]string, 0, len(cert.URIs))
		for _, u := range cert.URIs {
			certURIs = append(certURIs, u.String())
		}
		certDNS = cert.DNSNames
		certEmails = cert.EmailAddresses
		certOrgs = cert.Subject.Organization
	}

	return policy.Functionary{
		Type: "root",
		CertConstraint: policy.CertConstraint{
			Roots:         rootIDs,
			CommonName:    effectivePolicySignerCommonName(vo),
			URIs:          effectivePolicySignerSANList(pinned, vo.policyURIs, certURIs),
			Emails:        effectivePolicySignerSANList(pinned, vo.policyEmails, certEmails),
			Organizations: effectivePolicySignerSANList(pinned, vo.policyOrganizations, certOrgs),
			DNSNames:      effectivePolicySignerSANList(pinned, vo.policyDNSNames, certDNS),
			Extensions:    vo.fulcioCertExtensions,
		},
	}, trustBundle, false
}

// signerIdentityPinned reports whether the operator pinned the policy-signer
// identity by at least one CONCRETE constraint: a non-wildcard CommonName, a
// SAN list in which every element is concrete (pinsIdentity), or a Fulcio
// extension that pins identity (extensionsPinIdentity). It gates the
// empty-SAN-list relaxation below the same way the email/URI pin gates the
// empty-CN relaxation in effectivePolicySignerCommonName: with nothing pinned,
// nothing is relaxed and verification keeps failing closed
// (GHSA-mpvw-hw8p-7x27).
func signerIdentityPinned(vo *VerifyPolicySignatureOptions) bool {
	if vo.policyCommonName != "" && vo.policyCommonName != policy.AllowAllConstraint {
		return true
	}
	return pinsIdentity(vo.policyEmails) || pinsIdentity(vo.policyURIs) ||
		pinsIdentity(vo.policyDNSNames) || pinsIdentity(vo.policyOrganizations) ||
		extensionsPinIdentity(vo)
}

// effectivePolicySignerSANList resolves one multi-value SAN constraint list
// (dnsnames/emails/organizations/uris) applied to a policy-SIGNER cert. On the
// signer path an empty list has always meant "unconstrained": before #6266 an
// empty list matched against a cert field the leaf does not carry was a no-op
// pass, and operators pin the signer with --policy-emails / --policy-uris while
// leaving the other lists at their empty defaults (the exact release-fanout
// shape). Under R3_181 ENFORCEMENT (empty constraint vs empty cert field fails
// closed, #6266/#6454) that spelling would reject EVERY keyless author-signed
// policy — the same regression class as the empty-CN case handled by
// effectivePolicySignerCommonName, and resolved the same way:
//
//   - constraint empty + cert field ABSENT + identity otherwise pinned →
//     AllowAll (preserves the pre-#6266 no-op pass, bit-for-bit).
//   - constraint empty + cert field PRESENT → left empty: the downstream
//     "empty list forbids all present values" rejection is unchanged.
//   - nothing pinned anywhere → left empty: fails closed downstream.
//   - non-empty constraints are never touched.
//
// The policy-EMBEDDED functionary constraints (policy.CertConstraint.Check on
// step functionaries) are NOT relaxed — a policy author must spell out "*"
// explicitly there.
func effectivePolicySignerSANList(pinned bool, constraint, certValues []string) []string {
	if pinned && len(constraint) == 0 && len(certValues) == 0 {
		return []string{policy.AllowAllConstraint}
	}
	return constraint
}

// effectivePolicySignerCommonName resolves the CommonName constraint applied
// to a keyless POLICY-SIGNER cert. A keyless Fulcio cert legitimately has an
// EMPTY Subject CommonName — its identity lives in the email + OIDC-issuer SANs
// — so the release-fanout verify pins the signer with --policy-emails /
// --policy-uris and leaves --policy-commonname at its empty default.
//
// After #5746 an empty CommonName CONSTRAINT fails closed (a forgotten/blank CN
// must not silently accept any value). That hardening is correct for a
// policy-EMBEDDED functionary CN, but for the policy SIGNER it rejected every
// keyless author-signed policy. We restore the v3.0.9 behavior for the signer
// path ONLY, and ONLY when identity is GENUINELY pinned: if CommonName is empty
// AND the email or URI constraint list actually pins identity, the empty CN
// means "CN unconstrained" (returns AllowAllConstraint).
//
// The anti-bypass from #5746 is preserved AND tightened: an empty CommonName is
// relaxed ONLY when pinsIdentity is true for email or URI. A list that is empty,
// nil, or that contains a wildcard ("*") or empty-string element does NOT pin —
// because under the downstream OR-matching of multi-value SAN constraints
// (attestation/policy.checkCertConstraint) a "*" matches ANY value at any
// position (policy.hasAllowAll) and an empty element is dropped
// (policy.dropEmpty). So a list like ["*", "trusted@example.com"] matches any
// cert email and does NOT restrict identity; relaxing the CN there would yield a
// fully-unconstrained signer (fail-open). Such cases are left empty and continue
// to fail closed downstream. The functionary CN check
// (attestation/policy.checkCertConstraintGlob) is NOT touched.
func effectivePolicySignerCommonName(vo *VerifyPolicySignatureOptions) string {
	if vo.policyCommonName != "" {
		return vo.policyCommonName
	}
	if pinsIdentity(vo.policyEmails) || pinsIdentity(vo.policyURIs) {
		return policy.AllowAllConstraint
	}
	return vo.policyCommonName
}

// pinsIdentity reports whether a multi-value SAN constraint list GENUINELY
// restricts identity under the downstream OR-matching semantics
// (attestation/policy.checkCertConstraint). A list pins identity iff it is
// non-empty AND every element is a concrete value: non-empty and not the
// AllowAll wildcard ("*").
//
// A list that is empty/nil does not constrain. A list containing "*" matches
// ANY value (policy.hasAllowAll honors the wildcard at any position), so even
// ["*", "trusted@example.com"] does NOT pin — it accepts any cert. An empty
// element is dropped by policy.dropEmpty and carries no identity; a list with
// one is treated conservatively as non-pinning here, which is strictly safer
// than the downstream behavior. Only when EVERY element is concrete can the
// empty-CN relaxation in effectivePolicySignerCommonName fire.
func pinsIdentity(in []string) bool {
	if len(in) == 0 {
		return false
	}
	for _, s := range in {
		if s == "" || s == policy.AllowAllConstraint {
			return false
		}
	}
	return true
}

// policyVerifierIdentityHint extracts the SAN identity (URIs/emails, or CN
// as a fallback) and OIDC issuer from each x509 policy-signing cert so a
// failed match can tell the operator the exact --policy-uris value to use.
func policyVerifierIdentityHint(verifiers []dsse.CheckedVerifier) string {
	parts := make([]string, 0, len(verifiers))
	for _, v := range verifiers {
		x509v, ok := v.Verifier.(*cryptoutil.X509Verifier)
		if !ok {
			continue
		}
		cert := x509v.Certificate()
		if cert == nil {
			continue
		}
		fields := make([]string, 0, 4)
		for _, u := range cert.URIs {
			fields = append(fields, "uri="+u.String())
		}
		for _, e := range cert.EmailAddresses {
			fields = append(fields, "email="+e)
		}
		if len(fields) == 0 && cert.Subject.CommonName != "" {
			fields = append(fields, "cn="+cert.Subject.CommonName)
		}
		if ext, err := certificate.ParseExtensions(cert.Extensions); err == nil && ext.Issuer != "" {
			fields = append(fields, "issuer="+ext.Issuer)
		}
		if len(fields) > 0 {
			parts = append(parts, strings.Join(fields, ", "))
		}
	}
	return strings.Join(parts, " | ")
}
