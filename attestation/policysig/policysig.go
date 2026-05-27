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
	}
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
		kid, err := verifier.Verifier.KeyID()
		if err != nil {
			return fmt.Errorf("could not get verifier key id: %w", err)
		}

		var f policy.Functionary
		trustBundle := make(map[string]policy.TrustBundle)
		if _, ok := verifier.Verifier.(*cryptoutil.X509Verifier); ok {
			rootIDs := make([]string, 0)
			for _, root := range vo.policyCARoots {
				id := base64.StdEncoding.EncodeToString(root.Raw)
				rootIDs = append(rootIDs, id)
				trustBundle[id] = policy.TrustBundle{
					Root: root,
				}
			}

			f = policy.Functionary{
				Type: "root",
				CertConstraint: policy.CertConstraint{
					Roots:         rootIDs,
					CommonName:    vo.policyCommonName,
					URIs:          vo.policyURIs,
					Emails:        vo.policyEmails,
					Organizations: vo.policyOrganizations,
					DNSNames:      vo.policyDNSNames,
					Extensions:    vo.fulcioCertExtensions,
				},
			}

		} else {
			f = policy.Functionary{
				Type:        "key",
				PublicKeyID: kid,
			}
		}

		err = f.Validate(verifier.Verifier, trustBundle)
		if err != nil {
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
