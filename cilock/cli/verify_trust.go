// Copyright 2026 The Aflock Authors
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

package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/aflock-ai/rookery/cilock/internal/embeddedtrust"
	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// loadEmbeddedTrust is the one seam through which package cli reads the trust
// compiled into this binary. Tests swap it (restoring with t.Cleanup, never in
// parallel) to hand verify roots without a baked trust.json.
var loadEmbeddedTrust = embeddedtrust.Load

// embeddedPolicyTrust is the compiled-in policy trust with its roots parsed
// once, so the caller's "is there any trust at all" precheck and the trust
// assembly read the same certificates.
type embeddedPolicyTrust struct {
	trust       *embeddedtrust.Trust
	fulcioRoots []*x509.Certificate
	tsaRoots    []*x509.Certificate
}

// loadEmbeddedPolicyTrust returns the embedded policy trust, or nil when the
// operator opted out (--no-embedded-trust / CILOCK_NO_EMBEDDED_TRUST) or the
// build embeds nothing. The opt-out is checked before the loader runs.
func loadEmbeddedPolicyTrust(vo options.VerifyOptions) (*embeddedPolicyTrust, error) {
	if vo.NoEmbeddedTrust || os.Getenv("CILOCK_NO_EMBEDDED_TRUST") != "" {
		log.Infof("ignoring embedded policy trust (--no-embedded-trust); supply --policy-ca-roots / --policy-* explicitly")
		return nil, nil
	}
	t, err := loadEmbeddedTrust()
	if err != nil {
		return nil, fmt.Errorf("load embedded policy trust: %w", err)
	}
	return parseEmbeddedPolicyTrust(t)
}

func parseEmbeddedPolicyTrust(t *embeddedtrust.Trust) (*embeddedPolicyTrust, error) {
	if t == nil {
		return nil, nil
	}
	fulcio, err := t.FulcioRoots()
	if err != nil {
		return nil, err
	}
	tsa, err := t.TSARoots()
	if err != nil {
		return nil, err
	}
	return &embeddedPolicyTrust{trust: t, fulcioRoots: fulcio, tsaRoots: tsa}, nil
}

// policySignatureTrust is what a policy-signature (or approval-signature)
// check trusts: CA roots and intermediates for the signing leaf, and timestamp
// verifiers for its RFC 3161 token. tsaCerts is kept only for display.
type policySignatureTrust struct {
	roots              []*x509.Certificate
	intermediates      []*x509.Certificate
	timestampVerifiers []timestamp.TimestampVerifier
	tsaCerts           []*x509.Certificate
}

// resolvePolicySignatureTrust assembles signature trust from, in order, the
// --policy-ca-roots / --policy-ca-intermediates files, the discovered CA
// bundle, the --policy-timestamp-servers files, the discovered TSA chain, and
// embedded trust for any dimension the flags left empty.
//
// applyEmbeddedSigner decides whether the embedded policy-signer identity is
// written into vo's --policy-* identity fields. Policy verification passes true
// when no identity flag was set. A caller verifying a signature that is not the
// release workflow's (an approval) passes false.
func resolvePolicySignatureTrust(vo *options.VerifyOptions, emb *embeddedPolicyTrust, applyEmbeddedSigner bool) (policySignatureTrust, error) {
	var st policySignatureTrust
	if err := st.addCAFiles(vo); err != nil {
		return st, err
	}
	if err := st.addDiscoveredCA(vo.PolicyCARootsPEM); err != nil {
		return st, err
	}
	if err := st.addTimestampFiles(vo.PolicyTimestampServers); err != nil {
		return st, err
	}
	if err := st.addDiscoveredTSA(vo.PolicyTSAChainPEM); err != nil {
		return st, err
	}
	if err := st.applyEmbedded(vo, emb, applyEmbeddedSigner); err != nil {
		return st, err
	}
	return st, nil
}

// addCAFiles loads --policy-ca-roots and --policy-ca-intermediates.
//
// --policy-ca-roots may point at a MULTI-cert PEM bundle (the platform's
// fulcio-roots.pem is the Fulcio CA + the self-signed Root CA, in that order).
// Every cert is parsed and bucketed by self-signedness, so the keyless signing
// leaf chains leaf -> Fulcio CA -> Root. This is what makes the published-trust
// offline command
// `cilock verify --policy-ca-roots fulcio-roots.pem ... --platform-url ""`
// work with one file. --policy-ca-intermediates loads EVERY cert as an
// intermediate: the operator explicitly declared them as such.
func (st *policySignatureTrust) addCAFiles(vo *options.VerifyOptions) error {
	for _, caPath := range vo.PolicyCARootPaths {
		caFile, err := os.ReadFile(caPath) //nolint:gosec // G304: caPath is from CLI flags
		if err != nil {
			return fmt.Errorf("failed to read root CA certificate file: %w", err)
		}
		roots, intermediates, err := splitPEMCertsBySelfSigned(caFile)
		if err != nil {
			return fmt.Errorf("failed to parse root CA certificate file %q: %w", caPath, err)
		}
		st.roots = append(st.roots, roots...)
		st.intermediates = append(st.intermediates, intermediates...)
	}
	for _, caPath := range vo.PolicyCAIntermediatePaths {
		caFile, err := os.ReadFile(caPath) //nolint:gosec // G304: caPath is from CLI flags
		if err != nil {
			return fmt.Errorf("failed to read intermediate CA certificate file: %w", err)
		}
		certs, err := parsePEMCerts(caFile)
		if err != nil {
			return fmt.Errorf("failed to parse intermediate CA certificate file %q: %w", caPath, err)
		}
		st.intermediates = append(st.intermediates, certs...)
	}
	return nil
}

// addDiscoveredCA loads the CA roots discovered from the platform (the inlined
// trust bundle in /.well-known/judge-configuration), split by self-signedness
// exactly as the file flags are. Non-certificate PEM blocks are skipped.
func (st *policySignatureTrust) addDiscoveredCA(bundle []byte) error {
	for rest := bundle; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemTypeCertificate {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse discovered CA certificate: %w", err)
		}
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			st.roots = append(st.roots, cert)
		} else {
			st.intermediates = append(st.intermediates, cert)
		}
	}
	return nil
}

// addTimestampFiles loads each --policy-timestamp-servers file. A TSA chain
// file (the platform's tsa-chain.pem) holds the TSA leaf AND the self-signed
// Root CA; EVERY cert goes into one verifier pool so p7.VerifyWithChain can
// build TSA-leaf -> Root. Parsing only the first cert dropped the anchor and
// broke the single-file offline command
// `cilock verify --policy-timestamp-servers tsa-chain.pem ... --platform-url ""`.
func (st *policySignatureTrust) addTimestampFiles(paths []string) error {
	for _, server := range paths {
		f, err := os.ReadFile(server) //nolint:gosec // G304: server path is from CLI flags
		if err != nil {
			return fmt.Errorf("failed to open Timestamp Server CA certificate file: %w", err)
		}
		certs, err := parsePEMCerts(f)
		if err != nil {
			return fmt.Errorf("failed to parse Timestamp Server CA certificate file %q: %w", server, err)
		}
		st.timestampVerifiers = append(st.timestampVerifiers, timestamp.NewVerifier(timestamp.VerifyWithCerts(certs)))
		st.tsaCerts = append(st.tsaCerts, certs...)
	}
	return nil
}

// addDiscoveredTSA loads the TSA chain discovered from the platform (served at
// the discovery document's tsa_cert_chain_url). ResolvePlatformDefaults sets it
// ONLY when the operator passed no --policy-timestamp-servers AND the discovery
// CA bundle was adopted under its TOFU pin (GHSA #5988), so the timestamp leg
// rides the same trust decision as the CA leg.
func (st *policySignatureTrust) addDiscoveredTSA(chain []byte) error {
	if len(chain) == 0 {
		return nil
	}
	certs, err := parsePEMCerts(chain)
	if err != nil {
		return fmt.Errorf("failed to parse platform-discovered TSA certificate chain: %w", err)
	}
	if len(certs) > 0 {
		st.timestampVerifiers = append(st.timestampVerifiers, timestamp.NewVerifier(timestamp.VerifyWithCerts(certs)))
		st.tsaCerts = append(st.tsaCerts, certs...)
	}
	return nil
}

// applyEmbedded fills any trust dimension the operator did not pass on the
// command line from embedded trust. Flags win wholesale per dimension. It
// covers ONLY signature trust; attestation trust always comes from the policy.
//
// The embedded signer identity is applied only when applyEmbeddedSigner is
// true. Policy verification sets it only when the operator pinned NO signer
// identity at all (CN/DNS/email/org/URIs/Fulcio extensions): gating on
// --policy-uris alone would silently overwrite an operator who pinned the
// signer via --policy-emails / --policy-fulcio-* without --policy-uris.
func (st *policySignatureTrust) applyEmbedded(vo *options.VerifyOptions, emb *embeddedPolicyTrust, applyEmbeddedSigner bool) error {
	if emb == nil {
		return nil
	}
	applied := make([]string, 0, 3)
	if len(vo.PolicyCARootPaths) == 0 && len(emb.fulcioRoots) > 0 {
		st.roots = append(st.roots, emb.fulcioRoots...)
		applied = append(applied, "ca-roots")
	}
	if len(vo.PolicyTimestampServers) == 0 && len(emb.tsaRoots) > 0 {
		for _, c := range emb.tsaRoots {
			st.timestampVerifiers = append(st.timestampVerifiers, timestamp.NewVerifier(timestamp.VerifyWithCerts([]*x509.Certificate{c})))
			st.tsaCerts = append(st.tsaCerts, c)
		}
		applied = append(applied, "timestamp-roots")
	}
	if signers := emb.trust.PolicySigners; applyEmbeddedSigner && len(signers) > 0 {
		if len(signers) > 1 {
			return fmt.Errorf("embedded trust defines %d policy signers; selecting among multiple embedded signers is not yet supported; pass --policy-uris / --policy-fulcio-* to choose", len(signers))
		}
		cc := signers[0].CertConstraint
		vo.PolicyCommonName = cc.CommonName
		vo.PolicyDNSNames = cc.DNSNames
		vo.PolicyEmails = cc.Emails
		vo.PolicyOrganizations = cc.Organizations
		vo.PolicyURIs = cc.URIs
		vo.PolicyFulcioCertExtensions = cc.Extensions
		applied = append(applied, "signer-identity")
	}
	if len(applied) > 0 {
		src := emb.trust.Source
		if src == "" {
			src = "this build"
		}
		log.Infof("using embedded policy trust from %s (%s); override with the corresponding --policy-* flags, or ignore it entirely with --no-embedded-trust", src, strings.Join(applied, ", "))
	}
	return nil
}
