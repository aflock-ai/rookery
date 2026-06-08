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

package dsse

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation/timestamp"
)

// trustedRootsProvider is the optional interface a timestamp verifier may
// implement to expose the policy-trusted TSA roots it was configured with.
// timestamp.TSPVerifier satisfies it; the FakeTimestamper used in tests does
// not, in which case the TSA diagnostic is simply skipped.
type trustedRootsProvider interface {
	TrustedRoots() []*x509.Certificate
}

// TrustNameKeyMismatchError is a DIAGNOSTIC error. It is produced only on an
// already-failing verify when the artifact's signing chain shares a Subject
// Common Name with one of the policy's trusted roots/intermediates but uses a
// DIFFERENT key. This is the classic "wrong platform" failure: e.g. a
// prod-signed artifact verified against a staging-trust policy, where both
// CAs are named "TestifySec Platform Root CA" but carry different keys.
//
// It NEVER changes the verification verdict — by the time this is constructed,
// the signature has ALREADY failed to verify. It only enriches the
// human-readable reason so an operator knows the real cause instead of seeing
// a bare "unknown authority".
type TrustNameKeyMismatchError struct {
	// CommonName is the shared Subject CN that triggered the diagnostic.
	CommonName string
	// ArtifactKeyID is the key fingerprint of the CA in the artifact's
	// signing chain that carries CommonName.
	ArtifactKeyID string
	// PolicyKeyID is the key fingerprint of the policy-trusted root/
	// intermediate that carries the same CommonName.
	PolicyKeyID string
	// IsTimestamp is true when the mismatch was detected on the timestamp
	// (TSA) trust path rather than the signing (Fulcio) path. It only
	// changes the wording ("timestamp produced by" vs "signed by").
	IsTimestamp bool
}

func (e TrustNameKeyMismatchError) Error() string {
	// Only the "Same name, different key:" clause changes between the Fulcio
	// (signing) and TSA (timestamp) paths, per spec. Everything else — the
	// header, the two "artifact signed by" / "policy trusts" lines, and the
	// Fix guidance — is identical so the block is recognizable in both cases.
	mismatchClause := "this artifact was signed against a DIFFERENT platform\n  than the policy trusts"
	if e.IsTimestamp {
		mismatchClause = "the timestamp was produced by a different platform\n  than the policy trusts"
	}
	return fmt.Sprintf(`TRUST MISMATCH: the artifact's signing chain and the policy's trusted roots
share a Common Name but NOT a key —
    artifact signed by : %q  key=%s
    policy trusts      : %q  key=%s
  Same name, different key: %s (e.g. a prod-signed artifact verified against a
  staging-trust policy, or vice-versa).
  Fix: regenerate the policy roots/timestampauthorities from the SIGNING platform's
  ${PLATFORM}/.well-known/judge-configuration and re-sign — or verify against that
  platform's policy.`,
		e.CommonName, e.ArtifactKeyID,
		e.CommonName, e.PolicyKeyID,
		mismatchClause)
}

// certKeyFingerprint returns a short, stable identifier for a certificate's
// key. It prefers the Subject Key Identifier (SKI) when present, falling back
// to the first 8 hex chars of sha256(DER SubjectPublicKeyInfo). The SKI is the
// canonical "which key" anchor in PKI; the SPKI hash is a deterministic
// substitute for certs that omit the SKI extension (common for short-lived
// Fulcio leaves, though CAs almost always carry one).
func certKeyFingerprint(cert *x509.Certificate) string {
	if len(cert.SubjectKeyId) > 0 {
		return hex.EncodeToString(cert.SubjectKeyId)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])[:8]
}

// detectTrustNameKeyMismatch compares the CAs in an artifact's signing chain
// against the policy-trusted roots/intermediates and returns a diagnostic
// error iff some CN appears in BOTH sets but with DIFFERENT keys. It returns
// nil when no such collision exists — in particular, a genuinely-unrelated CA
// (different CN) yields nil, so the caller falls through to the existing
// "unknown authority" error and no false TRUST MISMATCH is emitted.
//
// artifactChain is the leaf's issuer chain (the signature's cert plus its
// intermediates); policyTrusted is the policy's roots plus its configured
// intermediates. Leaf certificates are skipped on both sides — the diagnostic
// is about CA trust anchors, and a Fulcio leaf legitimately shares no CN with
// a CA.
func detectTrustNameKeyMismatch(artifactChain, policyTrusted []*x509.Certificate, isTimestamp bool) *TrustNameKeyMismatchError {
	policyByCN := indexCAsByCN(policyTrusted)
	if len(policyByCN) == 0 {
		return nil
	}

	for _, c := range artifactChain {
		cn, ok := caCommonName(c)
		if !ok {
			continue
		}
		policyFPs, ok := policyByCN[cn]
		if !ok {
			continue // different CN entirely — not our case, stay silent
		}
		artifactFP := certKeyFingerprint(c)
		if _, keyMatches := policyFPs[artifactFP]; keyMatches {
			continue // same CN AND same key for this CA — no mismatch here
		}
		// Same CN, but this artifact CA's key is not among the policy's keys
		// for that CN: that is the trust mismatch. Report the first
		// policy-trusted key under the shared CN as the contrast.
		return &TrustNameKeyMismatchError{
			CommonName:    cn,
			ArtifactKeyID: artifactFP,
			PolicyKeyID:   anyKey(policyFPs),
			IsTimestamp:   isTimestamp,
		}
	}

	return nil
}

// caCommonName returns the Subject CN of a non-nil CA certificate, or ok=false
// for nil certs, non-CA leaves, or CAs with an empty CN — all of which the
// trust diagnostic must skip.
func caCommonName(c *x509.Certificate) (string, bool) {
	if c == nil || !c.IsCA || c.Subject.CommonName == "" {
		return "", false
	}
	return c.Subject.CommonName, true
}

// indexCAsByCN maps each CA's Subject CN to the set of key fingerprints seen
// under that CN.
func indexCAsByCN(certs []*x509.Certificate) map[string]map[string]struct{} {
	byCN := make(map[string]map[string]struct{})
	for _, c := range certs {
		cn, ok := caCommonName(c)
		if !ok {
			continue
		}
		fps := byCN[cn]
		if fps == nil {
			fps = make(map[string]struct{})
			byCN[cn] = fps
		}
		fps[certKeyFingerprint(c)] = struct{}{}
	}
	return byCN
}

// anyKey returns an arbitrary fingerprint from the set (used to show one
// policy-trusted key as the contrast in the diagnostic).
func anyKey(fps map[string]struct{}) string {
	for fp := range fps {
		return fp
	}
	return ""
}

// detectTimestampMismatch runs the same-CN/different-key diagnostic on the TSA
// path. It parses the TSA's signing chain out of the timestamp token bytes and
// compares it against the policy-trusted TSA roots exposed by the verifier. It
// returns nil (silent) when the verifier does not expose its roots, when the
// token can't be parsed, or when there is no CN collision — so it never
// produces a false positive on a genuinely-unrelated TSA.
func detectTimestampMismatch(tsrData []byte, tv timestamp.TimestampVerifier) *TrustNameKeyMismatchError {
	provider, ok := tv.(trustedRootsProvider)
	if !ok {
		return nil
	}
	// A parse failure or an empty chain means we can't diagnose — stay silent
	// (return nil) rather than guess. Gate on the success path so the nil return
	// is unconditional, not a "swallow the error" path.
	if tsaChain, err := timestamp.TokenCertificates(tsrData); err == nil && len(tsaChain) > 0 {
		return detectTrustNameKeyMismatch(tsaChain, provider.TrustedRoots(), true)
	}
	return nil
}

// chainIssuerFingerprint renders the key fingerprint of the first CA in an
// artifact's issuer chain (the cert that anchors trust). Used only for the
// [dsse-verify] debug line. Returns "(none)" when the chain carries no CA.
func chainIssuerFingerprint(chain []*x509.Certificate) string {
	for _, c := range chain {
		if c != nil && c.IsCA {
			return certKeyFingerprint(c)
		}
	}
	return "(none)"
}

// trustedRootFingerprints renders the key fingerprints of the policy-trusted
// roots for the [dsse-verify] debug line, so a mismatch against the artifact's
// issuer fingerprint is visible at a glance.
func trustedRootFingerprints(roots []*x509.Certificate) string {
	if len(roots) == 0 {
		return "(none)"
	}
	fps := make([]string, 0, len(roots))
	for _, c := range roots {
		if c == nil {
			continue
		}
		fps = append(fps, certKeyFingerprint(c))
	}
	return strings.Join(fps, ",")
}
