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

// Package sigstorebundle verifies a Sigstore bundle
// (application/vnd.dev.sigstore.bundle*) under the Sigstore client
// verification procedure (client-spec §4).
//
// The cryptography (path validation, RFC 3161, SETs, inclusion proofs,
// checkpoints, SCTs, signatures) is sigstore-go's, the reference verifier.
// This package owns the policy: which checks are required, and which
// identity is expected. Derive is that policy, and formal/sigstore
// (Sigstore/Bundle.lean, `derive`) proves it accepts exactly what the
// procedure accepts for every trusted root (`required_conforms`).
package sigstorebundle

import (
	"errors"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

var (
	// ErrUnconstrainedIdentity: an empty expected SAN or issuer is not a
	// policy. It would accept every identity the CA ever certified.
	ErrUnconstrainedIdentity = errors.New("sigstore bundle: both --certificate-identity and --certificate-oidc-issuer are required and must be non-empty")
	// ErrNoTimeSource: the bundle carries no time evidence the trusted root
	// can verify, so no signing time can be established (client-spec §4.2).
	ErrNoTimeSource = errors.New("sigstore bundle: no verifiable time evidence: the bundle has no timestamp from a trusted TSA and no transparency-log inclusion promise from a trusted log")
)

// Trust is what a trusted root distributes, beyond its Fulcio CAs.
type Trust struct {
	TSA, Tlog, CT bool
}

// TrustOf reads Trust from trusted material.
func TrustOf(tm root.TrustedMaterial) Trust {
	return Trust{
		TSA:  len(tm.TimestampingAuthorities()) > 0,
		Tlog: len(tm.RekorLogs()) > 0,
		CT:   len(tm.CTLogs()) > 0,
	}
}

// Evidence is what a bundle offers as time evidence.
type Evidence struct {
	Timestamps bool
	Promise    bool
}

// Entity is a signed entity whose evidence can be read.
type Entity interface {
	verify.SignedEntity
}

// EvidenceOf reads Evidence from an entity. The inclusion promise is read
// from the log entries themselves, never from a bundle-level flag.
func EvidenceOf(e Entity) (Evidence, error) {
	ts, err := e.Timestamps()
	if err != nil {
		return Evidence{}, err
	}
	entries, err := e.TlogEntries()
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{Timestamps: len(ts) > 0, Promise: anyPromise(entries)}, nil
}

func anyPromise(entries []*tlog.Entry) bool {
	for _, e := range entries {
		if e != nil && e.HasInclusionPromise() {
			return true
		}
	}
	return false
}

// Policy is the set of checks Derive requires; each is a threshold of one.
type Policy struct {
	SCT, Tlog, SignedTimestamps, IntegratedTimestamps bool
}

// Derive is the verification policy for a certificate-signed bundle.
//   - Every check the trusted root can back is required: an SCT if it
//     distributes CT logs (§4.3), a log entry if it distributes Rekor logs
//     (§4.4).
//   - Time comes from evidence the bundle carries and the root can verify:
//     TSA timestamps (§4.2.1), or a V1 inclusion promise (§4.2.2).
//   - No SAN or no issuer is a refusal, never an unconstrained identity.
func Derive(t Trust, ev Evidence, san, issuer string) (Policy, error) {
	if san == "" || issuer == "" {
		return Policy{}, ErrUnconstrainedIdentity
	}
	return deriveTime(t, ev, Policy{SCT: t.CT, Tlog: t.Tlog})
}

// DeriveKey is the policy for a bundle signed by a managed key: there is
// no certificate, so there is no SCT and no certificate identity. It is
// outside the formal model.
func DeriveKey(t Trust, ev Evidence) (Policy, error) {
	return deriveTime(t, ev, Policy{Tlog: t.Tlog})
}

func deriveTime(t Trust, ev Evidence, p Policy) (Policy, error) {
	p.SignedTimestamps = t.TSA && ev.Timestamps
	p.IntegratedTimestamps = t.Tlog && ev.Promise
	if !p.SignedTimestamps && !p.IntegratedTimestamps {
		return Policy{}, ErrNoTimeSource
	}
	return p, nil
}

// Options renders the policy as sigstore-go verifier options.
func (p Policy) Options() []verify.VerifierOption {
	var opts []verify.VerifierOption
	if p.SCT {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}
	if p.Tlog {
		opts = append(opts, verify.WithTransparencyLog(1))
	}
	if p.SignedTimestamps {
		opts = append(opts, verify.WithSignedTimestamps(1))
	}
	if p.IntegratedTimestamps {
		opts = append(opts, verify.WithIntegratedTimestamps(1))
	}
	return opts
}

// VerifyCertificate verifies a certificate-signed entity: exact SAN and
// exact OIDC issuer.
func VerifyCertificate(e Entity, tm root.TrustedMaterial, artifact verify.ArtifactPolicyOption, san, issuer string) (*verify.VerificationResult, error) {
	ev, err := EvidenceOf(e)
	if err != nil {
		return nil, err
	}
	p, err := Derive(TrustOf(tm), ev, san, issuer)
	if err != nil {
		return nil, err
	}
	id, err := verify.NewShortCertificateIdentity(issuer, "", san, "")
	if err != nil {
		return nil, err
	}
	v, err := verify.NewVerifier(tm, p.Options()...)
	if err != nil {
		return nil, err
	}
	return v.Verify(e, verify.NewPolicy(artifact, verify.WithCertificateIdentity(id)))
}

// VerifyKey verifies an entity signed by the managed key in tm.
func VerifyKey(e Entity, tm root.TrustedMaterial, artifact verify.ArtifactPolicyOption) (*verify.VerificationResult, error) {
	ev, err := EvidenceOf(e)
	if err != nil {
		return nil, err
	}
	p, err := DeriveKey(TrustOf(tm), ev)
	if err != nil {
		return nil, err
	}
	v, err := verify.NewVerifier(tm, p.Options()...)
	if err != nil {
		return nil, err
	}
	return v.Verify(e, verify.NewPolicy(artifact, verify.WithKey()))
}
