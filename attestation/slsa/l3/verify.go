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

package l3

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/slsa"
)

// Trust is one root the verifier may accept certificates from: the dsse
// options (roots, intermediates, timestamp verifiers) that verify a chain to
// it. A certificate is labelled with the first Trust that verifies it.
type Trust struct {
	Root    Root
	Options []dsse.VerificationOption
}

// Result is the outcome of Verify.
type Result struct {
	// ObservedLevel is 3 when some provenance statement is accepted and
	// covers every caller subject, otherwise 0 (see ObservedBuildLevel).
	ObservedLevel int `json:"observed_level"`
	// Verdict is the accepted candidate's (empty), or the closest rejected
	// candidate's failures.
	Verdict Verdict `json:"verdict"`
	// Signer and Statement name the candidate the verdict is about.
	Signer    *Cert      `json:"signer,omitempty"`
	Statement *Statement `json:"statement,omitempty"`
	// Problems are envelopes that could not be used, and why.
	Problems []string `json:"problems,omitempty"`
}

// signerCert verifies env under the first trust that accepts it and returns
// the one leaf certificate that signed it. An envelope carrying signatures
// from more than one certificate is refused: which identity it speaks for
// would be ambiguous.
func signerCert(env dsse.Envelope, trusts []Trust) (Root, *x509.Certificate, error) {
	var errs []error
	for _, t := range trusts {
		checked, err := env.Verify(t.Options...)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Root, err))
			continue
		}
		var leaf *x509.Certificate
		for _, c := range checked {
			if c.Error != nil {
				continue
			}
			xv, ok := c.Verifier.(*cryptoutil.X509Verifier)
			if !ok {
				continue
			}
			cert := xv.Certificate()
			if leaf != nil && !bytes.Equal(leaf.Raw, cert.Raw) {
				return "", nil, fmt.Errorf("signed by more than one certificate")
			}
			leaf = cert
		}
		if leaf == nil {
			errs = append(errs, fmt.Errorf("%s: no certificate signature verified", t.Root))
			continue
		}
		return t.Root, leaf, nil
	}
	return "", nil, errors.Join(errs...)
}

func isCollectionType(t string) bool {
	return attestation.IsCollectionType(t)
}

// gather verifies every envelope and sorts the usable ones into provenance
// candidates and build collections; each unusable one is a problem string.
func gather(trusts []Trust, envs []dsse.Envelope) (candidates []Evidence, builds []Collection, problems []string) {
	for i, env := range envs {
		if env.PayloadType != intoto.PayloadType {
			continue
		}
		st, err := decodeStatement(env.Payload)
		if err != nil {
			problems = append(problems, fmt.Sprintf("envelope %d: %v", i, err))
			continue
		}
		isProv := st.PredicateType == ProvenancePredicateType
		if !isProv && !isCollectionType(st.PredicateType) {
			continue
		}
		cert, err := verifiedCert(env, trusts)
		if err != nil {
			problems = append(problems, fmt.Sprintf("envelope %d (%s): %v", i, st.PredicateType, err))
			continue
		}
		if !isProv {
			keys, _ := subjectKeys(st.Subject, false)
			builds = append(builds, Collection{Cert: cert, Subjects: keys})
			continue
		}
		stmt, err := StatementFromPayload(env.Payload)
		if err != nil {
			problems = append(problems, fmt.Sprintf("envelope %d: provenance: %v", i, err))
			continue
		}
		candidates = append(candidates, Evidence{Signer: cert, Statement: stmt})
	}
	return candidates, builds, problems
}

// verifiedCert is the Cert of env's one signing certificate, under the first
// trust that verifies it.
func verifiedCert(env dsse.Envelope, trusts []Trust) (Cert, error) {
	root, leaf, err := signerCert(env, trusts)
	if err != nil {
		return Cert{}, fmt.Errorf("signature: %w", err)
	}
	ext, err := ExtFromCertificate(leaf)
	if err != nil {
		return Cert{}, fmt.Errorf("certificate: %w", err)
	}
	return Cert{Root: root, Ext: ext, ConfigURI: buildConfigURI(leaf)}, nil
}

// evaluate is Accept plus the checks outside the Lean model: buildType,
// externalParameters, the trusted-builder catalog, and the caller subjects.
func evaluate(pol Policy, e Evidence, callerSubjects []string) Verdict {
	v := Accept(pol, e)
	v.require(e.Statement.BuildType == BuildType, ReqBuildType, "buildType %q is not %q", e.Statement.BuildType, BuildType)
	if err := checkExternalParameters(e.Statement.ExternalParameters, e.Signer); err != nil {
		v.require(false, ReqExternalParameters, "%v", err)
	}
	level := slsa.BuilderMaxLevel(e.Statement.BuilderID)
	v.require(level >= 3, ReqTrustedBuilder, "the trusted-builder catalog allows builder %q level %d, not 3", e.Statement.BuilderID, level)
	v.require(len(callerSubjects) > 0, ReqCallerSubjects, "no artifact or subject to look up")
	for _, s := range callerSubjects {
		v.require(slices.Contains(e.Statement.Subjects, s), ReqCallerSubjects, "the provenance does not name %s", s)
	}
	return v
}

// Verify is `cilock verify --slsa-level 3` over a set of envelopes. Envelopes
// whose statement is SLSA v1 provenance are candidates; envelopes whose
// statement is an attestation collection are build evidence. Each candidate
// is checked with Accept against all the build evidence, then every caller
// subject must be among its subjects (requirement 7: caller subjects are
// lookup keys, never evidence). Level 3 is observed when one candidate passes.
func Verify(pol Policy, trusts []Trust, envs []dsse.Envelope, callerSubjects []string) Result {
	var r Result
	if err := pol.Validate(); err != nil {
		r.Verdict.require(false, ReqPolicy, "%v", err)
		return r
	}
	candidates, builds, problems := gather(trusts, envs)
	r.Problems = problems
	if len(candidates) == 0 {
		r.Verdict.require(false, ReqProvenance, "no SLSA v1 provenance statement verified under a trusted root")
		return r
	}
	for i := range candidates {
		e := candidates[i]
		e.Builds = builds
		v := evaluate(pol, e, callerSubjects)
		if r.Signer == nil || len(v.Failures) < len(r.Verdict.Failures) {
			r.Verdict, r.Signer, r.Statement = v, &e.Signer, &e.Statement
		}
		if v.Accepted() {
			r.ObservedLevel = 3
			return r
		}
	}
	return r
}
