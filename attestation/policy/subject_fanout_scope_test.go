// Copyright 2026 The Archivista Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
)

const (
	fsCommit  = "3d7b4fdb1c9e2a5f8b0c7d4e6a1f3b8c9d2e5a70"
	fsGitType = "https://aflock.ai/attestations/git/v0.1"
	fsSBOMTyp = "https://aflock.ai/attestations/sbom/v0.1"
)

// fsAttestationBody returns the body a producer of the given type signs. For
// the git type that is the HARDENED shape — commithash plus the
// "commithashverified" capability marker — because the SHA-1 scope these tests
// exercise is granted only to hardened git evidence; a bare `{}` git body
// would be LEGACY evidence and (correctly) never open the arm.
func fsAttestationBody(typ string) json.RawMessage {
	if typ == fsGitType {
		return json.RawMessage(`{"commithash":"` + fsCommit + `","commithashverified":true}`)
	}
	return json.RawMessage(`{}`)
}

// signedCollectionPayload marshals a collection statement to the bytes a source
// would SIGN — the source of truth a verification verdict must read, distinct
// from the Statement/Collection struct fields a source can project independently.
func signedCollectionPayload(t *testing.T, subjects []intoto.Subject, attTypes ...string) []byte {
	t.Helper()
	atts := make([]attestation.CollectionAttestation, 0, len(attTypes))
	for _, typ := range attTypes {
		atts = append(atts, attestation.CollectionAttestation{
			Type:        typ,
			Attestation: attestation.NewRawAttestation(typ, fsAttestationBody(typ)),
		})
	}
	predicate, err := json.Marshal(attestation.Collection{Name: "build", Attestations: atts})
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	b, err := json.Marshal(intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: attestation.CollectionType,
		Subject:       subjects,
		Predicate:     json.RawMessage(predicate),
	})
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}
	return b
}

// fsEnvelope builds the decoded envelope the guard actually sees: a statement
// with one commithash subject, and a collection carrying the given attestation
// types.
func fsEnvelope(t *testing.T, attTypes ...string) source.CollectionEnvelope {
	t.Helper()
	atts := make([]attestation.CollectionAttestation, 0, len(attTypes))
	for _, typ := range attTypes {
		atts = append(atts, attestation.CollectionAttestation{
			Type:        typ,
			Attestation: attestation.NewRawAttestation(typ, fsAttestationBody(typ)),
		})
	}
	return source.CollectionEnvelope{
		Statement: intoto.Statement{
			// A real collection envelope always carries the collection
			// predicateType (EnvelopeToCollectionEnvelope decodes it from the
			// signed payload). SubjectMatchScope now gates the git arm on it — a
			// bare external predicate must not claim the SHA-1 exception — so the
			// fixture has to be a genuine collection, not a struct with a
			// collection body and no type.
			PredicateType: attestation.CollectionType,
			Subject: []intoto.Subject{{
				Name:   "commithash:" + fsCommit,
				Digest: map[string]string{"sha1": fsCommit},
			}},
		},
		Collection: attestation.Collection{Name: "build", Attestations: atts},
	}
}

// TestClosureIntersectOne_GitScope pins the THIRD call site of the subject
// matcher against the other two.
//
// The index build (MemorySource) and the artifact-substitution guard
// (VerifiedSource) both stopped granting the SHA-1 commit exception to a
// statement that does not attest git. The fan-out guard reads subjects too,
// and a rule applied at two of three sites is a rule the third disagrees with:
// here the disagreement is not a fail-open — this guard only ever REMOVES
// candidates — but it would make hub classification count a connection the
// other two sites do not believe exists, so an operator would see a candidate
// hub-rejected over a digest that never anchored anything.
func TestClosureIntersectOne_GitScope(t *testing.T) {
	closure := map[string]struct{}{fsCommit: {}}

	gitAttested := closureIntersectOne(fsEnvelope(t, fsGitType), closure)
	if _, ok := gitAttested[fsCommit]; !ok {
		t.Errorf("a git-attested collection's commithash subject did not connect it to the closure "+
			"(got %v) — real evidence would be hub-rejected as closure-disjoint", gitAttested)
	}

	notGitAttested := closureIntersectOne(fsEnvelope(t, fsSBOMTyp), closure)
	if _, ok := notGitAttested[fsCommit]; ok {
		t.Errorf("a minted commithash subject on a collection that attests no git connected it to "+
			"the closure (got %v) — the fan-out guard still honours a label the index and the "+
			"substitution guard both refuse", notGitAttested)
	}
}

// TestClosureIntersectOne_ClassifiesFromSignedPayloadNotProjection is the
// trust-boundary rebuttal. The fan-out guard is a VERIFICATION verdict input, so
// the candidate's subjects must come from its SIGNATURE-VERIFIED payload — not
// the Statement/Collection struct fields, which an untrusted source populates
// independently of what was signed. A malicious source passes the substitution
// guard on real signed evidence, then projects a DIFFERENT subject to skew hub
// classification (here: project a victim's digest to inflate its fan-out and
// demote the victim's genuine evidence). closureIntersectOne must read the
// payload, so the decoy projection cannot alter the verdict.
func TestClosureIntersectOne_ClassifiesFromSignedPayloadNotProjection(t *testing.T) {
	realSHA := strings.Repeat("a", 64)  // the candidate's TRUE signed subject
	decoySHA := strings.Repeat("b", 64) // a victim's digest the source projects
	closure := map[string]struct{}{realSHA: {}, decoySHA: {}}

	payload := signedCollectionPayload(t, []intoto.Subject{
		{Name: "artifact", Digest: map[string]string{"sha256": realSHA}},
	})
	// The projection names ONLY the decoy — not the real subject.
	ce := source.CollectionEnvelope{
		Envelope: dsse.Envelope{Payload: payload},
		Statement: intoto.Statement{
			PredicateType: attestation.CollectionType,
			Subject: []intoto.Subject{
				{Name: "artifact", Digest: map[string]string{"sha256": decoySHA}},
			},
		},
		Collection: attestation.Collection{Name: "build"},
	}

	ds := closureIntersectOne(ce, closure)
	if _, ok := ds[realSHA]; !ok {
		t.Error("closureIntersectOne ignored the SIGNED payload's subject — the candidate's real closure " +
			"connection was lost")
	}
	if _, ok := ds[decoySHA]; ok {
		t.Error("closureIntersectOne counted a source-PROJECTED decoy subject absent from the signed payload " +
			"— a malicious source can inflate a victim digest's fan-out and demote genuine evidence")
	}

	// Positive control: a projection consistent with the payload classifies the
	// same as the payload.
	consistent := source.CollectionEnvelope{
		Envelope: dsse.Envelope{Payload: payload},
		Statement: intoto.Statement{
			Subject: []intoto.Subject{{Name: "artifact", Digest: map[string]string{"sha256": realSHA}}},
		},
	}
	ds2 := closureIntersectOne(consistent, closure)
	if _, ok := ds2[realSHA]; !ok || len(ds2) != 1 {
		t.Errorf("positive control: consistent envelope should classify exactly {realSHA}, got %v", ds2)
	}
}

// TestClosureIntersectOne_GitScopeFromSignedPayload pins the SCOPE half of the
// trust boundary: the git-attested scope (which decides whether a SHA-1
// commithash is matchable) must also come from the signed payload. A source that
// signed a NON-git collection but projects a git-attested one into the envelope
// must not thereby open the SHA-1 arm.
func TestClosureIntersectOne_GitScopeFromSignedPayload(t *testing.T) {
	closure := map[string]struct{}{fsCommit: {}}

	// SIGNED payload: sbom only (no git), carrying a git-namespaced commithash.
	payload := signedCollectionPayload(t, []intoto.Subject{
		{Name: fsGitType + "/commithash:" + fsCommit, Digest: map[string]string{"sha1": fsCommit}},
	}, fsSBOMTyp)
	// PROJECTION: a fully HARDENED-shaped git collection (type and marker), to
	// try to open the SHA-1 arm — so what this test pins is that the projection
	// is IGNORED in favour of the signed payload, not that the projection
	// happened to be legacy-shaped.
	ce := source.CollectionEnvelope{
		Envelope: dsse.Envelope{Payload: payload},
		Statement: intoto.Statement{
			PredicateType: attestation.CollectionType,
			Subject: []intoto.Subject{
				{Name: fsGitType + "/commithash:" + fsCommit, Digest: map[string]string{"sha1": fsCommit}},
			},
		},
		Collection: attestation.Collection{Name: "build", Attestations: []attestation.CollectionAttestation{
			{Type: fsGitType, Attestation: attestation.NewRawAttestation(fsGitType, fsAttestationBody(fsGitType))},
		}},
	}

	ds := closureIntersectOne(ce, closure)
	if _, ok := ds[fsCommit]; ok {
		t.Error("closureIntersectOne granted the SHA-1 git arm from the source-PROJECTED git collection — " +
			"the signed payload attests no git, so a sha1 commithash must stay unmatchable")
	}
}
