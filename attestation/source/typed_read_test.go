// jade:ring local

package source

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// A verified envelope is read as an in-toto statement only when it is typed
// as one: DSSE's payloadType is authenticated precisely so a verifier can
// refuse bytes signed for another purpose (DSSE protocol: "Reject if
// PAYLOAD_TYPE is not a supported type"), and the in-toto envelope layer names
// the supported types (application/vnd.in-toto+json and
// application/vnd.in-toto.<predicate>+json). The statement's _type must be a
// Statement schema. And what the policy reads is decoded from the verified
// bytes, never taken from the source (DSSE: "the same SERIALIZED_BODY that is
// verified is the same sent to the application layer").

const typedReadDigest = "4f1c6e1b0a7a1f4b6ad0e5d8f1c2b3a4d5e6f708192a3b4c5d6e7f8091a2b3c4"

func typedReadStatement(t *testing.T, stmtType, predicateType string, predicate string) []byte {
	t.Helper()
	return []byte(fmt.Sprintf(`{"_type":%q,"subject":[{"name":"a","digest":{"sha256":%q}}],"predicateType":%q,"predicate":%s}`,
		stmtType, typedReadDigest, predicateType, predicate))
}

const typedReadCollection = `{"name":"step","attestations":[]}`

func TestEnvelopeToCollectionEnvelopeRefusesForeignPayloadType(t *testing.T) {
	for _, pt := range []string{
		"application/vnd.aflock.policy+json",
		"application/json",
		"",
		"APPLICATION/VND.IN-TOTO+JSON",
		"application/vnd.in-toto.+json",
	} {
		env := dsse.Envelope{PayloadType: pt, Payload: typedReadStatement(t, intoto.StatementType, attestation.CollectionType, typedReadCollection)}
		if _, err := EnvelopeToCollectionEnvelope("ref", env); err == nil {
			t.Errorf("payloadType %q: a verified envelope typed for another purpose was read as an in-toto collection", pt)
		}
	}
}

func TestEnvelopeToCollectionEnvelopeRefusesForeignStatementType(t *testing.T) {
	for _, st := range []string{"", "https://example.com/NotAStatement", "https://in-toto.io/Statement/v2", "https://in-toto.io/Statement/v0.1 "} {
		env := dsse.Envelope{PayloadType: intoto.PayloadType, Payload: typedReadStatement(t, st, attestation.CollectionType, typedReadCollection)}
		if _, err := EnvelopeToCollectionEnvelope("ref", env); err == nil {
			t.Errorf("_type %q: a payload that is not an in-toto Statement was read as one", st)
		}
	}
}

func TestEnvelopeToCollectionEnvelopeAcceptsInTotoTypes(t *testing.T) {
	for _, pt := range []string{intoto.PayloadType, "application/vnd.in-toto.provenance+json"} {
		for _, st := range []string{intoto.StatementType, "https://in-toto.io/Statement/v1"} {
			env := dsse.Envelope{PayloadType: pt, Payload: typedReadStatement(t, st, attestation.CollectionType, typedReadCollection)}
			if _, err := EnvelopeToCollectionEnvelope("ref", env); err != nil {
				t.Errorf("payloadType %q, _type %q: refused: %v", pt, st, err)
			}
		}
	}
}

// typedReadSource returns one envelope next to a decode the source chose.
type typedReadSource struct {
	env  dsse.Envelope
	stmt intoto.Statement
	att  attestation.Attestor
}

func (s typedReadSource) Search(context.Context, string, []string, []string) ([]CollectionEnvelope, error) {
	return nil, nil
}

func (s typedReadSource) SearchByPredicateType(context.Context, []string, []string) ([]StatementEnvelope, error) {
	return []StatementEnvelope{{Envelope: s.env, Statement: s.stmt, Attestor: s.att, Reference: "typed-read"}}, nil
}

func typedReadSigned(t *testing.T, payloadType string, payload []byte) (dsse.Envelope, cryptoutil.Verifier) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.Sign(payloadType, strings.NewReader(string(payload)), dsse.SignWithSigners(cryptoutil.NewECDSASigner(priv, crypto.SHA256)))
	if err != nil {
		t.Fatal(err)
	}
	return env, cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
}

const (
	typedReadSigned1 = "https://example.com/signed-predicate/v1"
	typedReadClaimed = "https://example.com/claimed-predicate/v1"
)

func typedReadSearch(t *testing.T, src typedReadSource, v cryptoutil.Verifier, requested string) StatementEnvelope {
	t.Helper()
	rs, err := NewVerifiedSource(src, dsse.VerifyWithVerifiers(v)).SearchByPredicateType(context.Background(), []string{requested}, []string{typedReadDigest})
	if err != nil || len(rs) != 1 {
		t.Fatalf("SearchByPredicateType: %d results, err %v", len(rs), err)
	}
	return rs[0]
}

func TestVerifiedExternalReadsTheVerifiedBytes(t *testing.T) {
	env, v := typedReadSigned(t, intoto.PayloadType, typedReadStatement(t, intoto.StatementType, typedReadSigned1, `{"verdict":"signed"}`))
	src := typedReadSource{
		env:  env,
		stmt: intoto.Statement{Type: intoto.StatementType, PredicateType: typedReadSigned1, Predicate: json.RawMessage(`{"verdict":"claimed"}`)},
		att:  attestation.NewRawAttestation(typedReadSigned1, json.RawMessage(`{"verdict":"claimed"}`)),
	}
	got := typedReadSearch(t, src, v, typedReadSigned1)
	if len(got.Verifiers) == 0 {
		t.Fatalf("the validly signed envelope was refused: %v", got.Errors)
	}
	if string(got.Statement.Predicate) != `{"verdict":"signed"}` {
		t.Errorf("the statement handed on is the source's, not the verified bytes': predicate %s", got.Statement.Predicate)
	}
	raw, err := json.Marshal(got.Attestor)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"signed"`) || strings.Contains(string(raw), `"claimed"`) {
		t.Errorf("the attestor policy evaluates is the source's, not the verified bytes': %s", raw)
	}
}

func TestVerifiedExternalRefusesUnrequestedPredicateType(t *testing.T) {
	env, v := typedReadSigned(t, intoto.PayloadType, typedReadStatement(t, intoto.StatementType, typedReadSigned1, `{}`))
	src := typedReadSource{env: env, stmt: intoto.Statement{Type: intoto.StatementType, PredicateType: typedReadClaimed}}
	got := typedReadSearch(t, src, v, typedReadClaimed)
	if len(got.Verifiers) != 0 {
		t.Errorf("an envelope signed as %s was accepted in a search for %s", typedReadSigned1, typedReadClaimed)
	}
}

func TestVerifiedExternalRefusesForeignPayloadType(t *testing.T) {
	env, v := typedReadSigned(t, "application/json", typedReadStatement(t, intoto.StatementType, typedReadSigned1, `{}`))
	src := typedReadSource{env: env, stmt: intoto.Statement{Type: intoto.StatementType, PredicateType: typedReadSigned1}}
	got := typedReadSearch(t, src, v, typedReadSigned1)
	if len(got.Verifiers) != 0 {
		t.Errorf("an envelope signed as application/json was accepted as an in-toto statement")
	}
}

func TestVerifiedExternalRefusesForeignStatementType(t *testing.T) {
	env, v := typedReadSigned(t, intoto.PayloadType, typedReadStatement(t, "https://example.com/NotAStatement", typedReadSigned1, `{}`))
	src := typedReadSource{env: env, stmt: intoto.Statement{Type: intoto.StatementType, PredicateType: typedReadSigned1}}
	got := typedReadSearch(t, src, v, typedReadSigned1)
	if len(got.Verifiers) != 0 {
		t.Errorf("a payload whose _type is not an in-toto Statement was accepted")
	}
}
