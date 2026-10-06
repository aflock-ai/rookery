// jade:ring local

package source

import (
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// The verified read path checks the statement BODY, not only the envelope and
// _type (#10068). in-toto Attestation Framework v1, statement.md: each subject
// "MUST have `digest` set", and `predicateType` is "_string (TypeURI),
// required_". This is the read-side mirror of the write-side checks in
// intoto.newStatement.

const statementBodyValidSubject = `{"name":"a","digest":{"sha256":"` + typedReadDigest + `"}}`

func statementBody(subjects, predicateType, predicate string) []byte {
	return []byte(fmt.Sprintf(`{"_type":%q,"subject":%s,"predicateType":%q,"predicate":%s}`,
		intoto.StatementType, subjects, predicateType, predicate))
}

// Every subject shape that carries no digest. Each is listed next to a valid
// subject too, so a check that looks only at the first subject is caught.
var digestlessSubjects = map[string]string{
	"digest absent":        `{"name":"b"}`,
	"digest null":          `{"name":"b","digest":null}`,
	"digest empty":         `{"name":"b","digest":{}}`,
	"digest value empty":   `{"name":"b","digest":{"sha256":""}}`,
	"no name, uri, digest": `{}`,
}

func TestEnvelopeToCollectionEnvelopeRefusesADigestlessSubject(t *testing.T) {
	for name, subject := range digestlessSubjects {
		for _, list := range []string{"[" + subject + "]", "[" + statementBodyValidSubject + "," + subject + "]"} {
			env := dsse.Envelope{PayloadType: intoto.PayloadType, Payload: statementBody(list, attestation.CollectionType, typedReadCollection)}
			if _, err := EnvelopeToCollectionEnvelope("ref", env); err == nil {
				t.Errorf("%s, subject %s: a statement with a digest-less subject was read as a collection", name, list)
			}
		}
	}
}

func TestVerifiedExternalRefusesADigestlessSubject(t *testing.T) {
	for name, subject := range digestlessSubjects {
		env, v := typedReadSigned(t, intoto.PayloadType, statementBody("["+statementBodyValidSubject+","+subject+"]", typedReadSigned1, `{}`))
		src := typedReadSource{env: env, stmt: intoto.Statement{Type: intoto.StatementType, PredicateType: typedReadSigned1}}
		got := typedReadSearch(t, src, v, typedReadSigned1)
		if len(got.Verifiers) != 0 {
			t.Errorf("%s: an external statement with a digest-less subject was accepted", name)
		}
	}
}

// The collection path already refused an empty predicateType; the external path
// did not, so a search that asked for "" was handed one.
func TestVerifiedExternalRefusesAnEmptyPredicateType(t *testing.T) {
	env, v := typedReadSigned(t, intoto.PayloadType, statementBody("["+statementBodyValidSubject+"]", "", `{}`))
	src := typedReadSource{env: env, stmt: intoto.Statement{Type: intoto.StatementType}}
	got := typedReadSearch(t, src, v, "")
	if len(got.Verifiers) != 0 {
		t.Errorf("an external statement with an empty predicateType was accepted")
	}
}

// Out of scope on purpose (#10068): cilock signs `subject: []` for a step that
// produces no artifact, and the spec prose leaves `predicate` optional. Neither
// may start being refused as a side effect of the digest check.
func TestEnvelopeToCollectionEnvelopeStillAcceptsNoSubjectsAndNoPredicate(t *testing.T) {
	env := dsse.Envelope{PayloadType: intoto.PayloadType, Payload: statementBody("[]", attestation.CollectionType, typedReadCollection)}
	if _, err := EnvelopeToCollectionEnvelope("ref", env); err != nil {
		t.Errorf("subject: [] refused: %v", err)
	}
	payload := []byte(fmt.Sprintf(`{"_type":%q,"subject":[%s],"predicateType":%q}`, intoto.StatementType, statementBodyValidSubject, typedReadSigned1))
	if _, err := decodeInTotoStatement("ref", dsse.Envelope{PayloadType: intoto.PayloadType, Payload: payload}); err != nil {
		t.Errorf("a statement with no predicate refused: %v", err)
	}
}
