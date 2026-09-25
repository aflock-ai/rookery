// jade:ring local

package intoto

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// in-toto Attestation Framework v1, statement.md: predicateType is a
// required TypeURI, predicate is an object (optional), and every subject
// "MUST have digest set". NewStatement is the one constructor every signed
// statement goes through, so it refuses what the spec forbids rather than
// signing it.

func conformanceSubjects(t *testing.T) map[string]cryptoutil.DigestSet {
	t.Helper()
	ds, err := cryptoutil.NewDigestSet(map[string]string{"sha256": "ab01"})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]cryptoutil.DigestSet{"a": ds}
}

func TestNewStatementRefusesEmptyPredicateType(t *testing.T) {
	if _, err := NewStatement("", []byte(`{}`), conformanceSubjects(t)); err == nil {
		t.Fatal("a statement with an empty predicateType was built")
	}
}

func TestNewStatementRefusesNonObjectPredicate(t *testing.T) {
	for _, pred := range []string{`[1]`, `"s"`, `1`, `true`, `null`, ` [] `} {
		if _, err := NewStatement("https://example.com/p/v1", []byte(pred), conformanceSubjects(t)); err == nil {
			t.Errorf("predicate %s is not a JSON object but was signed as one", pred)
		}
	}
}

func TestNewStatementRefusesSubjectWithoutDigest(t *testing.T) {
	subjects := conformanceSubjects(t)
	subjects["b"] = cryptoutil.DigestSet{}
	if _, err := NewStatement("https://example.com/p/v1", []byte(`{}`), subjects); err == nil {
		t.Fatal("a subject with no digest was signed")
	}
}

func TestNewStatementBuildsConformingStatements(t *testing.T) {
	for _, tc := range []struct {
		pred     string
		subjects map[string]cryptoutil.DigestSet
	}{
		{`{}`, conformanceSubjects(t)},
		{` {"a":1} `, conformanceSubjects(t)},
		{`{"a":1}`, map[string]cryptoutil.DigestSet{}},
		{`{"a":1}`, nil},
	} {
		stmt, err := NewStatement("https://example.com/p/v1", []byte(tc.pred), tc.subjects)
		if err != nil {
			t.Errorf("predicate %s, %d subjects: refused: %v", tc.pred, len(tc.subjects), err)
			continue
		}
		out, err := json.Marshal(stmt)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(out, &wire); err != nil {
			t.Fatal(err)
		}
		if string(wire["subject"]) == "null" {
			t.Errorf("subject serialized as null, not an array: %s", out)
		}
	}
}
