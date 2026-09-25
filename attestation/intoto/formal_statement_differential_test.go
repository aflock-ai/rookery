// jade:ring local

package intoto

// formal:differential dsse-intoto TestFormalStatementDifferential
//
// Binds the Lean model of statement construction (formal/dsse-intoto,
// DsseIntoto/Statement.lean) to NewStatement. Each case of the model's
// "statement" vectors is replayed here: the predicate type, a predicate of
// the given JSON kind (or bytes that are not JSON), and a subject set. The
// code must refuse exactly when the model refuses and, when it builds a
// statement, emit the model's _type, subjects (in order, with their digest
// maps), predicateType and predicate kind.
//
// newStatementModel names which model the shipped code must match:
// "asbuilt" while NewStatement signs what the v1 body forbids, "required"
// once the fix lands.
//
// The test skips when the vectors are not on disk and FAILS instead when
// JADE_FORMAL_DIFFERENTIAL=1.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// The v1 body fix landed in #10058 (empty predicate type, non-object
// predicate, subject without a digest).
const newStatementModel = "required"

type formalStmtOut struct {
	Error         string           `json:"error"`
	Type          string           `json:"type"`
	Subject       []formalStmtSubj `json:"subject"`
	PredicateType string           `json:"predicateType"`
	Predicate     string           `json:"predicate"`
}

type formalStmtSubj struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type formalStmtCase struct {
	PredicateType string           `json:"predicateType"`
	Predicate     string           `json:"predicate"`
	Subjects      []formalStmtSubj `json:"subjects"`
	AsBuilt       formalStmtOut    `json:"asbuilt"`
	Required      formalStmtOut    `json:"required"`
}

func formalPredicateBytes(kind string) []byte {
	switch kind {
	case "object":
		return []byte(`{"a":1}`)
	case "array":
		return []byte(`[1]`)
	case "string":
		return []byte(`"s"`)
	case "number":
		return []byte(`1`)
	case "bool":
		return []byte(`true`)
	case "null":
		return []byte(`null`)
	default:
		return []byte(`{`)
	}
}

func formalKind(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	switch {
	case s == "":
		return "unset"
	case s[0] == '{':
		return "object"
	case s[0] == '[':
		return "array"
	case s[0] == '"':
		return "string"
	case s == "true" || s == "false":
		return "bool"
	case s == "null":
		return "null"
	default:
		return "number"
	}
}

func TestFormalStatementDifferential(t *testing.T) {
	path := filepath.Join("..", "..", "formal", "dsse-intoto", "vectors", "dsse-intoto.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") != "" {
			t.Fatalf("JADE_FORMAL_DIFFERENTIAL is set but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal vectors not on disk (%v); the differential needs the repository checkout", err)
	}
	var v struct {
		Statement []formalStmtCase `json:"statement"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(v.Statement) == 0 {
		t.Fatal("vectors have no statement section")
	}
	bad := 0
	for i, c := range v.Statement {
		want := c.AsBuilt
		if newStatementModel == "required" {
			want = c.Required
		}
		subjects := map[string]cryptoutil.DigestSet{}
		for _, s := range c.Subjects {
			ds, err := cryptoutil.NewDigestSet(s.Digest)
			if err != nil {
				t.Fatalf("case %d: digest set %v: %v", i, s.Digest, err)
			}
			subjects[s.Name] = ds
		}
		stmt, err := NewStatement(c.PredicateType, formalPredicateBytes(c.Predicate), subjects)
		var got formalStmtOut
		if err != nil {
			got.Error = "refused"
		} else {
			got = formalStmtWire(t, i, &stmt)
		}
		if want.Error != "" {
			want = formalStmtOut{Error: "refused"}
		} else if want.Subject == nil {
			want.Subject = []formalStmtSubj{}
		}
		if !reflect.DeepEqual(got, want) {
			bad++
			if bad <= 20 {
				t.Errorf("statement case %d: code %+v, %s model %+v (input %+v)", i, got, newStatementModel, want, c)
			}
		}
	}
	if bad > 0 {
		t.Fatalf("statement: %d of %d cases disagree with the %s model", bad, len(v.Statement), newStatementModel)
	}
	t.Logf("statement: %d cases agree with the %s model", len(v.Statement), newStatementModel)
}

// formalStmtWire marshals stmt and reads back the fields the formal model
// predicts, as they appear on the wire.
func formalStmtWire(t *testing.T, i int, stmt *Statement) formalStmtOut {
	t.Helper()
	out, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("case %d: marshal: %v", i, err)
	}
	var wire struct {
		Type          string           `json:"_type"`
		Subject       []formalStmtSubj `json:"subject"`
		PredicateType string           `json:"predicateType"`
		Predicate     json.RawMessage  `json:"predicate"`
	}
	if err := json.Unmarshal(out, &wire); err != nil {
		t.Fatalf("case %d: re-read %s: %v", i, out, err)
	}
	got := formalStmtOut{Type: wire.Type, Subject: wire.Subject, PredicateType: wire.PredicateType, Predicate: formalKind(wire.Predicate)}
	if got.Subject == nil {
		got.Subject = []formalStmtSubj{}
	}
	return got
}
