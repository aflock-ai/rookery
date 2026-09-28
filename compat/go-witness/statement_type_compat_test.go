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

package witness_test

import (
	"encoding/json"
	"testing"

	compatIntoto "github.com/in-toto/go-witness/intoto"
)

// go-witness consumers decode statements of either in-toto _type: cilock
// signs v1 since #9827, and stored envelopes carry v0.1.
func TestCompatDecodesBothStatementTypes(t *testing.T) {
	if compatIntoto.StatementTypeV1 != "https://in-toto.io/Statement/v1" {
		t.Fatalf("StatementTypeV1 = %q", compatIntoto.StatementTypeV1)
	}
	for _, typ := range []string{"https://in-toto.io/Statement/v1", "https://in-toto.io/Statement/v0.1"} {
		payload := []byte(`{"_type":"` + typ + `","subject":[{"name":"a","digest":{"sha256":"abc"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{}}`)
		var stmt compatIntoto.Statement
		if err := json.Unmarshal(payload, &stmt); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if stmt.Type != typ || len(stmt.Subject) != 1 || stmt.PredicateType != "https://slsa.dev/provenance/v1" {
			t.Fatalf("%s: decoded %+v", typ, stmt)
		}
		if !compatIntoto.IsStatementType(stmt.Type) {
			t.Fatalf("IsStatementType(%q) = false", typ)
		}
	}
	stmt, err := compatIntoto.NewStatementV1("https://slsa.dev/provenance/v1", []byte(`{}`), nil)
	if err != nil || stmt.Type != compatIntoto.StatementTypeV1 {
		t.Fatalf("NewStatementV1: %+v, %v", stmt, err)
	}
}
