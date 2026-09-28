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

package intoto

import (
	"crypto"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// The in-toto attestation framework's Statement v1 _type, pinned as a literal
// (https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md).
const specStatementV1 = "https://in-toto.io/Statement/v1"

func TestNewStatementV1EmitsTheSpecType(t *testing.T) {
	if StatementTypeV1 != specStatementV1 {
		t.Fatalf("StatementTypeV1 = %q, want %q", StatementTypeV1, specStatementV1)
	}
	subjects := map[string]cryptoutil.DigestSet{"file:a": {{Hash: crypto.SHA256}: "abc"}}
	stmt, err := NewStatementV1("https://slsa.dev/provenance/v1", []byte(`{}`), subjects)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["_type"] != specStatementV1 {
		t.Fatalf("_type = %v, want %q", decoded["_type"], specStatementV1)
	}
}

func TestIsStatementTypeAcceptsV1AndLegacyV01(t *testing.T) {
	for typ, want := range map[string]bool{
		"https://in-toto.io/Statement/v1":   true,
		"https://in-toto.io/Statement/v0.1": true,
		"https://in-toto.io/Statement/v2":   false,
		"https://in-toto.io/Statement/v1 ":  false,
		"":                                  false,
	} {
		if got := IsStatementType(typ); got != want {
			t.Errorf("IsStatementType(%q) = %v, want %v", typ, got, want)
		}
	}
}
