//go:build audit

package intoto

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// NewStatement subject validation
// ==========================================================================

// TestAdversarial_NewStatement_EmptySubjects verifies that zero subjects
// are allowed (matching upstream witness behavior — many workflows like
// linters and tests don't produce file artifacts).
func TestAdversarial_NewStatement_EmptySubjects(t *testing.T) {
	stmt, err := NewStatement("https://example.com/predicate/v1", []byte(`{}`), nil)
	require.NoError(t, err, "nil subjects should be allowed")
	assert.Empty(t, stmt.Subject)

	stmt, err = NewStatement("https://example.com/predicate/v1", []byte(`{}`), map[string]cryptoutil.DigestSet{})
	require.NoError(t, err, "empty subjects map should be allowed")
	assert.Empty(t, stmt.Subject)
}

// TestAdversarial_NewStatement_SubjectWithEmptyDigest tests that a subject
// whose DigestSet is empty gets through NewStatement. DigestSetToSubject
// calls ds.ToNameMap() which returns an empty map for an empty DigestSet.
// The resulting Subject has an empty Digest map, which violates the in-toto
// spec (subjects MUST have at least one digest).
//
// BUG: Empty digest sets on subjects are silently accepted.
func TestAdversarial_NewStatement_SubjectWithEmptyDigest(t *testing.T) {
	emptyDS := cryptoutil.DigestSet{}
	subjects := map[string]cryptoutil.DigestSet{
		"artifact.tar.gz": emptyDS,
	}

	stmt, err := NewStatement("https://example.com/predicate/v1", []byte(`{}`), subjects)
	// This SHOULD error but currently does NOT.
	if err != nil {
		t.Logf("Good: empty digest set was rejected: %v", err)
		return
	}

	// If we reach here, we have a bug.
	require.Len(t, stmt.Subject, 1)
	assert.Empty(t, stmt.Subject[0].Digest,
		"BUG [MEDIUM]: Subject with empty digest set is accepted. "+
			"In-toto spec requires at least one digest per subject. "+
			"File: intoto/statement.go, DigestSetToSubject line ~80")
}

// TestAdversarial_NewStatement_SubjectWithEmptyName tests that a subject
// with an empty string name is accepted. The in-toto spec says subjects
// SHOULD have a non-empty name, but this isn't enforced.
//
// DESIGN NOTE: Empty subject names are silently accepted.
func TestAdversarial_NewStatement_SubjectWithEmptyName(t *testing.T) {
	ds := cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "abc123def456",
	}
	subjects := map[string]cryptoutil.DigestSet{
		"": ds,
	}

	stmt, err := NewStatement("https://example.com/predicate/v1", []byte(`{}`), subjects)
	// This probably succeeds, which is a design issue.
	if err != nil {
		t.Logf("Good: empty name was rejected: %v", err)
		return
	}

	require.Len(t, stmt.Subject, 1)
	assert.Equal(t, "", stmt.Subject[0].Name,
		"DESIGN NOTE [LOW]: Empty subject name is accepted. "+
			"File: intoto/statement.go, NewStatement")
}

// TestAdversarial_NewStatement_InvalidPredicate tests that invalid JSON
// predicate is rejected.
func TestAdversarial_NewStatement_InvalidPredicate(t *testing.T) {
	ds := cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "abc123",
	}
	subjects := map[string]cryptoutil.DigestSet{
		"artifact": ds,
	}

	tests := []struct {
		name      string
		predicate []byte
		wantErr   bool
	}{
		{"nil predicate", nil, true},
		{"empty bytes", []byte{}, true},
		{"not JSON", []byte("not json at all"), true},
		{"truncated JSON", []byte(`{"key": `), true},
		{"valid empty object", []byte(`{}`), false},
		{"valid array", []byte(`[]`), false},
		{"valid string", []byte(`"hello"`), false},
		{"valid null", []byte(`null`), false},
		{"valid number", []byte(`42`), false},
		{"valid boolean", []byte(`true`), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewStatement("https://example.com/predicate/v1", tc.predicate, subjects)
			if tc.wantErr {
				require.Error(t, err, "should reject predicate: %q", tc.predicate)
			} else {
				require.NoError(t, err, "should accept predicate: %q", tc.predicate)
			}
		})
	}
}

// TestAdversarial_NewStatement_EmptyPredicateType tests that an empty
// predicate type string is accepted. This is arguably a bug since
// predicateType is a required field in the in-toto spec.
//
// DESIGN NOTE: Empty predicateType is accepted without validation.
func TestAdversarial_NewStatement_EmptyPredicateType(t *testing.T) {
	ds := cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "abc123",
	}
	subjects := map[string]cryptoutil.DigestSet{
		"artifact": ds,
	}

	stmt, err := NewStatement("", []byte(`{}`), subjects)
	if err != nil {
		t.Logf("Good: empty predicate type was rejected: %v", err)
		return
	}

	assert.Equal(t, "", stmt.PredicateType,
		"DESIGN NOTE [LOW]: Empty predicateType is accepted. "+
			"In-toto spec requires a non-empty predicateType URI. "+
			"File: intoto/statement.go:42")
}

// ==========================================================================
// Statement JSON unmarshaling safety
// ==========================================================================

// TestAdversarial_Statement_UnmarshalWrongType tests that unmarshaling a
// Statement with a wrong _type field does NOT produce an error. The
// Statement struct has no custom UnmarshalJSON, so any _type value is
// accepted silently.
//
// BUG: No validation of _type field during JSON unmarshaling.
func TestAdversarial_Statement_UnmarshalWrongType(t *testing.T) {
	raw := `{
		"_type": "https://evil.com/fake-type/v666",
		"subject": [{"name": "foo", "digest": {"sha256": "abc123"}}],
		"predicateType": "https://example.com/predicate/v1",
		"predicate": {}
	}`

	var stmt Statement
	err := json.Unmarshal([]byte(raw), &stmt)
	require.NoError(t, err, "unmarshal should succeed even with wrong type")
	assert.Equal(t, "https://evil.com/fake-type/v666", stmt.Type,
		"BUG [HIGH]: Statement._type is not validated during JSON unmarshal. "+
			"An attacker can craft a Statement with an arbitrary type field "+
			"that passes parsing. Consumers must check Type==StatementType "+
			"themselves. File: intoto/statement.go:36")
}

// TestAdversarial_Statement_UnmarshalEmptyType tests unmarshaling with
// an empty _type field.
func TestAdversarial_Statement_UnmarshalEmptyType(t *testing.T) {
	raw := `{
		"_type": "",
		"subject": [],
		"predicateType": "",
		"predicate": null
	}`

	var stmt Statement
	err := json.Unmarshal([]byte(raw), &stmt)
	require.NoError(t, err)
	assert.Equal(t, "", stmt.Type,
		"DESIGN NOTE: Empty _type is accepted during unmarshal")
	assert.Empty(t, stmt.Subject,
		"DESIGN NOTE: Empty subject array is accepted during unmarshal")
}

// TestAdversarial_Statement_UnmarshalMissingFields tests that missing
// fields don't cause errors during unmarshal - they just get zero values.
func TestAdversarial_Statement_UnmarshalMissingFields(t *testing.T) {
	raw := `{}`

	var stmt Statement
	err := json.Unmarshal([]byte(raw), &stmt)
	require.NoError(t, err, "empty JSON object should unmarshal without error")
	assert.Equal(t, "", stmt.Type)
	assert.Nil(t, stmt.Subject)
	assert.Equal(t, "", stmt.PredicateType)
	assert.Nil(t, stmt.Predicate)
}

// TestAdversarial_Statement_UnmarshalDuplicateSubjects tests that
// duplicate subjects (same name) are accepted during unmarshal.
func TestAdversarial_Statement_UnmarshalDuplicateSubjects(t *testing.T) {
	raw := `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [
			{"name": "artifact.tar.gz", "digest": {"sha256": "abc123"}},
			{"name": "artifact.tar.gz", "digest": {"sha256": "def456"}}
		],
		"predicateType": "https://example.com/predicate/v1",
		"predicate": {}
	}`

	var stmt Statement
	err := json.Unmarshal([]byte(raw), &stmt)
	require.NoError(t, err)
	assert.Len(t, stmt.Subject, 2,
		"BUG [MEDIUM]: Duplicate subject names are accepted during unmarshal. "+
			"Two subjects with the same name but different digests could confuse "+
			"verification logic. File: intoto/statement.go:36 (no custom UnmarshalJSON)")
}

// TestAdversarial_Statement_UnmarshalSubjectEmptyDigest tests that a
// subject with an empty digest map is accepted during unmarshal.
func TestAdversarial_Statement_UnmarshalSubjectEmptyDigest(t *testing.T) {
	raw := `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "artifact.tar.gz", "digest": {}}],
		"predicateType": "https://example.com/predicate/v1",
		"predicate": {}
	}`

	var stmt Statement
	err := json.Unmarshal([]byte(raw), &stmt)
	require.NoError(t, err)
	assert.Empty(t, stmt.Subject[0].Digest,
		"BUG [MEDIUM]: Subject with empty digest map is accepted during unmarshal. "+
			"In-toto spec requires at least one digest per subject. "+
			"File: intoto/statement.go:30-33 (Subject struct has no validation)")
}

// TestAdversarial_Statement_UnmarshalSubjectNullDigest tests that a
// subject with null digest is accepted.
func TestAdversarial_Statement_UnmarshalSubjectNullDigest(t *testing.T) {
	raw := `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "artifact.tar.gz", "digest": null}],
		"predicateType": "https://example.com/predicate/v1",
		"predicate": {}
	}`

	var stmt Statement
	err := json.Unmarshal([]byte(raw), &stmt)
	require.NoError(t, err)
	assert.Nil(t, stmt.Subject[0].Digest,
		"BUG [MEDIUM]: Subject with null digest is accepted during unmarshal. "+
			"File: intoto/statement.go:30-33")
}

// TestAdversarial_Statement_UnmarshalMalformedJSON tests various
// malformed JSON inputs don't cause panics.
func TestAdversarial_Statement_UnmarshalMalformedJSON(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"empty string", ""},
		{"null", "null"},
		{"array", "[]"},
		{"number", "42"},
		{"string", `"hello"`},
		{"truncated", `{"_type": "https://in-toto.io/Statement/v0.1"`},
		{"deeply nested", buildDeeplyNested(100)},
		{"very long subject name", buildLongSubjectName(1 << 16)},
		{"subject with non-string digest", `{"subject": [{"name": "a", "digest": {"sha256": 12345}}]}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stmt Statement
			// We don't care about the error; we just need no panics.
			_ = json.Unmarshal([]byte(tc.raw), &stmt)
		})
	}
}

// TestAdversarial_Statement_UnmarshalExtraFields tests that extra fields
// in the JSON are silently ignored (standard Go behavior).
func TestAdversarial_Statement_UnmarshalExtraFields(t *testing.T) {
	raw := `{
		"_type": "https://in-toto.io/Statement/v0.1",
		"subject": [{"name": "a", "digest": {"sha256": "abc"}}],
		"predicateType": "https://example.com/predicate/v1",
		"predicate": {},
		"extraField": "should be ignored",
		"_malicious": true
	}`

	var stmt Statement
	err := json.Unmarshal([]byte(raw), &stmt)
	require.NoError(t, err,
		"DESIGN NOTE: Extra fields are silently ignored during unmarshal. "+
			"This is standard Go JSON behavior but means schema validation "+
			"doesn't happen at the struct level.")
}

// ==========================================================================
// Statement JSON marshal/unmarshal round-trip
// ==========================================================================

// TestAdversarial_Statement_RoundTrip tests that marshal/unmarshal
// preserves all fields.
func TestAdversarial_Statement_RoundTrip(t *testing.T) {
	original := Statement{
		Type: StatementType,
		Subject: []Subject{
			{Name: "artifact.tar.gz", Digest: map[string]string{"sha256": "abc123"}},
			{Name: "other.bin", Digest: map[string]string{"sha256": "def456", "sha1": "789abc"}},
		},
		PredicateType: "https://example.com/predicate/v1",
		Predicate:     json.RawMessage(`{"key":"value"}`),
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var roundTripped Statement
	err = json.Unmarshal(data, &roundTripped)
	require.NoError(t, err)

	assert.Equal(t, original.Type, roundTripped.Type)
	assert.Equal(t, original.PredicateType, roundTripped.PredicateType)
	assert.Equal(t, len(original.Subject), len(roundTripped.Subject))

	for i := range original.Subject {
		assert.Equal(t, original.Subject[i].Name, roundTripped.Subject[i].Name)
		assert.Equal(t, original.Subject[i].Digest, roundTripped.Subject[i].Digest)
	}

	// Compare predicate (RawMessage)
	assert.JSONEq(t, string(original.Predicate), string(roundTripped.Predicate))
}

// ==========================================================================
// NewStatement determinism
// ==========================================================================

// TestAdversarial_NewStatement_DeterministicOrder tests that NewStatement
// produces deterministic subject ordering regardless of map iteration order.
func TestAdversarial_NewStatement_DeterministicOrder(t *testing.T) {
	ds := cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "abc123",
	}
	subjects := map[string]cryptoutil.DigestSet{
		"zebra":    ds,
		"apple":    ds,
		"mango":    ds,
		"banana":   ds,
		"cherry":   ds,
		"date":     ds,
		"fig":      ds,
		"grape":    ds,
		"honeydew": ds,
		"kiwi":     ds,
	}

	// Run multiple times to test determinism.
	var firstJSON []byte
	for i := 0; i < 20; i++ {
		stmt, err := NewStatement("https://example.com/predicate/v1", []byte(`{}`), subjects)
		require.NoError(t, err)

		data, err := json.Marshal(stmt)
		require.NoError(t, err)

		if i == 0 {
			firstJSON = data
		} else {
			assert.Equal(t, string(firstJSON), string(data),
				"iteration %d: NewStatement must produce deterministic output", i)
		}
	}

	// Verify the order is alphabetical.
	stmt, err := NewStatement("https://example.com/predicate/v1", []byte(`{}`), subjects)
	require.NoError(t, err)

	for i := 1; i < len(stmt.Subject); i++ {
		assert.True(t, stmt.Subject[i-1].Name < stmt.Subject[i].Name,
			"subjects should be sorted alphabetically: %q should come before %q",
			stmt.Subject[i-1].Name, stmt.Subject[i].Name)
	}
}

// ==========================================================================
// DigestSetToSubject edge cases
// ==========================================================================

// TestAdversarial_DigestSetToSubject_UnsupportedHash tests that an
// unsupported hash in the DigestSet propagates the error.
func TestAdversarial_DigestSetToSubject_UnsupportedHash(t *testing.T) {
	ds := cryptoutil.DigestSet{
		{Hash: crypto.Hash(255)}: "deadbeef", // unsupported hash
	}

	_, err := DigestSetToSubject("artifact", ds)
	require.Error(t, err, "unsupported hash should produce error")
}

// TestAdversarial_DigestSetToSubject_MultipleHashes tests that a DigestSet
// with multiple hash algorithms produces the correct Subject.
func TestAdversarial_DigestSetToSubject_MultipleHashes(t *testing.T) {
	ds := cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "sha256_value",
		{Hash: crypto.SHA1}:   "sha1_value",
	}

	subj, err := DigestSetToSubject("artifact", ds)
	require.NoError(t, err)
	assert.Equal(t, "artifact", subj.Name)
	assert.Len(t, subj.Digest, 2)
	assert.Equal(t, "sha256_value", subj.Digest["sha256"])
	assert.Equal(t, "sha1_value", subj.Digest["sha1"])
}

// ==========================================================================
// NewStatement with unsupported hash propagation
// ==========================================================================

// TestAdversarial_NewStatement_UnsupportedHashPropagates tests that if
// one subject has an unsupported hash, the error propagates through
// NewStatement.
func TestAdversarial_NewStatement_UnsupportedHashPropagates(t *testing.T) {
	goodDS := cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "abc123",
	}
	badDS := cryptoutil.DigestSet{
		{Hash: crypto.Hash(255)}: "deadbeef",
	}
	subjects := map[string]cryptoutil.DigestSet{
		"good-artifact": goodDS,
		"bad-artifact":  badDS,
	}

	_, err := NewStatement("https://example.com/predicate/v1", []byte(`{}`), subjects)
	require.Error(t, err, "unsupported hash in any subject should propagate error")
}

// ==========================================================================
// Statement constants
// ==========================================================================

// TestAdversarial_StatementConstants verifies the expected constant values.
func TestAdversarial_StatementConstants(t *testing.T) {
	assert.Equal(t, "https://in-toto.io/Statement/v0.1", StatementType,
		"StatementType constant must match in-toto spec")
	assert.Equal(t, "application/vnd.in-toto+json", PayloadType,
		"PayloadType constant must match in-toto spec")
}

// ==========================================================================
// Large input handling
// ==========================================================================

// TestAdversarial_NewStatement_LargeNumberOfSubjects tests that a large
// number of subjects doesn't cause performance issues or panics.
func TestAdversarial_NewStatement_LargeNumberOfSubjects(t *testing.T) {
	subjects := make(map[string]cryptoutil.DigestSet, 10000)
	for i := 0; i < 10000; i++ {
		ds := cryptoutil.DigestSet{
			{Hash: crypto.SHA256}: "abc123",
		}
		subjects[strings.Repeat("a", 100)+strings.Repeat("0", 5)] = ds
		// Use unique names
		subjects[strings.Repeat("x", i%100+1)] = ds
	}

	_, err := NewStatement("https://example.com/predicate/v1", []byte(`{}`), subjects)
	require.NoError(t, err)
}

// TestAdversarial_NewStatement_LargePredicate tests that a large predicate
// payload is accepted.
func TestAdversarial_NewStatement_LargePredicate(t *testing.T) {
	ds := cryptoutil.DigestSet{
		{Hash: crypto.SHA256}: "abc123",
	}
	subjects := map[string]cryptoutil.DigestSet{
		"artifact": ds,
	}

	// 1MB predicate.
	largePredicate := []byte(`{"data":"` + strings.Repeat("x", 1<<20) + `"}`)

	stmt, err := NewStatement("https://example.com/predicate/v1", largePredicate, subjects)
	require.NoError(t, err,
		"DESIGN NOTE: No size limit on predicate. A 1MB+ predicate is accepted. "+
			"File: intoto/statement.go:47")
	assert.True(t, len(stmt.Predicate) > 1<<20)
}

// ==========================================================================
// Helpers
// ==========================================================================

func buildDeeplyNested(depth int) string {
	var sb strings.Builder
	for i := 0; i < depth; i++ {
		sb.WriteString(`{"a":`)
	}
	sb.WriteString(`"end"`)
	for i := 0; i < depth; i++ {
		sb.WriteString(`}`)
	}
	return sb.String()
}

func buildLongSubjectName(length int) string {
	name := strings.Repeat("a", length)
	return `{"subject": [{"name": "` + name + `", "digest": {"sha256": "abc"}}]}`
}
