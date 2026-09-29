// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0
// jade:ring local

package testkit

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRecordedChangesRejectVacuousExpectations(t *testing.T) {
	for name, expectation := range map[string]string{
		"missing-path":       `[{before: '', after: github.com, reason: bugfix}]`,
		"missing-reason":     `[{path: cihost, before: '', after: github.com}]`,
		"blank-reason":       `[{path: cihost, before: '', after: github.com, reason: '  '}]`,
		"missing-before":     `[{path: cihost, after: github.com, reason: bugfix}]`,
		"missing-after":      `[{path: cihost, before: '', reason: bugfix}]`,
		"object-before":      `[{path: cihost, before: {}, after: github.com, reason: bugfix}]`,
		"array-after":        `[{path: cihost, before: '', after: [], reason: bugfix}]`,
		"empty-path-segment": `[{path: host..name, before: '', after: github.com, reason: bugfix}]`,
		"array-path":         `[{path: 'host.[].name', before: '', after: github.com, reason: bugfix}]`,
		"duplicate":          `[{path: cihost, before: '', after: github.com, reason: bugfix}, {path: cihost, before: '', after: github.com, reason: bugfix}]`,
		"ancestor":           `[{path: host.name, before: '', after: github.com, reason: bugfix}, {path: host, before: '', after: github.com, reason: bugfix}]`,
		"descendant":         `[{path: host, before: '', after: github.com, reason: bugfix}, {path: host.name, before: '', after: github.com, reason: bugfix}]`,
		"redacted-leaf":      "[{path: host.name, before: '', after: github.com, reason: bugfix}]\n  redact: [host.name]",
		"redacted-parent":    "[{path: host.name, before: '', after: github.com, reason: bugfix}]\n  redact: [host]",
		"redacted-child":     "[{path: host, before: '', after: github.com, reason: bugfix}]\n  redact: [host.name]",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, "attestation.json"), []byte(`{}`))
			mustWrite(t, filepath.Join(dir, ManifestFile), []byte("schema_version: '0.1'\nattestor: example\nsetup:\n  mode: env\nrecording:\n  attestation: attestation.json\nexpect:\n  predicate_type: example\n  recorded_changes: "+expectation+"\n"))
			if _, err := LoadFixture(dir); err == nil {
				t.Fatal("invalid recorded_changes accepted")
			}
		})
	}
}

func TestRecordedChangesCompareExactHistoricalExpectation(t *testing.T) {
	const recorded = `{"host":{"name":""},"other":"unchanged","stamp":1}`
	const replay = `{"host":{"name":"github.com"},"other":"unchanged","stamp":2}`
	const change = `recorded_changes: [{path: host.name, before: '', after: github.com, reason: 'derive missing host from validated server URL'}]`
	for _, tc := range []struct {
		name, recorded, replay, expect, wantError string
	}{
		{"explicit-migration", recorded, replay, change + "\nredact: [stamp]", ""},
		{"unexpected-old-value", strings.Replace(recorded, `"name":""`, `"name":"already-set"`, 1), replay, change, "does not equal before"},
		{"wrong-after", recorded, replay, strings.Replace(change, "after: github.com", "after: wrong.example", 1), "does not equal after"},
		{"missing-recorded-leaf", `{"host":{}}`, replay, change, "does not equal before"},
		{"missing-parent", `{}`, replay, change, "not an object leaf"},
		{"redaction-overlap", recorded, replay, change + "\nredact: [host]", "overlaps redact"},
		{"unrelated-drift", recorded, strings.Replace(replay, "unchanged", "changed", 1), change + "\nredact: [stamp]", "replayed predicate !="},
		{"unchanged-fixture", recorded, recorded, "{}", ""},
		{"unchanged-fixture-rejects-drift", recorded, replay, "{}", "replayed predicate !="},
		{"unchanged-redactions", recorded, strings.Replace(recorded, `"stamp":1`, `"stamp":2`, 1), "redact: [stamp]", ""},
		{"malformed-recording", `{`, replay, change, "decode recorded"},
		{"malformed-replay", recorded, `{`, change, "decode replay"},
		{"explicit-null", `{"name":null}`, `{"name":true}`, "recorded_changes: [{path: name, before: null, after: true, reason: bugfix}]", ""},
		{"missing-is-not-null", `{}`, `{"name":true}`, "recorded_changes: [{path: name, before: null, after: true, reason: bugfix}]", "does not equal before"},
		{"exact-after-large-number", `{"name":0}`, `{"name":9007199254740993}`, "recorded_changes: [{path: name, before: 0, after: 9007199254740992, reason: bugfix}]", "does not equal after"},
		{"trailing-recorded-json", `{"name":null} {}`, `{"name":true}`, "recorded_changes: [{path: name, before: null, after: true, reason: bugfix}]", "decode recorded"},
		{"duplicate-recorded-key", `{"host":{"name":"wrong","name":""}}`, `{"host":{"name":"github.com"}}`, change, "duplicate JSON key"},
		{"escaped-equivalent-recorded-key", `{"host":{"name":"wrong","\u006eame":""}}`, `{"host":{"name":"github.com"}}`, change, "duplicate JSON key"},
		{"duplicate-replay-key", `{"host":{"name":""}}`, `{"host":{"name":"wrong","name":"github.com"}}`, change, "duplicate JSON key"},
		{"unlisted-large-number-drift", `{"host":{"name":""},"n":9007199254740992}`, `{"host":{"name":"github.com"},"n":9007199254740993}`, change, "replayed predicate !="},
		{"unlisted-nested-array-number-drift", `{"host":{"name":""},"v":[{"n":9007199254740992}]}`, `{"host":{"name":"github.com"},"v":[{"n":9007199254740993}]}`, change, "replayed predicate !="},
		{"unmigrated-large-number-drift", `{"n":9007199254740992}`, `{"n":9007199254740993}`, "{}", "replayed predicate !="},
		{"yaml-before-decimal-precision", `{"name":9007199254740992}`, `{"name":true}`, "recorded_changes: [{path: name, before: 9007199254740993.0, after: true, reason: bugfix}]", "does not equal before"},
		{"yaml-before-exponent-precision", `{"name":9007199254740992}`, `{"name":true}`, "recorded_changes: [{path: name, before: 9.007199254740993e15, after: true, reason: bugfix}]", "does not equal before"},
		{"yaml-after-decimal-precision", `{"name":null}`, `{"name":9007199254740992}`, "recorded_changes: [{path: name, before: null, after: 9007199254740993.0, reason: bugfix}]", "does not equal after"},
		{"yaml-after-exponent-precision", `{"name":null}`, `{"name":9007199254740992}`, "recorded_changes: [{path: name, before: null, after: 9.007199254740993e15, reason: bugfix}]", "does not equal after"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var expect expectSpec
			if err := yaml.Unmarshal([]byte(tc.expect), &expect); err != nil {
				t.Fatal(err)
			}
			source, actual := json.RawMessage(tc.recorded), json.RawMessage(tc.replay)
			err := compareRecordedPredicate(source, actual, expect)
			if tc.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("error = %v, want %q", err, tc.wantError)
			}
			if !bytes.Equal(source, []byte(tc.recorded)) || !bytes.Equal(actual, []byte(tc.replay)) {
				t.Fatal("comparison mutated source or replay bytes")
			}
		})
	}
}

func TestCanonicalizeRejectsDuplicateKeys(t *testing.T) {
	for _, raw := range []string{
		`{"cihost":"wrong","cihost":""}`,
		`{"nested":{"cihost":"wrong","cihost":""}}`,
		`{"nested":[{"cihost":"wrong","\u0063ihost":""}]}`,
	} {
		if _, err := canonicalize([]byte(raw), []string{"nested"}); err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
			t.Errorf("canonicalize %s: %v, want duplicate rejection even before redaction", raw, err)
		}
	}
	if _, err := canonicalize([]byte(`[{"name":1},{"name":2}]`), nil); err != nil {
		t.Fatalf("same key in distinct objects is valid: %v", err)
	}
}

func TestRecordedScalarPreservesNumericLiteral(t *testing.T) {
	for _, literal := range []string{"9007199254740993", "9007199254740993.0", "9.007199254740993e15", "0.1234567890123456789"} {
		t.Run(literal, func(t *testing.T) {
			var doc yaml.Node
			if err := yaml.Unmarshal([]byte(literal), &doc); err != nil {
				t.Fatal(err)
			}
			got, err := recordedScalar(*doc.Content[0])
			if err != nil || string(got) != literal {
				t.Fatalf("numeric scalar = %s, %v; want exact literal %s", got, err, literal)
			}
		})
	}
	for _, literal := range []string{"0x10", "1_000", ".inf", ".nan", "+1", ".5"} {
		t.Run("reject-"+literal, func(t *testing.T) {
			var doc yaml.Node
			if err := yaml.Unmarshal([]byte(literal), &doc); err != nil {
				t.Fatal(err)
			}
			if _, err := recordedScalar(*doc.Content[0]); err == nil || !strings.Contains(err.Error(), "JSON numeric syntax") {
				t.Fatalf("non-JSON numeric scalar %s: %v, want explicit syntax error", literal, err)
			}
		})
	}
}

func TestRecordedAdditionsCompareExactNewField(t *testing.T) {
	const recorded = `{"s":{"a":1}}`
	const replay = `{"s":{"a":1,"runs":[{"check":"x","pass":1}]}}`
	const add = `recorded_additions: [{path: s.runs, value: '[{"check":"x","pass":1}]', reason: 'attestor records the checks it ran'}]`
	for _, tc := range []struct {
		name, recorded, replay, expect, wantError string
	}{
		{"declared-addition", recorded, replay, add, ""},
		{"undeclared-addition", recorded, replay, "{}", "replayed predicate !="},
		{"wrong-value", recorded, strings.Replace(replay, `"pass":1`, `"pass":2`, 1), add, "does not equal the declared value"},
		{"absent-in-replay", recorded, recorded, add, "does not equal the declared value"},
		{"already-recorded", replay, replay, add, "already present in recorded"},
		{"no-parent", `{}`, replay, add, "no object parent"},
		{"other-drift", recorded, strings.Replace(replay, `"a":1`, `"a":2`, 1), add, "replayed predicate !="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var expect expectSpec
			if err := yaml.Unmarshal([]byte(tc.expect), &expect); err != nil {
				t.Fatal(err)
			}
			err := compareRecordedPredicate(json.RawMessage(tc.recorded), json.RawMessage(tc.replay), expect)
			if tc.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("error = %v, want %q", err, tc.wantError)
			}
		})
	}
	for name, bad := range map[string]string{
		"no-reason":  `[{path: s.runs, value: '[]'}]`,
		"bad-json":   `[{path: s.runs, value: '[', reason: r}]`,
		"array-path": `[{path: 's.[].x', value: '1', reason: r}]`,
		"overlap":    "[{path: s.runs, value: '[]', reason: r}]\nredact: [s]",
	} {
		t.Run("reject-"+name, func(t *testing.T) {
			var expect expectSpec
			if err := yaml.Unmarshal([]byte("recorded_additions: "+bad), &expect); err != nil {
				t.Fatal(err)
			}
			if err := validateRecordedChanges(expect); err == nil {
				t.Fatal("invalid recorded_additions accepted")
			}
		})
	}
}
