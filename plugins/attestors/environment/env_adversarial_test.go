//go:build audit

// Copyright 2025 The Witness Contributors
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

package environment

import (
	"strings"
	"sync"
	"testing"

	"github.com/gobwas/glob"
)

// =============================================================================
// splitVariable adversarial tests
// =============================================================================

func TestSplitVariableAdversarial(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantKey string
		wantVal string
	}{
		{"standard", "KEY=VALUE", "KEY", "VALUE"},
		{"empty value", "KEY=", "KEY", ""},
		{"empty key", "=VALUE", "", "VALUE"},
		{"both empty", "=", "", ""},
		{"no equals", "NOEQUALS", "NOEQUALS", ""},
		{"multiple equals", "KEY=VAL=UE=MORE", "KEY", "VAL=UE=MORE"},
		{"equals in value", "KEY==", "KEY", "="},
		{"only value", "=abc=def", "", "abc=def"},
		{"empty string", "", "", ""},
		{"just equals signs", "===", "", "=="},
		{"spaces in key", "MY KEY=VALUE", "MY KEY", "VALUE"},
		{"spaces in value", "KEY=MY VALUE", "KEY", "MY VALUE"},
		{"tabs", "KEY\t=\tVALUE", "KEY\t", "\tVALUE"},
		{"newline in value", "KEY=LINE1\nLINE2", "KEY", "LINE1\nLINE2"},
		{"null byte", "KEY\x00=VAL\x00", "KEY\x00", "VAL\x00"},
		{"unicode key", "\u00e9\u00e8=value", "\u00e9\u00e8", "value"},
		{"unicode value", "KEY=\u00e9\u00e8\u00ea", "KEY", "\u00e9\u00e8\u00ea"},
		{"very long key", strings.Repeat("K", 10000) + "=V", strings.Repeat("K", 10000), "V"},
		{"very long value", "K=" + strings.Repeat("V", 10000), "K", strings.Repeat("V", 10000)},
		{"binary value", "KEY=\xff\xfe\xfd", "KEY", "\xff\xfe\xfd"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, val := splitVariable(tc.input)
			if key != tc.wantKey {
				t.Errorf("splitVariable(%q) key = %q, want %q", tc.input, key, tc.wantKey)
			}
			if val != tc.wantVal {
				t.Errorf("splitVariable(%q) val = %q, want %q", tc.input, val, tc.wantVal)
			}
		})
	}
}

// =============================================================================
// FilterEnvironmentArray adversarial tests
// =============================================================================

func TestFilterEnvironmentArrayAdversarial(t *testing.T) {
	t.Run("nil variables", func(t *testing.T) {
		called := false
		FilterEnvironmentArray(nil, map[string]struct{}{"KEY": {}}, nil, func(key, val, orig string) {
			called = true
		})
		if called {
			t.Error("callback should not be called with nil variables")
		}
	})

	t.Run("empty variables", func(t *testing.T) {
		called := false
		FilterEnvironmentArray([]string{}, map[string]struct{}{"KEY": {}}, nil, func(key, val, orig string) {
			called = true
		})
		if called {
			t.Error("callback should not be called with empty variables")
		}
	})

	t.Run("nil blocklist", func(t *testing.T) {
		var collected []string
		FilterEnvironmentArray([]string{"KEY=VALUE"}, nil, nil, func(key, val, orig string) {
			collected = append(collected, key)
		})
		if len(collected) != 1 || collected[0] != "KEY" {
			t.Errorf("nil blocklist: got %v, want [KEY]", collected)
		}
	})

	t.Run("empty blocklist", func(t *testing.T) {
		var collected []string
		FilterEnvironmentArray([]string{"KEY=VALUE", "OTHER=VAL"}, map[string]struct{}{}, nil, func(key, val, orig string) {
			collected = append(collected, key)
		})
		if len(collected) != 2 {
			t.Errorf("empty blocklist: got %d items, want 2", len(collected))
		}
	})

	t.Run("exact match filtering", func(t *testing.T) {
		var collected []string
		FilterEnvironmentArray(
			[]string{"SECRET=password", "NAME=test"},
			map[string]struct{}{"SECRET": {}},
			nil,
			func(key, val, orig string) {
				collected = append(collected, key)
			},
		)
		if len(collected) != 1 || collected[0] != "NAME" {
			t.Errorf("exact match: got %v, want [NAME]", collected)
		}
	})

	t.Run("glob pattern filtering", func(t *testing.T) {
		var collected []string
		FilterEnvironmentArray(
			[]string{"AWS_SECRET_KEY=xxx", "MY_TOKEN=yyy", "SAFE_VAR=zzz"},
			map[string]struct{}{"*SECRET*": {}, "*TOKEN*": {}},
			nil,
			func(key, val, orig string) {
				collected = append(collected, key)
			},
		)
		if len(collected) != 1 || collected[0] != "SAFE_VAR" {
			t.Errorf("glob filter: got %v, want [SAFE_VAR]", collected)
		}
	})

	t.Run("exclude keys override blocklist", func(t *testing.T) {
		collected := make(map[string]bool)
		FilterEnvironmentArray(
			[]string{"MY_TOKEN=abc", "OTHER_TOKEN=def", "NAME=test"},
			map[string]struct{}{"*TOKEN*": {}},
			map[string]struct{}{"MY_TOKEN": {}},
			func(key, val, orig string) {
				collected[key] = true
			},
		)
		if !collected["MY_TOKEN"] {
			t.Error("MY_TOKEN should be excluded from filtering and pass through")
		}
		if !collected["NAME"] {
			t.Error("NAME should pass through")
		}
		if collected["OTHER_TOKEN"] {
			t.Error("OTHER_TOKEN should be filtered")
		}
	})

	t.Run("malformed env vars - no equals", func(t *testing.T) {
		var gotKey, gotVal string
		count := 0
		FilterEnvironmentArray(
			[]string{"NOEQUALS"},
			map[string]struct{}{},
			nil,
			func(key, val, orig string) {
				gotKey = key
				gotVal = val
				count++
			},
		)
		if count != 1 {
			t.Fatalf("expected 1 callback, got %d", count)
		}
		if gotKey != "NOEQUALS" {
			t.Errorf("key = %q, want 'NOEQUALS'", gotKey)
		}
		if gotVal != "" {
			t.Errorf("val = %q, want empty", gotVal)
		}
	})

	t.Run("malformed env vars - empty key", func(t *testing.T) {
		var gotKey, gotVal string
		FilterEnvironmentArray(
			[]string{"=VALUE"},
			map[string]struct{}{},
			nil,
			func(key, val, orig string) {
				gotKey = key
				gotVal = val
			},
		)
		if gotKey != "" {
			t.Errorf("key = %q, want empty", gotKey)
		}
		if gotVal != "VALUE" {
			t.Errorf("val = %q, want 'VALUE'", gotVal)
		}
	})

	t.Run("malformed env vars - multiple equals", func(t *testing.T) {
		var gotKey, gotVal string
		FilterEnvironmentArray(
			[]string{"KEY=VAL=MORE=STUFF"},
			map[string]struct{}{},
			nil,
			func(key, val, orig string) {
				gotKey = key
				gotVal = val
			},
		)
		if gotKey != "KEY" {
			t.Errorf("key = %q, want 'KEY'", gotKey)
		}
		if gotVal != "VAL=MORE=STUFF" {
			t.Errorf("val = %q, want 'VAL=MORE=STUFF'", gotVal)
		}
	})

	t.Run("invalid glob pattern without star - exact match attempt", func(t *testing.T) {
		// Pattern "[" doesn't contain * so it's tried as exact match only
		var collected []string
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panicked: %v", r)
			}
		}()
		FilterEnvironmentArray(
			[]string{"KEY=VALUE"},
			map[string]struct{}{"[": {}},
			nil,
			func(key, val, orig string) {
				collected = append(collected, key)
			},
		)
		if len(collected) != 1 || collected[0] != "KEY" {
			t.Errorf("got %v, want [KEY]", collected)
		}
	})

	t.Run("invalid glob pattern with star does not panic", func(t *testing.T) {
		var collected []string
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panicked: %v", r)
			}
		}()
		FilterEnvironmentArray(
			[]string{"KEY=VALUE"},
			map[string]struct{}{"*[": {}},
			nil,
			func(key, val, orig string) {
				collected = append(collected, key)
			},
		)
		// Invalid glob should be skipped; KEY passes through
		if len(collected) != 1 || collected[0] != "KEY" {
			t.Errorf("got %v, want [KEY]", collected)
		}
	})

	// Regression test for the upstream gobwas/glob panic bug
	t.Run("gobwas glob panic patterns", func(t *testing.T) {
		panicPatterns := []string{
			"0*,{*,",
			"*{*,",
			"*{a,b,*",
		}
		for _, pattern := range panicPatterns {
			t.Run(pattern, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panicked with pattern %q: %v", pattern, r)
					}
				}()
				FilterEnvironmentArray(
					[]string{"TEST_KEY=value"},
					map[string]struct{}{pattern: {}},
					nil,
					func(key, val, orig string) {},
				)
			})
		}
	})

	t.Run("orig parameter matches input", func(t *testing.T) {
		inputs := []string{"KEY=VALUE", "NOEQUALS", "=EMPTYKEY", "EMPTYVAL="}
		for _, input := range inputs {
			t.Run(input, func(t *testing.T) {
				FilterEnvironmentArray(
					[]string{input},
					map[string]struct{}{},
					nil,
					func(key, val, orig string) {
						if orig != input {
							t.Errorf("orig = %q, want %q", orig, input)
						}
					},
				)
			})
		}
	})
}

// =============================================================================
// ObfuscateEnvironmentArray adversarial tests
// =============================================================================

func TestObfuscateEnvironmentArrayAdversarial(t *testing.T) {
	t.Run("nil variables", func(t *testing.T) {
		called := false
		ObfuscateEnvironmentArray(nil, map[string]struct{}{"KEY": {}}, nil, func(key, val, orig string) {
			called = true
		})
		if called {
			t.Error("callback should not be called with nil variables")
		}
	})

	t.Run("empty variables", func(t *testing.T) {
		called := false
		ObfuscateEnvironmentArray([]string{}, map[string]struct{}{}, nil, func(key, val, orig string) {
			called = true
		})
		if called {
			t.Error("callback should not be called with empty variables")
		}
	})

	t.Run("nil obfuscate list passes all through", func(t *testing.T) {
		collected := make(map[string]string)
		ObfuscateEnvironmentArray(
			[]string{"SECRET=password", "NAME=test"},
			nil,
			nil,
			func(key, val, orig string) {
				collected[key] = val
			},
		)
		if collected["SECRET"] != "password" {
			t.Errorf("nil obfuscate list: SECRET = %q, want 'password'", collected["SECRET"])
		}
	})

	t.Run("exact match obfuscation", func(t *testing.T) {
		collected := make(map[string]string)
		ObfuscateEnvironmentArray(
			[]string{"SECRET=password", "NAME=test"},
			map[string]struct{}{"SECRET": {}},
			nil,
			func(key, val, orig string) {
				collected[key] = val
			},
		)
		if collected["SECRET"] != "******" {
			t.Errorf("SECRET = %q, want '******'", collected["SECRET"])
		}
		if collected["NAME"] != "test" {
			t.Errorf("NAME = %q, want 'test'", collected["NAME"])
		}
	})

	t.Run("glob match obfuscation", func(t *testing.T) {
		collected := make(map[string]string)
		ObfuscateEnvironmentArray(
			[]string{"AWS_SECRET_KEY=xxx", "MY_TOKEN=yyy", "NAME=test"},
			map[string]struct{}{"*SECRET*": {}, "*TOKEN*": {}},
			nil,
			func(key, val, orig string) {
				collected[key] = val
			},
		)
		if collected["AWS_SECRET_KEY"] != "******" {
			t.Errorf("AWS_SECRET_KEY = %q, want '******'", collected["AWS_SECRET_KEY"])
		}
		if collected["MY_TOKEN"] != "******" {
			t.Errorf("MY_TOKEN = %q, want '******'", collected["MY_TOKEN"])
		}
		if collected["NAME"] != "test" {
			t.Errorf("NAME = %q, want 'test'", collected["NAME"])
		}
	})

	t.Run("exclude keys override obfuscation", func(t *testing.T) {
		collected := make(map[string]string)
		ObfuscateEnvironmentArray(
			[]string{"MY_TOKEN=abc", "OTHER_TOKEN=def"},
			map[string]struct{}{"*TOKEN*": {}},
			map[string]struct{}{"MY_TOKEN": {}},
			func(key, val, orig string) {
				collected[key] = val
			},
		)
		if collected["MY_TOKEN"] != "abc" {
			t.Errorf("excluded MY_TOKEN = %q, want 'abc'", collected["MY_TOKEN"])
		}
		if collected["OTHER_TOKEN"] != "******" {
			t.Errorf("OTHER_TOKEN = %q, want '******'", collected["OTHER_TOKEN"])
		}
	})

	t.Run("all variables always get callback", func(t *testing.T) {
		count := 0
		vars := []string{"A=1", "B=2", "C=3", "D=4", "E=5"}
		ObfuscateEnvironmentArray(
			vars,
			map[string]struct{}{"A": {}, "C": {}, "E": {}},
			nil,
			func(key, val, orig string) {
				count++
			},
		)
		if count != 5 {
			t.Errorf("ObfuscateEnvironmentArray called callback %d times, want 5", count)
		}
	})

	t.Run("invalid glob pattern with star does not panic", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panicked: %v", r)
			}
		}()
		ObfuscateEnvironmentArray(
			[]string{"KEY=VALUE"},
			map[string]struct{}{"*[invalid": {}},
			nil,
			func(key, val, orig string) {},
		)
	})

	t.Run("gobwas glob panic patterns", func(t *testing.T) {
		panicPatterns := []string{
			"0*,{*,",
			"*{*,",
			"*{a,b,*",
		}
		for _, pattern := range panicPatterns {
			t.Run(pattern, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("panicked with pattern %q: %v", pattern, r)
					}
				}()
				ObfuscateEnvironmentArray(
					[]string{"TEST=value"},
					map[string]struct{}{pattern: {}},
					nil,
					func(key, val, orig string) {},
				)
			})
		}
	})
}

// =============================================================================
// safeGlobMatch adversarial tests
// =============================================================================

func TestSafeGlobMatchAdversarial(t *testing.T) {
	t.Run("normal match", func(t *testing.T) {
		g, err := glob.Compile("*TOKEN*")
		if err != nil {
			t.Fatalf("glob.Compile: %v", err)
		}
		matched, err := safeGlobMatch(g, "MY_TOKEN")
		if err != nil {
			t.Errorf("safeGlobMatch error: %v", err)
		}
		if !matched {
			t.Error("expected match for 'MY_TOKEN' against '*TOKEN*'")
		}
	})

	t.Run("normal non-match", func(t *testing.T) {
		g, err := glob.Compile("*TOKEN*")
		if err != nil {
			t.Fatalf("glob.Compile: %v", err)
		}
		matched, err := safeGlobMatch(g, "MY_KEY")
		if err != nil {
			t.Errorf("safeGlobMatch error: %v", err)
		}
		if matched {
			t.Error("expected no match for 'MY_KEY' against '*TOKEN*'")
		}
	})

	t.Run("empty string match with star", func(t *testing.T) {
		g, err := glob.Compile("*")
		if err != nil {
			t.Fatalf("glob.Compile: %v", err)
		}
		matched, err := safeGlobMatch(g, "")
		if err != nil {
			t.Errorf("safeGlobMatch error: %v", err)
		}
		if !matched {
			t.Error("expected '*' to match empty string")
		}
	})

	t.Run("unicode input", func(t *testing.T) {
		g, err := glob.Compile("*\u00e9*")
		if err != nil {
			t.Fatalf("glob.Compile: %v", err)
		}
		matched, err := safeGlobMatch(g, "caf\u00e9")
		if err != nil {
			t.Errorf("safeGlobMatch error: %v", err)
		}
		if !matched {
			t.Error("expected match for unicode")
		}
	})

	t.Run("very long input", func(t *testing.T) {
		g, err := glob.Compile("*")
		if err != nil {
			t.Fatalf("glob.Compile: %v", err)
		}
		matched, err := safeGlobMatch(g, strings.Repeat("A", 100000))
		if err != nil {
			t.Errorf("safeGlobMatch error: %v", err)
		}
		if !matched {
			t.Error("expected '*' to match long string")
		}
	})
}

// =============================================================================
// Capture integration tests
// =============================================================================

func TestCaptureAdversarial(t *testing.T) {
	t.Run("empty env", func(t *testing.T) {
		c := NewCapturer()
		result := c.Capture([]string{})
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if len(result) != 0 {
			t.Errorf("result should be empty, got %v", result)
		}
	})

	t.Run("nil env", func(t *testing.T) {
		c := NewCapturer()
		result := c.Capture(nil)
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if len(result) != 0 {
			t.Errorf("result should be empty, got %v", result)
		}
	})

	t.Run("obfuscation mode with sensitive var", func(t *testing.T) {
		c := NewCapturer()
		result := c.Capture([]string{"MY_TOKEN=secret123", "NAME=test"})
		if result["MY_TOKEN"] != "******" {
			t.Errorf("MY_TOKEN = %q, want '******'", result["MY_TOKEN"])
		}
		if result["NAME"] != "test" {
			t.Errorf("NAME = %q, want 'test'", result["NAME"])
		}
	})

	t.Run("filter mode with sensitive var", func(t *testing.T) {
		c := NewCapturer(WithFilterVarsEnabled())
		result := c.Capture([]string{"MY_TOKEN=secret123", "NAME=test"})
		if _, exists := result["MY_TOKEN"]; exists {
			t.Error("MY_TOKEN should be filtered out")
		}
		if result["NAME"] != "test" {
			t.Errorf("NAME = %q, want 'test'", result["NAME"])
		}
	})

	t.Run("disable default sensitive list", func(t *testing.T) {
		c := NewCapturer(WithDisableDefaultSensitiveList())
		result := c.Capture([]string{"MY_TOKEN=secret123", "NAME=test"})
		if result["MY_TOKEN"] != "secret123" {
			t.Errorf("with default list disabled: MY_TOKEN = %q, want 'secret123'", result["MY_TOKEN"])
		}
	})

	t.Run("additional keys", func(t *testing.T) {
		c := NewCapturer(
			WithDisableDefaultSensitiveList(),
			WithAdditionalKeys([]string{"CUSTOM_SENSITIVE"}),
		)
		result := c.Capture([]string{"CUSTOM_SENSITIVE=secret", "OTHER=value"})
		if result["CUSTOM_SENSITIVE"] != "******" {
			t.Errorf("CUSTOM_SENSITIVE = %q, want '******'", result["CUSTOM_SENSITIVE"])
		}
		if result["OTHER"] != "value" {
			t.Errorf("OTHER = %q, want 'value'", result["OTHER"])
		}
	})

	t.Run("exclude keys", func(t *testing.T) {
		c := NewCapturer(WithExcludeKeys([]string{"MY_TOKEN"}))
		result := c.Capture([]string{"MY_TOKEN=secret123", "OTHER_TOKEN=abc"})
		if result["MY_TOKEN"] != "secret123" {
			t.Errorf("excluded MY_TOKEN = %q, want 'secret123'", result["MY_TOKEN"])
		}
		if result["OTHER_TOKEN"] != "******" {
			t.Errorf("OTHER_TOKEN = %q, want '******'", result["OTHER_TOKEN"])
		}
	})

	t.Run("duplicate keys in env - last wins", func(t *testing.T) {
		c := NewCapturer(WithDisableDefaultSensitiveList())
		result := c.Capture([]string{"KEY=first", "KEY=second"})
		if result["KEY"] != "second" {
			t.Errorf("duplicate keys: KEY = %q, want 'second'", result["KEY"])
		}
	})

	t.Run("env with only separators", func(t *testing.T) {
		c := NewCapturer(WithDisableDefaultSensitiveList())
		result := c.Capture([]string{"=", "==", "==="})
		// All have empty key "", last value wins
		if result[""] != "==" {
			t.Errorf("separator env: [''] = %q, want '=='", result[""])
		}
	})
}

// =============================================================================
// Concurrent access tests
// =============================================================================

func TestFilterEnvironmentArrayConcurrent(t *testing.T) {
	vars := []string{
		"SECRET_TOKEN=abc",
		"API_KEY=def",
		"SAFE_VAR=ghi",
		"AWS_SECRET=jkl",
	}
	blockList := map[string]struct{}{
		"*TOKEN*":  {},
		"*KEY*":    {},
		"*SECRET*": {},
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			FilterEnvironmentArray(vars, blockList, nil, func(key, val, orig string) {
				_ = key
				_ = val
			})
		}()
	}
	wg.Wait()
}

func TestObfuscateEnvironmentArrayConcurrent(t *testing.T) {
	vars := []string{
		"SECRET_TOKEN=abc",
		"API_KEY=def",
		"SAFE_VAR=ghi",
		"AWS_SECRET=jkl",
	}
	obfuscateList := map[string]struct{}{
		"*TOKEN*":  {},
		"*KEY*":    {},
		"*SECRET*": {},
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ObfuscateEnvironmentArray(vars, obfuscateList, nil, func(key, val, orig string) {
				_ = key
				_ = val
			})
		}()
	}
	wg.Wait()
}

// =============================================================================
// Attestor integration test
// =============================================================================

func TestAttestorWithCustomEnv(t *testing.T) {
	customEnv := func() []string {
		return []string{
			"HOME=/home/test",
			"SECRET_KEY=password123",
			"PATH=/usr/bin",
			"MY_TOKEN=ghp_test123",
		}
	}

	attestor := New(WithCustomEnv(customEnv))
	if attestor.Name() != Name {
		t.Errorf("Name() = %q, want %q", attestor.Name(), Name)
	}
	if attestor.Type() != Type {
		t.Errorf("Type() = %q, want %q", attestor.Type(), Type)
	}
	if attestor.RunType() != RunType {
		t.Errorf("RunType() = %v, want %v", attestor.RunType(), RunType)
	}
	if attestor.Schema() == nil {
		t.Error("Schema() should not be nil")
	}
	if attestor.Data() != attestor {
		t.Error("Data() should return self")
	}
}

func TestNewAttestorDefaults(t *testing.T) {
	attestor := New()
	if attestor.osEnviron == nil {
		t.Error("osEnviron should default to os.Environ")
	}
}

// =============================================================================
// BUG TEST: Obfuscate both exact AND glob can double-match
// The current code first checks exact match and sets val to "******",
// then continues to check globs. This means a key that matches both
// an exact entry AND a glob entry will have its value set to "******" twice.
// This is not a functional bug (result is correct) but is wasted work.
// =============================================================================

func TestObfuscateDoubleMatch(t *testing.T) {
	matchCount := 0
	ObfuscateEnvironmentArray(
		[]string{"SECRET=password"},
		map[string]struct{}{
			"SECRET":  {}, // exact match
			"*ECRET*": {}, // also matches via glob
		},
		nil,
		func(key, val, orig string) {
			matchCount++
			if val != "******" {
				t.Errorf("val = %q, want '******'", val)
			}
		},
	)
	if matchCount != 1 {
		t.Errorf("callback count = %d, want 1 (ObfuscateEnvironmentArray always calls onAllowed once per var)", matchCount)
	}
}

// =============================================================================
// BUG TEST: ObfuscateEnvironmentArray does NOT break on glob match
// Unlike FilterEnvironmentArray which breaks after first glob match,
// ObfuscateEnvironmentArray continues checking all globs even after one matches.
// This is correct behavior (idempotent set to "******") but is a subtle
// behavioral difference between Filter and Obfuscate.
// =============================================================================

func TestFilterBreaksOnFirstGlobMatch(t *testing.T) {
	// FilterEnvironmentArray breaks after first glob match (line 71: break)
	collected := make(map[string]bool)
	FilterEnvironmentArray(
		[]string{"MY_SECRET_TOKEN=val"},
		map[string]struct{}{
			"*SECRET*": {},
			"*TOKEN*":  {},
		},
		nil,
		func(key, val, orig string) {
			collected[key] = true
		},
	)
	if collected["MY_SECRET_TOKEN"] {
		t.Error("MY_SECRET_TOKEN should be filtered by either glob")
	}
}

func TestObfuscateChecksAllGlobs(t *testing.T) {
	// ObfuscateEnvironmentArray does NOT break on glob match.
	// This verifies the behavior difference is intentional and safe.
	collected := make(map[string]string)
	ObfuscateEnvironmentArray(
		[]string{"MY_SECRET_TOKEN=val"},
		map[string]struct{}{
			"*SECRET*": {},
			"*TOKEN*":  {},
		},
		nil,
		func(key, val, orig string) {
			collected[key] = val
		},
	)
	if collected["MY_SECRET_TOKEN"] != "******" {
		t.Errorf("MY_SECRET_TOKEN = %q, want '******'", collected["MY_SECRET_TOKEN"])
	}
}
