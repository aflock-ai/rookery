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
	"time"
)

// =============================================================================
// Filter: glob pattern that matches everything (*)
// =============================================================================

func TestAdversarialFilterGlobMatchesAll(t *testing.T) {
	// A "*" glob pattern should match every single key, filtering out everything.
	// This is a potential footgun: a user passing "*" as a sensitive pattern
	// would suppress the entire environment.
	vars := []string{
		"HOME=/home/test",
		"PATH=/usr/bin",
		"SAFE_VAR=hello",
		"TOTALLY_NORMAL=world",
	}
	blockList := map[string]struct{}{
		"*": {},
	}

	var collected []string
	FilterEnvironmentArray(vars, blockList, nil, func(key, val, orig string) {
		collected = append(collected, key)
	})

	if len(collected) != 0 {
		t.Errorf("glob '*' should filter out ALL vars, but %d passed through: %v", len(collected), collected)
	}
}

func TestAdversarialObfuscateGlobMatchesAll(t *testing.T) {
	// A "*" glob pattern should obfuscate every single variable.
	vars := []string{
		"HOME=/home/test",
		"PATH=/usr/bin",
		"SAFE_VAR=hello",
	}
	obfuscateList := map[string]struct{}{
		"*": {},
	}

	collected := make(map[string]string)
	ObfuscateEnvironmentArray(vars, obfuscateList, nil, func(key, val, orig string) {
		collected[key] = val
	})

	for _, v := range vars {
		key, _ := splitVariable(v)
		if collected[key] != "******" {
			t.Errorf("glob '*' should obfuscate all vars, but %q = %q", key, collected[key])
		}
	}
}

// =============================================================================
// Filter: glob pattern with ReDoS / exponential blowup potential
// =============================================================================

func TestAdversarialFilterGlobComplexPatterns(t *testing.T) {
	// gobwas/glob uses a different algorithm than regex, so true ReDoS is
	// unlikely, but deeply nested alternations could still be slow.
	// We verify these complete in bounded time.
	patterns := []string{
		"*{a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z}*",
		"*{" + strings.Repeat("a,", 100) + "z}*",
		strings.Repeat("*", 50),
	}

	longKey := strings.Repeat("x", 10000)
	vars := []string{longKey + "=value"}

	for _, pattern := range patterns {
		t.Run(pattern[:min(len(pattern), 40)], func(t *testing.T) {
			start := time.Now()
			FilterEnvironmentArray(vars, map[string]struct{}{pattern: {}}, nil, func(key, val, orig string) {})
			elapsed := time.Since(start)
			if elapsed > 5*time.Second {
				t.Errorf("pattern %q took %v (potential DoS)", pattern[:min(len(pattern), 40)], elapsed)
			}
		})
	}
}

// =============================================================================
// Filter: Very long environment variable names (10KB+)
// =============================================================================

func TestAdversarialFilterVeryLongVarName(t *testing.T) {
	longKey := strings.Repeat("A", 10*1024) // 10KB key
	vars := []string{longKey + "=value"}

	var gotKey string
	FilterEnvironmentArray(vars, map[string]struct{}{}, nil, func(key, val, orig string) {
		gotKey = key
	})
	if len(gotKey) != 10*1024 {
		t.Errorf("expected key length %d, got %d", 10*1024, len(gotKey))
	}

	// Also test that glob matching works on very long keys
	blockList := map[string]struct{}{"*AAAA*": {}}
	var collected []string
	FilterEnvironmentArray(vars, blockList, nil, func(key, val, orig string) {
		collected = append(collected, key)
	})
	if len(collected) != 0 {
		t.Error("10KB key containing 'AAAA' should be filtered by *AAAA* glob")
	}
}

// =============================================================================
// Filter: Very long environment variable values (1MB+)
// =============================================================================

func TestAdversarialFilterVeryLongVarValue(t *testing.T) {
	longVal := strings.Repeat("X", 1024*1024) // 1MB value
	vars := []string{"LARGE_VAR=" + longVal}

	var gotVal string
	FilterEnvironmentArray(vars, map[string]struct{}{}, nil, func(key, val, orig string) {
		gotVal = val
	})
	if len(gotVal) != 1024*1024 {
		t.Errorf("expected value length %d, got %d", 1024*1024, len(gotVal))
	}
}

func TestAdversarialObfuscateVeryLongVarValue(t *testing.T) {
	// Obfuscating a 1MB value should still replace it with "******"
	longVal := strings.Repeat("X", 1024*1024)
	vars := []string{"SECRET_VAR=" + longVal}

	var gotVal string
	ObfuscateEnvironmentArray(vars, map[string]struct{}{"*SECRET*": {}}, nil, func(key, val, orig string) {
		gotVal = val
	})
	if gotVal != "******" {
		t.Errorf("expected '******', got string of length %d", len(gotVal))
	}
}

// =============================================================================
// Filter/Obfuscate: Env vars with null bytes, newlines, control characters
// =============================================================================

func TestAdversarialFilterControlCharacters(t *testing.T) {
	vars := []string{
		"KEY_NULL\x00BYTE=val\x00ue",
		"KEY_NEWLINE\n=val\nue",
		"KEY_TAB\t=val\tue",
		"KEY_CR\r=val\rue",
		"KEY_BELL\x07=val\x07ue",
		"KEY_ESC\x1b[31m=colored",
		"KEY_BACKSPACE\x08=deleted",
		"KEY_FORMFEED\x0c=paged",
	}

	collected := make(map[string]string)
	FilterEnvironmentArray(vars, map[string]struct{}{}, nil, func(key, val, orig string) {
		collected[key] = val
	})

	if len(collected) != len(vars) {
		t.Errorf("expected %d vars, got %d", len(vars), len(collected))
	}

	// Verify null-byte key is preserved exactly
	if _, ok := collected["KEY_NULL\x00BYTE"]; !ok {
		t.Error("null-byte key should be preserved in map")
	}

	// Test that glob patterns work with control chars in keys
	varsWithSecret := []string{"SECRET\x00KEY=password"}
	var passed []string
	FilterEnvironmentArray(varsWithSecret, map[string]struct{}{"*SECRET*": {}}, nil, func(key, val, orig string) {
		passed = append(passed, key)
	})
	if len(passed) != 0 {
		t.Errorf("*SECRET* glob should match key with null byte containing SECRET, but %v passed", passed)
	}
}

func TestAdversarialObfuscateControlCharacters(t *testing.T) {
	vars := []string{
		"TOKEN\x00VAR=secret",
		"NORMAL=visible",
	}

	collected := make(map[string]string)
	ObfuscateEnvironmentArray(vars, map[string]struct{}{"*TOKEN*": {}}, nil, func(key, val, orig string) {
		collected[key] = val
	})

	if collected["TOKEN\x00VAR"] != "******" {
		t.Errorf("null-byte key matching *TOKEN* should be obfuscated, got %q", collected["TOKEN\x00VAR"])
	}
	if collected["NORMAL"] != "visible" {
		t.Errorf("NORMAL should not be obfuscated, got %q", collected["NORMAL"])
	}
}

// =============================================================================
// Filter: Empty environment (zero vars)
// =============================================================================

func TestAdversarialFilterEmptyEnvironmentWithGlobs(t *testing.T) {
	// Ensure that compiled globs don't cause issues when there are no vars
	called := false
	FilterEnvironmentArray(
		[]string{},
		map[string]struct{}{"*TOKEN*": {}, "*SECRET*": {}, "*PASSWORD*": {}},
		nil,
		func(key, val, orig string) { called = true },
	)
	if called {
		t.Error("callback should never be called with empty variables")
	}
}

// =============================================================================
// Filter: Concurrent filter calls (race detector)
// =============================================================================

func TestAdversarialFilterConcurrentWithSharedData(t *testing.T) {
	// The blockList and excludeKeys maps are read-only during filtering.
	// Ensure no races when shared across goroutines.
	blockList := map[string]struct{}{
		"*TOKEN*":  {},
		"*SECRET*": {},
		"*KEY*":    {},
	}
	excludeKeys := map[string]struct{}{
		"SAFE_TOKEN": {},
	}

	vars := make([]string, 100)
	for i := range vars {
		if i%3 == 0 {
			vars[i] = "SECRET_" + string(rune('A'+i%26)) + "=val"
		} else if i%3 == 1 {
			vars[i] = "SAFE_TOKEN=included"
		} else {
			vars[i] = "NORMAL_" + string(rune('A'+i%26)) + "=val"
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			count := 0
			FilterEnvironmentArray(vars, blockList, excludeKeys, func(key, val, orig string) {
				count++
			})
			// At minimum, SAFE_TOKEN entries and NORMAL entries should pass through
			if count == 0 {
				t.Error("expected some vars to pass through")
			}
		}()
	}
	wg.Wait()
}

// =============================================================================
// Obfuscate: Pattern that matches nothing
// =============================================================================

func TestAdversarialObfuscatePatternMatchesNothing(t *testing.T) {
	vars := []string{
		"HOME=/home/test",
		"PATH=/usr/bin",
		"USER=testuser",
	}
	// Pattern with no wildcard that doesn't match any key
	obfuscateList := map[string]struct{}{
		"NONEXISTENT_VAR": {},
	}

	collected := make(map[string]string)
	ObfuscateEnvironmentArray(vars, obfuscateList, nil, func(key, val, orig string) {
		collected[key] = val
	})

	for _, v := range vars {
		key, originalVal := splitVariable(v)
		if collected[key] != originalVal {
			t.Errorf("non-matching obfuscation should not alter %q: got %q, want %q",
				key, collected[key], originalVal)
		}
	}
}

func TestAdversarialObfuscateGlobMatchesNothing(t *testing.T) {
	vars := []string{"HOME=/home/test", "PATH=/usr/bin"}
	// Glob that contains * but matches nothing in practice
	obfuscateList := map[string]struct{}{
		"*ZZZNONEXISTENT*": {},
	}

	collected := make(map[string]string)
	ObfuscateEnvironmentArray(vars, obfuscateList, nil, func(key, val, orig string) {
		collected[key] = val
	})

	if collected["HOME"] != "/home/test" {
		t.Errorf("HOME should not be obfuscated: %q", collected["HOME"])
	}
}

// =============================================================================
// Obfuscate: Value that's already obfuscated
// =============================================================================

func TestAdversarialObfuscateAlreadyObfuscatedValue(t *testing.T) {
	// If a value is already "******", obfuscation should still work correctly
	vars := []string{"TOKEN_VAR=******"}

	collected := make(map[string]string)
	ObfuscateEnvironmentArray(vars, map[string]struct{}{"*TOKEN*": {}}, nil, func(key, val, orig string) {
		collected[key] = val
	})
	if collected["TOKEN_VAR"] != "******" {
		t.Errorf("already-obfuscated value should remain '******', got %q", collected["TOKEN_VAR"])
	}

	// The original should still contain the actual value
	ObfuscateEnvironmentArray(vars, map[string]struct{}{"*TOKEN*": {}}, nil, func(key, val, orig string) {
		if orig != "TOKEN_VAR=******" {
			t.Errorf("orig should be the raw env var, got %q", orig)
		}
	})
}

// =============================================================================
// Obfuscate: Empty replacement (the hardcoded "******")
// =============================================================================

func TestAdversarialObfuscateReplacementIsHardcoded(t *testing.T) {
	// Verify the obfuscation replacement is exactly "******" (6 asterisks)
	// and cannot be customized or bypassed
	vars := []string{"SECRET=mypassword"}

	var gotVal string
	ObfuscateEnvironmentArray(vars, map[string]struct{}{"SECRET": {}}, nil, func(key, val, orig string) {
		gotVal = val
	})
	if gotVal != "******" {
		t.Errorf("obfuscated value should be exactly '******', got %q", gotVal)
	}
	if len(gotVal) != 6 {
		t.Errorf("obfuscated value length should be 6, got %d", len(gotVal))
	}
}

// =============================================================================
// Obfuscate: Sensitive values that look like obfuscated values (confusion)
// =============================================================================

func TestAdversarialObfuscateConfusionWithObfuscatedLookingValues(t *testing.T) {
	// If a non-sensitive var has value "******", it should NOT be altered
	vars := []string{
		"DISPLAY_MASK=******",
		"REAL_SECRET=actualpassword",
	}

	collected := make(map[string]string)
	ObfuscateEnvironmentArray(vars, map[string]struct{}{"*SECRET*": {}}, nil, func(key, val, orig string) {
		collected[key] = val
	})

	// DISPLAY_MASK is not sensitive -- its value "******" should pass through unchanged
	if collected["DISPLAY_MASK"] != "******" {
		t.Errorf("non-sensitive var with '******' value should pass through, got %q", collected["DISPLAY_MASK"])
	}
	if collected["REAL_SECRET"] != "******" {
		t.Errorf("REAL_SECRET should be obfuscated, got %q", collected["REAL_SECRET"])
	}

	// Key point: you CANNOT distinguish between an intentionally "******" value
	// and an obfuscated one. This is a known limitation worth documenting.
}

// =============================================================================
// BUG: Case sensitivity asymmetry between exact and glob matching
// Glob patterns are uppercased for matching, but exact-match keys are NOT.
// This means `blockList["secret_key"]` will not match env var "SECRET_KEY"
// via exact match, but `*secret_key*` WOULD match via glob (after uppercasing).
// =============================================================================

func TestAdversarialCaseSensitivityAsymmetry(t *testing.T) {
	vars := []string{"secret_key=password", "SECRET_KEY=password2"}

	t.Run("exact match is now case insensitive (R3-124 fix)", func(t *testing.T) {
		// After R3-124 fix, exact matching is case-insensitive.
		// "secret_key" in blocklist should match both cases.
		collected := make(map[string]string)
		FilterEnvironmentArray(vars, map[string]struct{}{"secret_key": {}}, nil, func(key, val, orig string) {
			collected[key] = val
		})
		// Both should be filtered now (case-insensitive exact match)
		if _, exists := collected["secret_key"]; exists {
			t.Error("lowercase 'secret_key' should be filtered by exact match")
		}
		if _, exists := collected["SECRET_KEY"]; exists {
			t.Error("uppercase 'SECRET_KEY' should also be filtered (case-insensitive exact match after R3-124)")
		}
	})

	t.Run("glob match is case insensitive", func(t *testing.T) {
		// "*secret_key*" glob is uppercased to "*SECRET_KEY*" and keys are uppercased too
		collected := make(map[string]string)
		FilterEnvironmentArray(vars, map[string]struct{}{"*secret_key*": {}}, nil, func(key, val, orig string) {
			collected[key] = val
		})
		// Both should be filtered because glob matching normalizes to uppercase
		if _, exists := collected["secret_key"]; exists {
			t.Error("lowercase 'secret_key' should be filtered by case-insensitive glob")
		}
		if _, exists := collected["SECRET_KEY"]; exists {
			t.Error("uppercase 'SECRET_KEY' should also be filtered by case-insensitive glob")
		}
	})

	t.Run("exact key in list now catches lowercase env vars (R3-124 fix)", func(t *testing.T) {
		// After R3-124 fix, exact matching is case-insensitive.
		// "TOKEN" in blocklist should match both "token" and "TOKEN".
		collected := make(map[string]string)
		FilterEnvironmentArray(
			[]string{"token=my_secret", "TOKEN=my_other_secret"},
			map[string]struct{}{"TOKEN": {}},
			nil,
			func(key, val, orig string) { collected[key] = val },
		)
		if _, exists := collected["token"]; exists {
			t.Error("lowercase 'token' should now be filtered by case-insensitive exact match 'TOKEN' (R3-124 fix)")
		}
		if _, exists := collected["TOKEN"]; exists {
			t.Error("uppercase 'TOKEN' should be filtered by exact match")
		}
	})
}

// =============================================================================
// BUG: Capture.Capture mutates sensitiveVarsList in place
// When disableSensitiveVarsDefault is true, it sets c.sensitiveVarsList to
// an empty map, destroying the original. Then it merges addSensitiveVarsList
// into it. Calling Capture a second time on the same Capture instance will
// behave differently if disableSensitiveVarsDefault was true.
// =============================================================================

func TestAdversarialCaptureMutatesSensitiveList(t *testing.T) {
	c := NewCapturer(
		WithDisableDefaultSensitiveList(),
		WithAdditionalKeys([]string{"CUSTOM_SENSITIVE"}),
	)

	env := []string{"CUSTOM_SENSITIVE=secret1", "MY_TOKEN=visible"}

	// First call
	result1 := c.Capture(env)
	if result1["CUSTOM_SENSITIVE"] != "******" {
		t.Fatalf("first call: CUSTOM_SENSITIVE should be obfuscated, got %q", result1["CUSTOM_SENSITIVE"])
	}
	if result1["MY_TOKEN"] != "visible" {
		t.Fatalf("first call: MY_TOKEN should be visible (default list disabled), got %q", result1["MY_TOKEN"])
	}

	// Second call on same Capture instance.
	// BUG: After the first call, c.sensitiveVarsList was replaced with an empty map
	// and addSensitiveVarsList was merged in. The second call sees
	// disableSensitiveVarsDefault=true, so it replaces c.sensitiveVarsList with
	// a NEW empty map, then merges addSensitiveVarsList again. But wait --
	// addSensitiveVarsList was already drained into the first sensitiveVarsList.
	// Actually, addSensitiveVarsList is iterated but not cleared, so it should
	// still work. Let's verify.
	result2 := c.Capture(env)
	if result2["CUSTOM_SENSITIVE"] != "******" {
		t.Errorf("BUG: second call: CUSTOM_SENSITIVE should still be obfuscated, got %q -- Capture mutates internal state", result2["CUSTOM_SENSITIVE"])
	}
}

func TestAdversarialCaptureRepeatedCallsWithDefaultList(t *testing.T) {
	// The more subtle bug: when disableSensitiveVarsDefault is true,
	// line 86-87 in capture.go does: c.sensitiveVarsList = map[string]struct{}{}
	// This permanently destroys the default list. Even if you later set
	// disableSensitiveVarsDefault back to false, the list is gone.
	c := &Capture{
		sensitiveVarsList:           map[string]struct{}{"*TOKEN*": {}, "SECRET": {}},
		addSensitiveVarsList:        map[string]struct{}{},
		excludeSensitiveVarsList:    map[string]struct{}{},
		disableSensitiveVarsDefault: true,
	}

	env := []string{"MY_TOKEN=secret", "SECRET=password"}

	// First call: disables default, so nothing is obfuscated
	result1 := c.Capture(env)
	if result1["MY_TOKEN"] != "secret" {
		t.Errorf("first call: MY_TOKEN should be visible, got %q", result1["MY_TOKEN"])
	}

	// Now "re-enable" the default list
	c.disableSensitiveVarsDefault = false

	// Second call: the default list was ALREADY destroyed by the first call!
	result2 := c.Capture(env)
	if result2["MY_TOKEN"] == "secret" {
		t.Logf("BUG CONFIRMED: After disabling then re-enabling default sensitive list, "+
			"MY_TOKEN is still visible (%q) because the original list was destroyed in place",
			result2["MY_TOKEN"])
	} else if result2["MY_TOKEN"] == "******" {
		t.Log("Default list was preserved (this would mean the bug was fixed)")
	}
}

// =============================================================================
// Concurrent Capture calls (race detector target)
// =============================================================================

func TestAdversarialCaptureConcurrent(t *testing.T) {
	// Capture.Capture mutates internal state (c.sensitiveVarsList),
	// so concurrent calls on the same Capture instance should race.
	c := NewCapturer(
		WithAdditionalKeys([]string{"EXTRA"}),
	)

	env := []string{
		"EXTRA=secret",
		"MY_TOKEN=abc",
		"SAFE_VAR=value",
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := c.Capture(env)
			// Basic sanity: SAFE_VAR should always be present
			if _, ok := result["SAFE_VAR"]; !ok {
				t.Error("SAFE_VAR should always be present")
			}
		}()
	}
	wg.Wait()
}

// =============================================================================
// Filter: Exclude keys interaction with exact vs glob
// =============================================================================

func TestAdversarialExcludeKeysDoNotAffectGlobCompilation(t *testing.T) {
	// Exclude keys only skip the key from being checked against blocklist.
	// They should not affect which globs get compiled.
	vars := []string{
		"TOKEN_A=secret1",
		"TOKEN_B=secret2",
	}

	// Exclude TOKEN_A -- it should pass through even though *TOKEN* matches
	collected := make(map[string]string)
	FilterEnvironmentArray(vars, map[string]struct{}{"*TOKEN*": {}}, map[string]struct{}{"TOKEN_A": {}}, func(key, val, orig string) {
		collected[key] = val
	})

	if _, exists := collected["TOKEN_A"]; !exists {
		t.Error("TOKEN_A should be excluded from filtering and pass through")
	}
	if _, exists := collected["TOKEN_B"]; exists {
		t.Error("TOKEN_B should be filtered by *TOKEN* glob")
	}
}

// =============================================================================
// Filter: Huge number of variables
// =============================================================================

func TestAdversarialFilterManyVariables(t *testing.T) {
	// 10,000 variables with varied patterns
	vars := make([]string, 10000)
	for i := range vars {
		if i%100 == 0 {
			vars[i] = "SECRET_" + strings.Repeat("X", i%50) + "=val"
		} else {
			vars[i] = "NORMAL_" + strings.Repeat("Y", i%50) + "=val"
		}
	}

	blockList := map[string]struct{}{"*SECRET*": {}}

	start := time.Now()
	count := 0
	FilterEnvironmentArray(vars, blockList, nil, func(key, val, orig string) {
		count++
	})
	elapsed := time.Since(start)

	expectedAllowed := 10000 - 100 // 100 SECRET vars
	if count != expectedAllowed {
		t.Errorf("expected %d allowed vars, got %d", expectedAllowed, count)
	}
	if elapsed > 5*time.Second {
		t.Errorf("filtering 10k vars took %v (too slow)", elapsed)
	}
}

// =============================================================================
// Obfuscate: Concurrent calls with shared obfuscation list
// =============================================================================

func TestAdversarialObfuscateConcurrentSharedList(t *testing.T) {
	obfuscateList := map[string]struct{}{
		"*TOKEN*":  {},
		"*SECRET*": {},
	}
	vars := []string{
		"MY_TOKEN=abc",
		"SECRET_KEY=def",
		"NORMAL=ghi",
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			collected := make(map[string]string)
			ObfuscateEnvironmentArray(vars, obfuscateList, nil, func(key, val, orig string) {
				collected[key] = val
			})
			if collected["MY_TOKEN"] != "******" {
				t.Errorf("MY_TOKEN should be '******', got %q", collected["MY_TOKEN"])
			}
			if collected["NORMAL"] != "ghi" {
				t.Errorf("NORMAL should be 'ghi', got %q", collected["NORMAL"])
			}
		}()
	}
	wg.Wait()
}

// =============================================================================
// Obfuscate: exclude key that contains glob characters
// =============================================================================

func TestAdversarialObfuscateExcludeKeyWithGlobChars(t *testing.T) {
	// An exclude key that looks like a glob pattern should be treated as
	// a literal key name, not compiled as a glob.
	vars := []string{"*TOKEN*=litvalue", "MY_TOKEN=secret"}

	collected := make(map[string]string)
	ObfuscateEnvironmentArray(
		vars,
		map[string]struct{}{"*TOKEN*": {}},
		map[string]struct{}{"*TOKEN*": {}}, // exclude key is literally "*TOKEN*"
		func(key, val, orig string) {
			collected[key] = val
		},
	)

	// The env var with key literally "*TOKEN*" should be excluded from obfuscation
	if collected["*TOKEN*"] != "litvalue" {
		t.Errorf("literal key '*TOKEN*' should be excluded from obfuscation, got %q", collected["*TOKEN*"])
	}
	// MY_TOKEN should still be obfuscated (it's not in the exclude list)
	if collected["MY_TOKEN"] != "******" {
		t.Errorf("MY_TOKEN should be obfuscated, got %q", collected["MY_TOKEN"])
	}
}

// =============================================================================
// Filter: Large block list with many patterns
// =============================================================================

func TestAdversarialFilterLargeBlockList(t *testing.T) {
	// 1000 different glob patterns
	blockList := make(map[string]struct{})
	for i := 0; i < 1000; i++ {
		blockList["*PATTERN_"+strings.Repeat("X", i%20)+"*"] = struct{}{}
	}

	vars := []string{"NORMAL=value", "PATTERN_XXXXX=matched"}
	var collected []string
	FilterEnvironmentArray(vars, blockList, nil, func(key, val, orig string) {
		collected = append(collected, key)
	})

	if len(collected) != 1 || collected[0] != "NORMAL" {
		t.Errorf("expected only NORMAL to pass, got %v", collected)
	}
}

// =============================================================================
// splitVariable: extreme edge cases
// =============================================================================

func TestAdversarialSplitVariableOnlyNullBytes(t *testing.T) {
	key, val := splitVariable("\x00=\x00")
	if key != "\x00" {
		t.Errorf("key = %q, want %q", key, "\x00")
	}
	if val != "\x00" {
		t.Errorf("val = %q, want %q", val, "\x00")
	}
}

func TestAdversarialSplitVariable10MBValue(t *testing.T) {
	bigVal := strings.Repeat("V", 10*1024*1024)
	key, val := splitVariable("K=" + bigVal)
	if key != "K" {
		t.Errorf("key = %q, want 'K'", key)
	}
	if len(val) != 10*1024*1024 {
		t.Errorf("val length = %d, want %d", len(val), 10*1024*1024)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
