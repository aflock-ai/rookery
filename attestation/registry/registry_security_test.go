//go:build audit

package registry

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// ==========================================================================
// R3-240: Case-sensitive name lookup allows attacker name squatting
// ==========================================================================

// TestSecurity_R3_240_CaseSensitiveNameLookup proves that registry lookups
// are case-sensitive, meaning "Git" and "git" are treated as distinct
// entries. An attacker or misconfigured plugin could register a name that
// differs only in case from a legitimate entry, causing confusion about
// which attestor is actually being used.
//
// BUG [MEDIUM]: No normalization (e.g., strings.ToLower) is applied to
// names during Register or Entry lookup. Case-variant names silently
// coexist, and callers must know the exact casing to retrieve the intended
// entry. In a supply chain security context, this enables name-squatting
// attacks where a malicious attestor registers "Git" to shadow the
// legitimate "git" attestor.
// File: registry/registry.go:51,71
func TestSecurity_R3_240_CaseSensitiveNameLookup(t *testing.T) {
	reg := New[*testEntity]()

	reg.Register("git", func() *testEntity { return &testEntity{intOpt: 1} })
	reg.Register("Git", func() *testEntity { return &testEntity{intOpt: 2} })
	reg.Register("GIT", func() *testEntity { return &testEntity{intOpt: 3} })

	// All three are distinct entries
	entries := reg.AllEntries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries for case-variant names, got %d", len(entries))
	}

	// Each lookup returns the case-exact match
	e1, ok1 := reg.Entry("git")
	e2, ok2 := reg.Entry("Git")
	e3, ok3 := reg.Entry("GIT")

	if !ok1 || !ok2 || !ok3 {
		t.Fatalf("all three case variants should be found: ok1=%v ok2=%v ok3=%v", ok1, ok2, ok3)
	}

	if e1.Factory().intOpt != 1 {
		t.Errorf("'git' should map to intOpt=1, got %d", e1.Factory().intOpt)
	}
	if e2.Factory().intOpt != 2 {
		t.Errorf("'Git' should map to intOpt=2, got %d", e2.Factory().intOpt)
	}
	if e3.Factory().intOpt != 3 {
		t.Errorf("'GIT' should map to intOpt=3, got %d", e3.Factory().intOpt)
	}

	// Lookup with wrong case returns not-found, not a fuzzy match
	_, okLower := reg.Entry("gIt")
	if okLower {
		t.Errorf("BUG: mixed-case 'gIt' should not match any entry")
	}

	t.Logf("BUG [MEDIUM]: Registry lookups are case-sensitive. "+
		"'git', 'Git', and 'GIT' are three distinct entries. "+
		"No name normalization is performed. An attacker can register "+
		"a case-variant name to shadow or confuse legitimate attestors. "+
		"File: registry.go:51,71")
}

// ==========================================================================
// R3-241: Nil factory registration is accepted without validation
// ==========================================================================

// TestSecurity_R3_241_NilFactoryDeferredPanic proves that Register accepts
// a nil factory function without error. The nil is stored and only causes
// a panic when NewEntity calls entry.Factory() -- a nil function pointer
// dereference. This creates a latent crash far from the registration site.
//
// BUG [HIGH]: Register at registry.go:51 does not validate factoryFunc.
// A nil factory is silently stored. The panic occurs at registry.go:94
// when NewEntity calls entry.Factory(). This is a time-bomb: registration
// appears to succeed, and the crash happens at an unrelated call site.
func TestSecurity_R3_241_NilFactoryDeferredPanic(t *testing.T) {
	reg := New[*testEntity]()

	// Registration succeeds with nil factory
	entry := reg.Register("nil-factory-r3241", nil)
	if entry.Name != "nil-factory-r3241" {
		t.Errorf("expected entry name 'nil-factory-r3241', got %q", entry.Name)
	}
	if entry.Factory != nil {
		t.Errorf("expected nil factory to be stored as nil, but it is non-nil")
	}

	// Verify the nil factory is retrievable via Entry
	retrieved, ok := reg.Entry("nil-factory-r3241")
	if !ok {
		t.Fatalf("entry should be found in registry")
	}
	if retrieved.Factory != nil {
		t.Errorf("stored factory should be nil")
	}

	// NewEntity panics because it calls entry.Factory() which is nil
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_, _ = reg.NewEntity("nil-factory-r3241")
	}()

	if !panicked {
		t.Errorf("BUG [HIGH]: expected panic when calling NewEntity with nil factory, but none occurred")
	} else {
		t.Logf("BUG [HIGH]: nil factory registration is accepted silently. "+
			"Panic deferred to NewEntity call site (registry.go:94). "+
			"Register should validate factoryFunc != nil.")
	}
}

// ==========================================================================
// R3-242: Silent overwrite on duplicate name registration
// ==========================================================================

// TestSecurity_R3_242_SilentOverwriteDuplicateName proves that registering
// the same name twice silently replaces the first registration -- factory,
// options, and all. No error, no warning, no log. The first registration
// is irrecoverably lost.
//
// BUG [MEDIUM]: Register at registry.go:58 does a simple map assignment
// with no existence check. In a plugin-based system where init() functions
// from different packages call Register, name collisions are silent and
// the winner depends on import order, which is non-deterministic across
// Go toolchain versions.
// File: registry/registry.go:51-59
func TestSecurity_R3_242_SilentOverwriteDuplicateName(t *testing.T) {
	reg := New[*testEntity]()

	factory1Called := false
	factory2Called := false

	reg.Register("duplicate-name", func() *testEntity {
		factory1Called = true
		return &testEntity{intOpt: 100}
	}, IntConfigOption("opt1", "first option", 10,
		func(te *testEntity, v int) (*testEntity, error) {
			te.intOpt = v
			return te, nil
		}),
	)

	reg.Register("duplicate-name", func() *testEntity {
		factory2Called = true
		return &testEntity{intOpt: 200}
	}, StringConfigOption("opt2", "second option", "val",
		func(te *testEntity, v string) (*testEntity, error) {
			te.strOpt = v
			return te, nil
		}),
	)

	// Only one entry exists
	allEntries := reg.AllEntries()
	if len(allEntries) != 1 {
		t.Errorf("expected exactly 1 entry after duplicate registration, got %d", len(allEntries))
	}

	// The second factory is the one stored
	entry, ok := reg.Entry("duplicate-name")
	if !ok {
		t.Fatalf("entry should exist")
	}
	entity := entry.Factory()
	if !factory2Called {
		t.Errorf("second factory should have been called")
	}
	if factory1Called {
		t.Errorf("first factory should NOT have been called (it was overwritten)")
	}
	if entity.intOpt != 200 {
		t.Errorf("expected intOpt=200 from second factory, got %d", entity.intOpt)
	}

	// Options are from second registration only
	if len(entry.Options) != 1 {
		t.Errorf("expected 1 option from second registration, got %d", len(entry.Options))
	}
	if entry.Options[0].Name() != "opt2" {
		t.Errorf("expected option 'opt2' from second registration, got %q", entry.Options[0].Name())
	}

	t.Logf("BUG [MEDIUM]: Register silently overwrites on duplicate name. "+
		"First registration's factory AND options are irrecoverably lost. "+
		"No error, no log. In plugin systems, this makes debugging name "+
		"collisions extremely difficult. File: registry.go:58")
}

// ==========================================================================
// R3-243: Concurrent register to same registry races on map write
// ==========================================================================

// TestSecurity_R3_243_ConcurrentRegisterSharesMap demonstrates that
// Registry's value receiver semantics combined with Go map reference
// sharing means that any code holding a copy of a Registry can write
// to the same underlying map. If Register is called from multiple
// goroutines (even on "copies"), they all race on the same map.
//
// BUG [HIGH]: Registry[T] has a value receiver on Register, but the
// entriesByName map is a reference type. Copies of the Registry share
// the map. No mutex or sync.Map protects it. Concurrent Register calls
// on any copy of the same Registry will race.
// File: registry/registry.go:26-28, 51-59
func TestSecurity_R3_243_ConcurrentRegisterSharesMap(t *testing.T) {
	reg := New[*testEntity]()

	// Create copies via value semantics -- all share the same map
	regCopy1 := reg
	regCopy2 := reg

	// Write from original
	reg.Register("from-original", func() *testEntity { return &testEntity{intOpt: 1} })

	// Verify copies see the write (proving map is shared)
	_, ok1 := regCopy1.Entry("from-original")
	_, ok2 := regCopy2.Entry("from-original")
	if !ok1 || !ok2 {
		t.Fatalf("copies should see writes from original: copy1=%v copy2=%v", ok1, ok2)
	}

	// Write from copy
	regCopy1.Register("from-copy1", func() *testEntity { return &testEntity{intOpt: 2} })

	// Original sees the write
	_, ok := reg.Entry("from-copy1")
	if !ok {
		t.Fatalf("original should see writes from copy")
	}

	// Write from function that takes Registry by value
	writeViaByValue := func(r Registry[*testEntity], name string) {
		r.Register(name, func() *testEntity { return &testEntity{intOpt: 3} })
	}
	writeViaByValue(reg, "from-by-value")

	_, ok = reg.Entry("from-by-value")
	if !ok {
		t.Fatalf("original should see writes from by-value function parameter")
	}

	t.Logf("BUG [HIGH]: Registry uses value receiver but map is a reference type. "+
		"All copies of a Registry share the same underlying map. Concurrent "+
		"Register() calls from any copy will data-race on the map. "+
		"File: registry.go:26-28, 51-59")
}

// ==========================================================================
// R3-244: FactoryByType/FactoryByName return nil function on miss
// ==========================================================================

// TestSecurity_R3_244_LookupMissReturnsNilFactory proves that when
// Entry() returns ok=false for a missing name, the returned Entry's
// Factory field is the zero value (nil function pointer). A caller
// that ignores the ok return value and calls Factory() will panic.
//
// BUG [MEDIUM]: Entry() and Options() return the zero value of Entry[T]
// when the name is not found. The Factory field is nil. Callers that
// skip the ok check and call factory() will get a nil function panic.
// This is standard Go map behavior, but in a security-critical system
// where attestor lookups drive verification decisions, a panic is
// unacceptable. Consider returning an error or a sentinel factory.
// File: registry/registry.go:71-74
func TestSecurity_R3_244_LookupMissReturnsNilFactory(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("exists", func() *testEntity { return &testEntity{} })

	// Entry for a missing name returns zero-value Entry
	entry, ok := reg.Entry("does-not-exist")
	if ok {
		t.Fatalf("Entry should return ok=false for missing name")
	}
	if entry.Factory != nil {
		t.Errorf("zero-value Entry should have nil Factory")
	}
	if entry.Name != "" {
		t.Errorf("zero-value Entry should have empty Name, got %q", entry.Name)
	}

	// Calling the nil factory panics
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_ = entry.Factory()
	}()

	if !panicked {
		t.Errorf("BUG [MEDIUM]: calling nil Factory from zero-value Entry should panic")
	}

	// Options for a missing name also returns ok=false
	opts, optOk := reg.Options("does-not-exist")
	if optOk {
		t.Errorf("Options should return ok=false for missing name")
	}
	if opts != nil {
		t.Errorf("zero-value Options should be nil, got %v", opts)
	}

	t.Logf("BUG [MEDIUM]: Entry() for missing name returns zero-value Entry "+
		"with nil Factory. Callers that skip the ok check will panic on "+
		"Factory(). File: registry.go:71-74")
}

// ==========================================================================
// R3-245: Empty string name is valid -- no name validation
// ==========================================================================

// TestSecurity_R3_245_EmptyAndWhitespaceNamesAccepted proves that Register
// accepts any string as a name, including empty string, whitespace-only,
// control characters, and null bytes. No validation is performed.
//
// BUG [LOW]: Register does not validate the name parameter. Empty strings,
// whitespace, control characters, and null bytes are all accepted. In a
// CLI that creates flags from registry names, these could cause parsing
// errors or security issues (e.g., null byte injection in logging).
// File: registry/registry.go:51
func TestSecurity_R3_245_EmptyAndWhitespaceNamesAccepted(t *testing.T) {
	reg := New[*testEntity]()

	problematicNames := []struct {
		desc string
		name string
	}{
		{"empty string", ""},
		{"single space", " "},
		{"tabs", "\t\t"},
		{"newlines", "\n\n"},
		{"null byte", "\x00"},
		{"control chars", "\x01\x02\x03"},
		{"mixed whitespace", " \t\n\r "},
		{"very long", strings.Repeat("a", 100000)},
		{"unicode homoglyph", "g\u0456t"}, // Cyrillic i instead of Latin i
	}

	for i, tc := range problematicNames {
		t.Run(tc.desc, func(t *testing.T) {
			reg.Register(tc.name, func() *testEntity { return &testEntity{intOpt: i} })
			entry, ok := reg.Entry(tc.name)
			if !ok {
				t.Errorf("Register accepted name %q but Entry cannot find it", tc.name)
				return
			}
			if entry.Factory().intOpt != i {
				t.Errorf("factory for name %q returned wrong intOpt: got %d, want %d",
					tc.name, entry.Factory().intOpt, i)
			}
		})
	}

	t.Logf("BUG [LOW]: Register accepts any string as a name with no validation. "+
		"Empty strings, control characters, null bytes, and unicode homoglyphs "+
		"are all valid names. This creates opportunities for confusion attacks "+
		"(e.g., registering 'g\\u0456t' which looks like 'git' but is distinct). "+
		"File: registry.go:51")
}

// ==========================================================================
// R3-246: SetDefaultVals type switch has no default case
// ==========================================================================

// TestSecurity_R3_246_SetDefaultValsSkipsUnmatchedConfigurer proves that
// SetDefaultVals silently skips any Configurer implementation that doesn't
// match one of the five known ConfigOption types. No error, no log. The
// entity is returned as-is with the option's default NOT applied.
//
// BUG [MEDIUM]: SetDefaultVals at registry.go:120-131 has a type switch
// with no default case. If a new type is added to the Option constraint
// or a custom Configurer is used, its default value will silently not be
// applied. There is no compile-time or runtime safeguard. This is a
// maintenance trap: adding a new option type (e.g., float64) to the
// constraint without updating the switch will cause silent misconfiguration.
// File: registry/registry.go:116-139
func TestSecurity_R3_246_SetDefaultValsSkipsUnmatchedConfigurer(t *testing.T) {
	reg := New[*testEntity]()

	// Create a Configurer that satisfies the interface but doesn't match
	// any case in the type switch
	custom := &silentlySkippedConfigurer{
		configName: "custom-option",
		configDesc: "a custom option that will be silently skipped",
	}

	entity := &testEntity{intOpt: 42, strOpt: "original"}
	result, err := reg.SetDefaultVals(entity, []Configurer{custom})

	if err != nil {
		t.Fatalf("expected no error for unmatched configurer, got: %v", err)
	}

	// Entity is completely unchanged -- the configurer was silently skipped
	if result.intOpt != 42 {
		t.Errorf("intOpt should be unchanged at 42, got %d", result.intOpt)
	}
	if result.strOpt != "original" {
		t.Errorf("strOpt should be unchanged at 'original', got %q", result.strOpt)
	}

	// Now test with mismatched entity type ConfigOption
	// An IntConfigOption parameterized for a completely different type
	type otherEntity struct{ val int }
	wrongTypeOpt := IntConfigOption[otherEntity]("val", "wrong entity type", 999,
		func(e otherEntity, v int) (otherEntity, error) {
			e.val = v
			return e, nil
		})

	entity2 := &testEntity{intOpt: 7}
	result2, err2 := reg.SetDefaultVals(entity2, []Configurer{wrongTypeOpt})
	if err2 != nil {
		t.Fatalf("expected no error for wrong-type configurer, got: %v", err2)
	}
	if result2.intOpt != 7 {
		t.Errorf("intOpt should be unchanged at 7, got %d", result2.intOpt)
	}

	t.Logf("BUG [MEDIUM]: SetDefaultVals silently skips configurers that "+
		"don't match the type switch. Custom Configurer implementations and "+
		"ConfigOptions parameterized for wrong entity types are all silently "+
		"ignored. No error, no warning. File: registry.go:116-139")
}

// silentlySkippedConfigurer satisfies Configurer but will not match any
// case in SetDefaultVals' type switch.
type silentlySkippedConfigurer struct {
	configName string
	configDesc string
}

func (c *silentlySkippedConfigurer) Name() string        { return c.configName }
func (c *silentlySkippedConfigurer) Description() string { return c.configDesc }
func (c *silentlySkippedConfigurer) SetPrefix(p string)  {}

// ==========================================================================
// R3-247: Partial entity state on SetDefaultVals error with pointer types
// ==========================================================================

// TestSecurity_R3_247_PartialStateOnSetterError proves that when
// SetDefaultVals encounters a setter error partway through the options
// list, it returns the entity with partial configuration applied. For
// pointer types, the entity has been mutated in place by earlier setters,
// so the returned entity (and any aliases to the same pointer) is in an
// inconsistent state.
//
// BUG [MEDIUM]: SetDefaultVals returns early on first setter error at
// registry.go:133. For pointer entities, earlier setters have already
// mutated the entity via the pointer. The returned entity has some
// defaults but not all. Callers that inspect the entity on error will
// find it in an inconsistent half-configured state.
// File: registry/registry.go:116-139
func TestSecurity_R3_247_PartialStateOnSetterError(t *testing.T) {
	reg := New[*testEntity]()

	opts := []Configurer{
		IntConfigOption("first", "will succeed", 42,
			func(te *testEntity, v int) (*testEntity, error) {
				te.intOpt = v
				return te, nil
			}),
		StringConfigOption("second", "will succeed", "hello",
			func(te *testEntity, v string) (*testEntity, error) {
				te.strOpt = v
				return te, nil
			}),
		BoolConfigOption("third", "will fail", true,
			func(te *testEntity, v bool) (*testEntity, error) {
				return te, fmt.Errorf("setter error in third option")
			}),
		StringSliceConfigOption("fourth", "will never run", []string{"a"},
			func(te *testEntity, v []string) (*testEntity, error) {
				te.strSliceOpt = v
				return te, nil
			}),
	}

	reg.Register("partial-config", func() *testEntity { return &testEntity{} }, opts...)

	entity, err := reg.NewEntity("partial-config")
	if err == nil {
		t.Fatalf("expected error from third setter, got nil")
	}

	// entity is non-nil and partially configured
	if entity == nil {
		t.Fatalf("entity should be non-nil even on error (pointer semantics)")
	}

	// First two setters mutated the entity
	if entity.intOpt != 42 {
		t.Errorf("intOpt should be 42 (set by first setter), got %d", entity.intOpt)
	}
	if entity.strOpt != "hello" {
		t.Errorf("strOpt should be 'hello' (set by second setter), got %q", entity.strOpt)
	}

	// Third setter failed, fourth never ran
	if entity.boolOpt != false {
		t.Errorf("boolOpt should be zero value (third setter failed)")
	}
	if entity.strSliceOpt != nil {
		t.Errorf("strSliceOpt should be nil (fourth setter never ran)")
	}

	t.Logf("BUG [MEDIUM]: entity returned on error is partially configured. "+
		"intOpt=42, strOpt='hello' (from successful setters), but boolOpt "+
		"and strSliceOpt are zero values (failed/skipped). Entity is in an "+
		"inconsistent state. File: registry.go:116-139")
}

// ==========================================================================
// R3-248: Concurrent NewEntity is safe but concurrent Register is not
// ==========================================================================

// TestSecurity_R3_248_ConcurrentNewEntitySafe verifies that concurrent
// NewEntity calls on a pre-populated (read-only) registry are safe
// and produce independent entities, while documenting that concurrent
// Register would be unsafe.
//
// NOTE: This test runs with -race and should PASS, proving that reads
// are safe. The documented bug is about writes, which we cannot safely
// test under -race without crashing the binary.
func TestSecurity_R3_248_ConcurrentNewEntitySafe(t *testing.T) {
	reg := New[*testEntity]()

	// Pre-populate with an option to exercise SetDefaultVals
	reg.Register("concurrent-test",
		func() *testEntity { return &testEntity{} },
		IntConfigOption("val", "test", 42,
			func(te *testEntity, v int) (*testEntity, error) {
				te.intOpt = v
				return te, nil
			}),
	)

	const goroutines = 200
	var wg sync.WaitGroup
	entities := make([]*testEntity, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			entities[idx], errs[idx] = reg.NewEntity("concurrent-test")
		}(i)
	}
	wg.Wait()

	// All should succeed
	for i := 0; i < goroutines; i++ {
		if errs[i] != nil {
			t.Errorf("goroutine %d: unexpected error: %v", i, errs[i])
		}
		if entities[i] == nil {
			t.Errorf("goroutine %d: entity is nil", i)
			continue
		}
		if entities[i].intOpt != 42 {
			t.Errorf("goroutine %d: intOpt=%d, want 42", i, entities[i].intOpt)
		}
	}

	// Verify independence: mutating one should not affect others
	if entities[0] != nil {
		entities[0].intOpt = 999
	}
	for i := 1; i < goroutines; i++ {
		if entities[i] != nil && entities[i].intOpt != 42 {
			t.Errorf("goroutine %d: entity is NOT independent (intOpt=%d after mutating entity 0)",
				i, entities[i].intOpt)
		}
	}

	t.Logf("OK: Concurrent NewEntity on a pre-populated registry is safe "+
		"(read-only map access). Each call produces an independent entity. "+
		"However, concurrent Register (writes) would race on the same map.")
}

// ==========================================================================
// R3-249: Unicode homoglyph name confusion attack
// ==========================================================================

// TestSecurity_R3_249_UnicodeHomoglyphNameConfusion proves that the
// registry treats visually identical but byte-different Unicode strings
// as distinct names. An attacker can register an attestor with a name
// that looks identical to a legitimate name (using Unicode homoglyphs)
// but maps to a different registry entry.
//
// BUG [MEDIUM]: Registry names are compared byte-for-byte (Go string
// equality). Visually identical names using Unicode homoglyphs (e.g.,
// Cyrillic 'а' U+0430 vs Latin 'a' U+0061) are distinct entries.
// In a supply chain security system, this enables visual confusion
// attacks where a malicious attestor appears to be the legitimate one.
// File: registry/registry.go:51,71
func TestSecurity_R3_249_UnicodeHomoglyphNameConfusion(t *testing.T) {
	reg := New[*testEntity]()

	// Latin "a" (U+0061) vs Cyrillic "а" (U+0430) -- visually identical
	latinName := "attestor"                         // all Latin
	cyrillicName := "\u0430ttestor"                 // Cyrillic 'а' + Latin "ttestor"
	fullwidthName := "\uff47\uff49\uff54"           // fullwidth "git"

	reg.Register(latinName, func() *testEntity { return &testEntity{intOpt: 1} })
	reg.Register(cyrillicName, func() *testEntity { return &testEntity{intOpt: 2} })
	reg.Register(fullwidthName, func() *testEntity { return &testEntity{intOpt: 3} })

	// All are distinct entries
	allEntries := reg.AllEntries()
	if len(allEntries) != 3 {
		t.Fatalf("expected 3 entries for homoglyph names, got %d", len(allEntries))
	}

	// Latin lookup finds Latin
	e1, ok1 := reg.Entry(latinName)
	if !ok1 || e1.Factory().intOpt != 1 {
		t.Errorf("Latin name should map to intOpt=1")
	}

	// Cyrillic lookup finds Cyrillic
	e2, ok2 := reg.Entry(cyrillicName)
	if !ok2 || e2.Factory().intOpt != 2 {
		t.Errorf("Cyrillic homoglyph name should map to intOpt=2")
	}

	// Fullwidth lookup finds fullwidth
	e3, ok3 := reg.Entry(fullwidthName)
	if !ok3 || e3.Factory().intOpt != 3 {
		t.Errorf("Fullwidth name should map to intOpt=3")
	}

	// Cross-lookups fail -- they're not interchangeable
	_, crossOk := reg.Entry(cyrillicName)
	if crossOk {
		_, crossOkLatin := reg.Entry(latinName)
		if crossOkLatin {
			// Both exist but they're different entries
			ce, _ := reg.Entry(cyrillicName)
			le, _ := reg.Entry(latinName)
			if ce.Factory().intOpt == le.Factory().intOpt {
				t.Errorf("homoglyph names should map to different entries")
			}
		}
	}

	t.Logf("BUG [MEDIUM]: Unicode homoglyph names are treated as distinct entries. "+
		"Latin 'attestor' and Cyrillic-a 'аttestor' are visually identical but "+
		"byte-different strings. An attacker can register a lookalike name to "+
		"confuse policy evaluation. No Unicode normalization is applied. "+
		"File: registry.go:51,71")
}
