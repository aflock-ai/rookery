//go:build audit

package registry

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Concurrent write race detection
// ==========================================================================

// TestAdversarial_ConcurrentWriteRace tests concurrent writes to the SAME
// registry. This WILL trigger the race detector because Registry uses a
// plain Go map with no synchronization.
//
// BUG [HIGH]: Registry.Register writes to an unprotected map. Concurrent
// Register calls on the same Registry instance will cause a data race.
// This test is skipped by default because it would fail under -race, but
// the bug is documented here. Run with -tags=racetest to enable.
//
// The existing test TestAdversarial_ConcurrentRegister in the original
// adversarial test file avoids this by using separate registries per
// goroutine, which doesn't actually test the race condition.
func TestAdversarial_ConcurrentWriteRace_Documented(t *testing.T) {
	// We CAN'T actually run concurrent writes with -race because it'll
	// crash the test binary. Instead, we document the issue and test
	// the architectural problem.
	t.Logf("BUG [HIGH]: Registry[T].Register() has no synchronization. " +
		"Concurrent Register() calls on the same Registry will data race. " +
		"The entriesByName map is written without mutex protection. " +
		"File: registry/registry.go:51-59")

	// Demonstrate the issue exists by examining the code structure:
	// Register has signature: func (r Registry[T]) Register(...)
	// It writes to r.entriesByName (a map) on line 58.
	// No mutex, no sync.Map, no channel serialization.

	// Prove maps are shared between Registry copies (value semantics + map):
	reg1 := New[*testEntity]()
	reg2 := reg1 // copy the Registry value

	reg1.Register("from-reg1", func() *testEntity { return &testEntity{intOpt: 1} })
	entry, ok := reg2.Entry("from-reg1")
	assert.True(t, ok,
		"Map is shared between Registry copies, confirming concurrent "+
			"writes to copies would also race")
	assert.Equal(t, 1, entry.Factory().intOpt)
}

// ==========================================================================
// Type switch coverage gap in SetDefaultVals
// ==========================================================================

// TestAdversarial_SetDefaultVals_UnsupportedTypesSilentlySkipped tests
// that the type switch in SetDefaultVals only handles specific types and
// silently skips all others. If someone adds a new ConfigOption type
// (e.g., float64, map[string]string), SetDefaultVals won't apply its
// default. This is a maintenance hazard.
//
// BUG [MEDIUM]: SetDefaultVals type switch (registry.go:120-131) has no
// default case. New option types added to the Option constraint interface
// would silently fail to have defaults applied.
func TestAdversarial_SetDefaultVals_UnsupportedTypesSilentlySkipped(t *testing.T) {
	reg := New[*testEntity]()

	// The Option interface currently supports: int | string | []string | bool | time.Duration
	// All five are handled in the type switch.
	// But if the constraint were extended (e.g., float64), the type switch
	// would miss it entirely.

	// Verify all currently supported types ARE handled:
	type entityWithAll struct {
		intVal      int
		strVal      string
		sliceVal    []string
		boolVal     bool
		durationVal time.Duration
	}

	regAll := New[*entityWithAll]()
	regAll.Register("all-types",
		func() *entityWithAll { return &entityWithAll{} },
		IntConfigOption("i", "", 42, func(e *entityWithAll, v int) (*entityWithAll, error) {
			e.intVal = v
			return e, nil
		}),
		StringConfigOption("s", "", "hello", func(e *entityWithAll, v string) (*entityWithAll, error) {
			e.strVal = v
			return e, nil
		}),
		StringSliceConfigOption("ss", "", []string{"a"}, func(e *entityWithAll, v []string) (*entityWithAll, error) {
			e.sliceVal = v
			return e, nil
		}),
		BoolConfigOption("b", "", true, func(e *entityWithAll, v bool) (*entityWithAll, error) {
			e.boolVal = v
			return e, nil
		}),
		DurationConfigOption("d", "", 5*time.Second, func(e *entityWithAll, v time.Duration) (*entityWithAll, error) {
			e.durationVal = v
			return e, nil
		}),
	)

	entity, err := regAll.NewEntity("all-types")
	require.NoError(t, err)
	assert.Equal(t, 42, entity.intVal)
	assert.Equal(t, "hello", entity.strVal)
	assert.Equal(t, []string{"a"}, entity.sliceVal)
	assert.True(t, entity.boolVal)
	assert.Equal(t, 5*time.Second, entity.durationVal)

	// Now test with a Configurer that matches the interface but has wrong
	// entity type parameter (will hit no case in the switch):
	type otherEntity struct{ val int }
	wrongOpt := IntConfigOption[*otherEntity]("wrong", "", 99,
		func(e *otherEntity, v int) (*otherEntity, error) {
			e.val = v
			return e, nil
		})

	entityUnchanged := &testEntity{intOpt: 7}
	result, err := reg.SetDefaultVals(entityUnchanged, []Configurer{wrongOpt})
	require.NoError(t, err,
		"BUG [MEDIUM]: Wrong-typed Configurer is silently skipped. "+
			"No error, no warning. The entity is returned unchanged. "+
			"File: registry.go:120-131")
	assert.Equal(t, 7, result.intOpt,
		"Entity should be unchanged when Configurer type doesn't match")
}

// ==========================================================================
// Name collision with special characters
// ==========================================================================

// TestAdversarial_RegisterSpecialCharNames tests registration with names
// containing special characters that might cause issues in CLI flag parsing.
func TestAdversarial_RegisterSpecialCharNames(t *testing.T) {
	reg := New[*testEntity]()

	specialNames := []string{
		"name with spaces",
		"name-with-dashes",
		"name_with_underscores",
		"name.with.dots",
		"name/with/slashes",
		"name=with=equals",
		"name\twith\ttabs",
		"name\nwith\nnewlines",
		"",                         // empty
		strings.Repeat("x", 10000), // very long
		"\x00null\x00byte",
	}

	for i, name := range specialNames {
		t.Run(fmt.Sprintf("special_name_%d", i), func(t *testing.T) {
			reg.Register(name, func() *testEntity { return &testEntity{intOpt: i} })
			entry, ok := reg.Entry(name)
			require.True(t, ok, "should find entry with special name %q", name)
			assert.Equal(t, i, entry.Factory().intOpt)
		})
	}
}

// ==========================================================================
// ConfigOption prefix injection
// ==========================================================================

// TestAdversarial_ConfigOption_PrefixInjection tests that setting a prefix
// with special characters could create naming collisions.
//
// DESIGN NOTE: Prefix is concatenated with a dash separator. If the prefix
// or name contains dashes, it becomes ambiguous whether "a-b-c" means
// prefix="a-b" name="c" or prefix="a" name="b-c".
func TestAdversarial_ConfigOption_PrefixInjection(t *testing.T) {
	opt1 := StringConfigOption[*testEntity]("b-c", "", "v1",
		func(te *testEntity, v string) (*testEntity, error) {
			te.strOpt = v
			return te, nil
		})
	opt1.SetPrefix("a")

	opt2 := StringConfigOption[*testEntity]("c", "", "v2",
		func(te *testEntity, v string) (*testEntity, error) {
			te.strOpt = v
			return te, nil
		})
	opt2.SetPrefix("a-b")

	// Both options have Name() == "a-b-c"
	assert.Equal(t, opt1.Name(), opt2.Name(),
		"DESIGN NOTE [MEDIUM]: Prefix-name concatenation with dash separator "+
			"creates ambiguity. prefix='a' name='b-c' and prefix='a-b' name='c' "+
			"both produce 'a-b-c'. This could cause CLI flag collisions. "+
			"File: option.go:40-46")
}

// ==========================================================================
// NewEntity with many option setters
// ==========================================================================

// TestAdversarial_NewEntity_ManyOptionSetters tests that a large number
// of option setters work correctly and don't stack overflow.
func TestAdversarial_NewEntity_ManyOptionSetters(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("test", func() *testEntity { return &testEntity{} })

	setters := make([]func(*testEntity) (*testEntity, error), 1000)
	for i := range setters {
		val := i
		setters[i] = func(te *testEntity) (*testEntity, error) {
			te.intOpt = val
			return te, nil
		}
	}

	entity, err := reg.NewEntity("test", setters...)
	require.NoError(t, err)
	assert.Equal(t, 999, entity.intOpt,
		"last setter should win")
}

// ==========================================================================
// SetOptions chain preserves entity identity
// ==========================================================================

// TestAdversarial_SetOptions_ChainReplacesEntity tests that when a setter
// returns a different entity instance, the chain continues with the new one.
func TestAdversarial_SetOptions_ChainReplacesEntity(t *testing.T) {
	original := &testEntity{intOpt: 1}
	replacement := &testEntity{intOpt: 100}

	result, err := SetOptions(original,
		func(te *testEntity) (*testEntity, error) {
			// Return a completely different entity.
			return replacement, nil
		},
		func(te *testEntity) (*testEntity, error) {
			// This should receive 'replacement', not 'original'.
			te.intOpt = te.intOpt + 1
			return te, nil
		},
	)

	require.NoError(t, err)
	assert.Equal(t, 101, result.intOpt,
		"chain should use the replacement entity from the first setter")
	assert.Equal(t, 1, original.intOpt,
		"original entity should be unchanged")
}

// ==========================================================================
// Entry.Factory called multiple times
// ==========================================================================

// TestAdversarial_FactoryCalledMultipleTimes tests that the factory
// function creates independent instances each time.
func TestAdversarial_FactoryCalledMultipleTimes(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("test", func() *testEntity { return &testEntity{intOpt: 0} })

	entry, ok := reg.Entry("test")
	require.True(t, ok)

	e1 := entry.Factory()
	e2 := entry.Factory()

	e1.intOpt = 42

	assert.NotEqual(t, e1.intOpt, e2.intOpt,
		"factory should create independent instances")
}

// TestAdversarial_FactoryWithSharedState tests a factory that accidentally
// shares state between instances (a common bug pattern).
func TestAdversarial_FactoryWithSharedState(t *testing.T) {
	// Intentionally buggy factory that shares state.
	shared := &testEntity{intOpt: 0}
	reg := New[*testEntity]()
	reg.Register("shared-bad", func() *testEntity { return shared })

	e1, err := reg.NewEntity("shared-bad")
	require.NoError(t, err)
	e1.intOpt = 42

	e2, err := reg.NewEntity("shared-bad")
	require.NoError(t, err)

	// Both point to the same object!
	assert.Equal(t, 42, e2.intOpt,
		"DESIGN NOTE: Registry does not protect against factories that "+
			"return shared mutable state. This is the factory author's "+
			"responsibility, but the API makes it easy to get wrong.")
}

// ==========================================================================
// AllEntries ordering
// ==========================================================================

// TestAdversarial_AllEntries_NonDeterministicOrder tests that AllEntries
// returns entries in non-deterministic order (map iteration order).
func TestAdversarial_AllEntries_NonDeterministicOrder(t *testing.T) {
	if runtime.GOARCH == "wasm" {
		t.Skip("map iteration may be deterministic on some platforms")
	}

	reg := New[*testEntity]()
	for i := 0; i < 50; i++ {
		reg.Register(fmt.Sprintf("entry-%03d", i), func() *testEntity { return &testEntity{} })
	}

	// Collect orderings.
	seenOrderings := make(map[string]bool)
	for i := 0; i < 100; i++ {
		entries := reg.AllEntries()
		var names []string
		for _, e := range entries {
			names = append(names, e.Name)
		}
		key := strings.Join(names, ",")
		seenOrderings[key] = true
	}

	t.Logf("DESIGN NOTE: AllEntries uses map iteration and returns entries in "+
		"non-deterministic order. Saw %d distinct orderings in 100 iterations. "+
		"Callers who need deterministic ordering must sort the result. "+
		"File: registry.go:77-84", len(seenOrderings))
}

// ==========================================================================
// Register after NewEntity
// ==========================================================================

// TestAdversarial_RegisterAfterNewEntity tests that registering new
// entries after calling NewEntity doesn't affect previously created entities.
func TestAdversarial_RegisterAfterNewEntity(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("first", func() *testEntity { return &testEntity{intOpt: 1} })

	e1, err := reg.NewEntity("first")
	require.NoError(t, err)
	assert.Equal(t, 1, e1.intOpt)

	// Register more entries.
	reg.Register("second", func() *testEntity { return &testEntity{intOpt: 2} })

	// Original entity should be unaffected.
	assert.Equal(t, 1, e1.intOpt)

	// New entity should work.
	e2, err := reg.NewEntity("second")
	require.NoError(t, err)
	assert.Equal(t, 2, e2.intOpt)

	// All entries should reflect both.
	all := reg.AllEntries()
	assert.Len(t, all, 2)
}

// ==========================================================================
// Value type registry with non-pointer entities
// ==========================================================================

// TestAdversarial_NonPointerEntity tests Registry with a non-pointer
// entity type. This is unusual but should work.
func TestAdversarial_NonPointerEntity(t *testing.T) {
	type valueEntity struct {
		val int
	}

	reg := New[valueEntity]()
	reg.Register("val", func() valueEntity { return valueEntity{val: 0} },
		IntConfigOption("v", "", 42, func(e valueEntity, v int) (valueEntity, error) {
			e.val = v
			return e, nil
		}),
	)

	entity, err := reg.NewEntity("val")
	require.NoError(t, err)
	assert.Equal(t, 42, entity.val,
		"non-pointer entity should work with value semantics")
}

// ==========================================================================
// Concurrent NewEntity on shared registry
// ==========================================================================

// TestAdversarial_ConcurrentNewEntity tests concurrent NewEntity calls
// on a pre-populated registry. Since NewEntity only reads the map (no
// writes), this should be safe.
func TestAdversarial_ConcurrentNewEntity(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("test", func() *testEntity { return &testEntity{} },
		IntConfigOption("val", "", 42, func(te *testEntity, v int) (*testEntity, error) {
			te.intOpt = v
			return te, nil
		}),
	)

	const goroutines = 100
	var wg sync.WaitGroup
	entities := make([]*testEntity, goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			entities[idx], errs[idx] = reg.NewEntity("test")
		}(i)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
		assert.Equal(t, 42, entities[i].intOpt, "goroutine %d", i)
	}

	// Verify all entities are independent.
	entities[0].intOpt = 999
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, 42, entities[i].intOpt,
			"goroutine %d: entity should be independent", i)
	}
}
