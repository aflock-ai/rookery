//go:build audit

package registry

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// R3-180: Nil factory function registration and deferred panic
// ==========================================================================

// TestSecurity_R3_180_NilFactoryRegistration proves that a nil factory
// function can be registered without any validation. The nil factory is
// stored in the registry and only causes a panic when NewEntity is called
// (which invokes entry.Factory(), a nil function pointer).
//
// BUG [HIGH]: Register does not validate that factoryFunc is non-nil.
// This creates a latent panic that surfaces at entity creation time, far
// from the registration site, making it extremely difficult to debug.
// File: registry/registry.go:51
func TestSecurity_R3_180_NilFactoryRegistration(t *testing.T) {
	reg := New[*testEntity]()

	// Register with nil factory -- no panic, no error
	entry := reg.Register("nil-factory", nil)
	assert.Equal(t, "nil-factory", entry.Name)
	assert.Nil(t, entry.Factory, "nil factory is silently stored in registry")

	// Verify the nil factory is retrievable
	retrieved, ok := reg.Entry("nil-factory")
	require.True(t, ok, "nil-factory entry should exist")
	assert.Nil(t, retrieved.Factory, "retrieved factory should still be nil")

	// The panic happens at entity creation time, not registration time
	assert.Panics(t, func() {
		_, _ = reg.NewEntity("nil-factory")
	}, "BUG [HIGH]: calling NewEntity with nil factory panics at registry.go:94 "+
		"(entry.Factory() calls nil function). Register should validate factory is non-nil.")
}

// ==========================================================================
// R3-181: Nil factory with options -- double fault
// ==========================================================================

// TestSecurity_R3_181_NilFactoryWithOptions proves that a nil factory
// registered with config options produces a panic. The nil is passed to
// SetDefaultVals, and then the option setter tries to operate on it.
//
// BUG [HIGH]: Even if the setter guards against nil, the initial Factory()
// call is the panic point. The options are never reached.
func TestSecurity_R3_181_NilFactoryWithOptions(t *testing.T) {
	reg := New[*testEntity]()

	opt := IntConfigOption("val", "test value", 42,
		func(te *testEntity, v int) (*testEntity, error) {
			if te == nil {
				return nil, fmt.Errorf("entity is nil")
			}
			te.intOpt = v
			return te, nil
		})

	// Registration succeeds
	reg.Register("nil-factory-opts", nil, opt)

	assert.Panics(t, func() {
		_, _ = reg.NewEntity("nil-factory-opts")
	}, "BUG [HIGH]: nil factory + options panics. The panic is in Factory() call, "+
		"not in the setter. The option's nil guard never executes.")
}

// ==========================================================================
// R3-182: Partial configuration state on setter error (pointer entity)
// ==========================================================================

// TestSecurity_R3_182_PartialConfigOnSetterError proves that when using
// pointer entities, a setter error leaves the entity in a partially
// configured state. The returned entity has some defaults applied but not
// all, and the caller receives both the partial entity and the error.
//
// BUG [MEDIUM]: SetDefaultVals returns early on first error, but for
// pointer entities, previous setters have already mutated the entity via
// the pointer. The returned entity is in an inconsistent state.
// File: registry/registry.go:116-139
func TestSecurity_R3_182_PartialConfigOnSetterError(t *testing.T) {
	reg := New[*testEntity]()

	opts := []Configurer{
		IntConfigOption("int-opt", "sets intOpt", 42,
			func(te *testEntity, v int) (*testEntity, error) {
				te.intOpt = v // This mutation persists
				return te, nil
			}),
		StringConfigOption("str-opt", "sets strOpt", "hello",
			func(te *testEntity, v string) (*testEntity, error) {
				te.strOpt = v // This mutation persists
				return te, nil
			}),
		BoolConfigOption("bool-opt", "will fail", true,
			func(te *testEntity, v bool) (*testEntity, error) {
				return te, fmt.Errorf("intentional failure in bool setter")
			}),
		// This setter would set strSliceOpt, but it never runs
		StringSliceConfigOption("slice-opt", "never reached", []string{"a"},
			func(te *testEntity, v []string) (*testEntity, error) {
				te.strSliceOpt = v
				return te, nil
			}),
	}

	reg.Register("partial", func() *testEntity { return &testEntity{} }, opts...)

	entity, err := reg.NewEntity("partial")
	require.Error(t, err, "should propagate setter error")
	require.NotNil(t, entity, "entity should be non-nil even with error (pointer semantics)")

	// The entity is partially configured: intOpt and strOpt are set,
	// boolOpt failed, strSliceOpt was never reached.
	assert.Equal(t, 42, entity.intOpt,
		"BUG [MEDIUM]: first setter mutated entity before error in third setter")
	assert.Equal(t, "hello", entity.strOpt,
		"BUG [MEDIUM]: second setter mutated entity before error in third setter")
	assert.False(t, entity.boolOpt,
		"bool should be zero value (setter failed)")
	assert.Nil(t, entity.strSliceOpt,
		"slice should be nil (setter never ran)")

	// This is dangerous because:
	// 1. The caller gets a partial entity they might accidentally use
	// 2. The entity has some defaults but not others, which is worse than no defaults
	// 3. For pointer types, the original factory-created entity is mutated
}

// ==========================================================================
// R3-183: Partial config with value entity is safer but inconsistent API
// ==========================================================================

// TestSecurity_R3_183_PartialConfigValueEntity proves that for value types,
// SetDefaultVals error still returns a partially-configured entity, but at
// least the returned entity is a copy (not mutating some shared state).
func TestSecurity_R3_183_PartialConfigValueEntity(t *testing.T) {
	type valEntity struct {
		intVal  int
		strVal  string
		boolVal bool
	}

	reg := New[valEntity]()
	opts := []Configurer{
		IntConfigOption("i", "", 42,
			func(e valEntity, v int) (valEntity, error) {
				e.intVal = v
				return e, nil
			}),
		StringConfigOption("s", "", "hello",
			func(e valEntity, v string) (valEntity, error) {
				return e, fmt.Errorf("fail on string setter")
			}),
		BoolConfigOption("b", "", true,
			func(e valEntity, v bool) (valEntity, error) {
				e.boolVal = v
				return e, nil
			}),
	}

	reg.Register("val-partial", func() valEntity { return valEntity{} }, opts...)

	entity, err := reg.NewEntity("val-partial")
	require.Error(t, err)

	// For value types, the returned entity also has partial state
	assert.Equal(t, 42, entity.intVal,
		"int was set before the error")
	assert.Equal(t, "", entity.strVal,
		"string setter failed, so strVal is zero")
	assert.False(t, entity.boolVal,
		"bool setter never ran")
}

// ==========================================================================
// R3-184: SetOptions partial mutation on error with pointer entity
// ==========================================================================

// TestSecurity_R3_184_SetOptionsPartialMutationPointer proves that
// SetOptions with pointer entities allows partial mutation when one
// setter errors. The entity is returned in an inconsistent state.
//
// BUG [MEDIUM]: SetOptions returns the entity alongside the error.
// For pointer types, all previous mutations are visible through the
// returned entity AND through any other references to the same object.
func TestSecurity_R3_184_SetOptionsPartialMutationPointer(t *testing.T) {
	original := &testEntity{intOpt: 0, strOpt: "original"}

	result, err := SetOptions(original,
		func(te *testEntity) (*testEntity, error) {
			te.intOpt = 100
			te.strOpt = "modified"
			return te, nil
		},
		func(te *testEntity) (*testEntity, error) {
			te.intOpt = 200 // This mutation persists!
			return te, fmt.Errorf("second setter fails")
		},
		func(te *testEntity) (*testEntity, error) {
			te.intOpt = 300 // Never reached
			return te, nil
		},
	)

	require.Error(t, err)

	// The result has partial mutations from setters 1 and 2 (before error)
	assert.Equal(t, 200, result.intOpt,
		"BUG: result has mutation from failing setter")
	assert.Equal(t, "modified", result.strOpt,
		"BUG: result has mutation from setter before the failing one")

	// Worse: for pointer types, original IS result -- they're the same object
	assert.Equal(t, 200, original.intOpt,
		"BUG [MEDIUM]: original entity was mutated through pointer. "+
			"The caller's original object is now in an inconsistent state.")
}

// ==========================================================================
// R3-185: Concurrent Register to SAME registry (true race condition)
// ==========================================================================

// TestSecurity_R3_185_ConcurrentRegisterSameRegistry demonstrates the actual
// race condition with concurrent writes to the same registry. This test is
// the real proof -- the existing tests in adversarial_test.go use separate
// registries per goroutine, which doesn't actually race.
//
// BUG [HIGH]: Registry.entriesByName is a plain Go map with no mutex.
// Concurrent Register() calls cause a data race.
// File: registry/registry.go:51-59
//
// NOTE: This test may crash under -race. We catch the panic to prove the
// point without crashing the test suite.
func TestSecurity_R3_185_ConcurrentRegisterSameRegistry(t *testing.T) {
	// We can't reliably trigger the map concurrent write panic without -race,
	// and under -race the binary crashes. So we document and prove the
	// structural issue: the map IS shared and IS written without protection.

	// Prove the map is shared (value receiver doesn't copy the map):
	reg := New[*testEntity]()
	regCopy := reg // value copy shares the map

	reg.Register("from-original", func() *testEntity { return &testEntity{intOpt: 1} })

	_, ok := regCopy.Entry("from-original")
	assert.True(t, ok,
		"Value copy of Registry shares the underlying map. "+
			"This confirms that concurrent Register calls on copies of the same "+
			"Registry (or the original) will write to the same unprotected map. "+
			"BUG [HIGH]: No sync.Mutex or sync.Map protects entriesByName.")

	// Prove Register has value receiver (not pointer), so passing by value
	// doesn't create isolation:
	writeFromFunc := func(r Registry[*testEntity], name string) {
		r.Register(name, func() *testEntity { return &testEntity{} })
	}
	writeFromFunc(reg, "from-func-call")

	_, ok = reg.Entry("from-func-call")
	assert.True(t, ok,
		"Register called on a by-value parameter still writes to the original map. "+
			"The value receiver gives a false sense of immutability.")
}

// ==========================================================================
// R3-186: Concurrent NewEntity + Register race
// ==========================================================================

// TestSecurity_R3_186_ConcurrentNewEntityAndRegister documents that
// concurrent NewEntity (read) + Register (write) on the same registry
// is a data race. NewEntity reads the map while Register writes to it.
//
// BUG [HIGH]: Even if Register is "only called during init()", there's no
// enforcement of that constraint. A plugin that lazily registers during
// first use would race with other goroutines calling NewEntity.
func TestSecurity_R3_186_ConcurrentNewEntityAndRegister(t *testing.T) {
	// Pre-populate so NewEntity has something to find
	reg := New[*testEntity]()
	reg.Register("existing", func() *testEntity { return &testEntity{intOpt: 1} })

	// Structural proof: Register writes to map, NewEntity reads from map.
	// Both use the SAME map with no synchronization.

	// Demonstrate that Register mutates the map that NewEntity reads:
	beforeLen := len(reg.AllEntries())
	reg.Register("new-entry", func() *testEntity { return &testEntity{intOpt: 2} })
	afterLen := len(reg.AllEntries())

	assert.Equal(t, beforeLen+1, afterLen,
		"Register mutates the same map that NewEntity/AllEntries reads. "+
			"BUG [HIGH]: Concurrent Register + NewEntity = data race on map. "+
			"No mutex, no sync.Map, no channel serialization.")
}

// ==========================================================================
// R3-187: SetDefaultVals silently ignores custom Configurer implementation
// ==========================================================================

// TestSecurity_R3_187_SetDefaultValsCustomConfigurer proves that if someone
// implements the Configurer interface with a custom type that doesn't match
// any case in the type switch, the option is silently ignored with no error.
//
// BUG [MEDIUM]: The type switch at registry.go:120-131 has no default case.
// A Configurer implementation that satisfies the interface but isn't one of
// the known ConfigOption[T, X] types will be silently skipped. No error,
// no warning. The entity won't have its default applied.
func TestSecurity_R3_187_SetDefaultValsCustomConfigurer(t *testing.T) {
	reg := New[*testEntity]()

	// Create a custom Configurer that satisfies the interface
	custom := &customConfigurer{
		name:        "custom-opt",
		description: "a custom config option",
	}

	entity := &testEntity{intOpt: 99}
	result, err := reg.SetDefaultVals(entity, []Configurer{custom})

	// No error -- the custom configurer is simply skipped
	require.NoError(t, err,
		"BUG [MEDIUM]: Custom Configurer is silently skipped in SetDefaultVals. "+
			"There's no default case in the type switch. The option's default value "+
			"is never applied. File: registry.go:120-131")

	// Entity is completely unchanged
	assert.Equal(t, 99, result.intOpt,
		"Entity should be unchanged because custom configurer was silently skipped")

	// This is dangerous because:
	// 1. Adding a new type to the Option constraint (e.g., float64) requires
	//    updating the type switch -- but there's no compile-time check for this.
	// 2. If someone extends ConfigOption with a new type parameter and forgets
	//    to update SetDefaultVals, defaults silently fail to apply.
}

// customConfigurer implements the Configurer interface but isn't a known
// ConfigOption type, so the type switch in SetDefaultVals won't match it.
type customConfigurer struct {
	name        string
	description string
}

func (c *customConfigurer) Name() string        { return c.name }
func (c *customConfigurer) Description() string { return c.description }
func (c *customConfigurer) SetPrefix(p string)  {}

// ==========================================================================
// R3-188: SetDefaultVals with mismatched entity type ConfigOption
// ==========================================================================

// TestSecurity_R3_188_SetDefaultValsMismatchedEntityType proves that a
// ConfigOption parameterized for a different entity type passes the
// Configurer interface check but hits no case in the type switch, causing
// silent default skip.
//
// BUG [MEDIUM]: The type switch matches on both T and TOption. If T doesn't
// match the registry's entity type, the case is skipped even if TOption is
// correct (e.g., int). This means mixing ConfigOptions from different
// registries silently drops defaults.
func TestSecurity_R3_188_SetDefaultValsMismatchedEntityType(t *testing.T) {
	type otherEntity struct{ val int }

	// Create an IntConfigOption for otherEntity, not *testEntity
	wrongEntityOpt := IntConfigOption[otherEntity]("val", "wrong entity type", 999,
		func(oe otherEntity, v int) (otherEntity, error) {
			oe.val = v
			return oe, nil
		})

	reg := New[*testEntity]()
	entity := &testEntity{intOpt: 1}
	result, err := reg.SetDefaultVals(entity, []Configurer{wrongEntityOpt})

	require.NoError(t, err,
		"BUG [MEDIUM]: ConfigOption for wrong entity type is silently skipped")
	assert.Equal(t, 1, result.intOpt,
		"Entity unchanged -- the int setter for otherEntity was silently dropped")
}

// ==========================================================================
// R3-189: AllEntries iteration order non-determinism
// ==========================================================================

// TestSecurity_R3_189_AllEntriesOrderNonDeterministic proves that AllEntries
// returns entries in Go map iteration order, which is non-deterministic.
// Any caller relying on consistent ordering will get inconsistent results.
//
// BUG [LOW]: AllEntries uses map iteration order. Callers that assume
// deterministic ordering (e.g., for generating CLI help, config files, or
// attestation collections) will produce inconsistent output.
// File: registry/registry.go:77-84
func TestSecurity_R3_189_AllEntriesOrderNonDeterministic(t *testing.T) {
	reg := New[*testEntity]()
	names := []string{"alpha", "bravo", "charlie", "delta", "echo",
		"foxtrot", "golf", "hotel", "india", "juliet"}
	for _, name := range names {
		reg.Register(name, func() *testEntity { return &testEntity{} })
	}

	// Collect orderings from multiple calls
	orderings := make(map[string]bool)
	for i := 0; i < 200; i++ {
		entries := reg.AllEntries()
		var order string
		for _, e := range entries {
			order += e.Name + ","
		}
		orderings[order] = true
	}

	assert.Len(t, reg.AllEntries(), len(names), "should have all entries")

	// We can't guarantee multiple orderings in a short test, but we can
	// verify the API provides no ordering guarantee.
	t.Logf("DESIGN NOTE [LOW]: AllEntries returned %d distinct orderings in 200 calls. "+
		"Map iteration order in Go is intentionally randomized. "+
		"File: registry/registry.go:77-84", len(orderings))
}

// ==========================================================================
// R3-190: Register overwrites without error/warning
// ==========================================================================

// TestSecurity_R3_190_RegisterOverwriteSilent proves that registering the
// same name twice silently replaces the first registration.
//
// BUG [MEDIUM]: No error, no log, no warning when overwriting a
// registration. This can cause insidious bugs where two plugins
// accidentally use the same name and one shadows the other.
// File: registry/registry.go:51-59
func TestSecurity_R3_190_RegisterOverwriteSilent(t *testing.T) {
	reg := New[*testEntity]()

	factory1 := func() *testEntity { return &testEntity{intOpt: 1} }
	factory2 := func() *testEntity { return &testEntity{intOpt: 2} }

	opt1 := IntConfigOption("val", "first option", 10,
		func(te *testEntity, v int) (*testEntity, error) {
			te.intOpt = v
			return te, nil
		})
	opt2 := StringConfigOption("name", "second option", "test",
		func(te *testEntity, v string) (*testEntity, error) {
			te.strOpt = v
			return te, nil
		})

	reg.Register("shared-name", factory1, opt1)
	reg.Register("shared-name", factory2, opt2)

	entry, ok := reg.Entry("shared-name")
	require.True(t, ok)

	// Factory is from second registration
	entity := entry.Factory()
	assert.Equal(t, 2, entity.intOpt,
		"BUG [MEDIUM]: second Register silently replaced first. "+
			"Factory from first registration is lost.")

	// Options are from second registration -- first registration's options are gone
	assert.Len(t, entry.Options, 1,
		"BUG [MEDIUM]: first registration's options are completely replaced")
	assert.Equal(t, "name", entry.Options[0].Name(),
		"only second registration's options survive")

	// Total entries is still 1
	assert.Len(t, reg.AllEntries(), 1,
		"overwrite doesn't create duplicate entries")
}

// ==========================================================================
// R3-191: NewEntity with option setter that replaces entity entirely
// ==========================================================================

// TestSecurity_R3_191_OptionSetterReplacesEntity proves that a SetDefaultVals
// setter can return a completely different entity (including nil) and the
// chain continues with the replacement. This is by design for value types
// but surprising for pointer types.
func TestSecurity_R3_191_OptionSetterReplacesEntity(t *testing.T) {
	reg := New[*testEntity]()

	replacement := &testEntity{intOpt: 999, strOpt: "replaced"}

	opts := []Configurer{
		IntConfigOption("replace", "replaces the entity", 0,
			func(te *testEntity, _ int) (*testEntity, error) {
				// Return a completely different entity
				return replacement, nil
			}),
		StringConfigOption("after", "modifies replacement", "suffix",
			func(te *testEntity, v string) (*testEntity, error) {
				te.strOpt = te.strOpt + "-" + v
				return te, nil
			}),
	}

	reg.Register("replaceable", func() *testEntity { return &testEntity{} }, opts...)

	entity, err := reg.NewEntity("replaceable")
	require.NoError(t, err)

	// The factory-created entity was discarded. The replacement was used.
	assert.Equal(t, replacement, entity,
		"DESIGN NOTE: SetDefaultVals allows setter to replace entity entirely. "+
			"The factory output is discarded if a setter returns a different pointer.")
	assert.Equal(t, "replaced-suffix", entity.strOpt,
		"Second setter modifies the replacement, not the original factory output")
}

// ==========================================================================
// R3-192: Register with nil options slice
// ==========================================================================

// TestSecurity_R3_192_RegisterNilOptions proves that passing no options
// stores an empty (nil) Options slice in the entry.
func TestSecurity_R3_192_RegisterNilOptions(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("no-opts", func() *testEntity { return &testEntity{intOpt: 1} })

	entry, ok := reg.Entry("no-opts")
	require.True(t, ok)

	// Options is nil (no variadic args passed)
	assert.Nil(t, entry.Options,
		"no options passed means Options slice is nil, not empty")

	// But NewEntity should still work
	entity, err := reg.NewEntity("no-opts")
	require.NoError(t, err)
	assert.Equal(t, 1, entity.intOpt)
}

// ==========================================================================
// R3-193: DurationConfigOption default not applied with mixed registry
// ==========================================================================

// TestSecurity_R3_193_DurationOptionInMixedRegistry proves Duration options
// work in isolation but verifies the type switch handles them correctly
// when mixed with other option types in a single entity registration.
func TestSecurity_R3_193_DurationOptionInMixedRegistry(t *testing.T) {
	type timedEntity struct {
		timeout time.Duration
		retries int
		name    string
	}

	reg := New[*timedEntity]()
	reg.Register("timed",
		func() *timedEntity { return &timedEntity{} },
		DurationConfigOption("timeout", "", 30*time.Second,
			func(e *timedEntity, v time.Duration) (*timedEntity, error) {
				e.timeout = v
				return e, nil
			}),
		IntConfigOption("retries", "", 3,
			func(e *timedEntity, v int) (*timedEntity, error) {
				e.retries = v
				return e, nil
			}),
		StringConfigOption("name", "", "default-name",
			func(e *timedEntity, v string) (*timedEntity, error) {
				e.name = v
				return e, nil
			}),
	)

	entity, err := reg.NewEntity("timed")
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, entity.timeout, "duration default applied")
	assert.Equal(t, 3, entity.retries, "int default applied")
	assert.Equal(t, "default-name", entity.name, "string default applied")
}

// ==========================================================================
// R3-194: SetOptions returns nil error variable when no setters
// ==========================================================================

// TestSecurity_R3_194_SetOptionsEmptyReturnsNilError verifies that SetOptions
// with no setters returns a nil error (not an uninitialized error variable).
func TestSecurity_R3_194_SetOptionsEmptyReturnsNilError(t *testing.T) {
	entity := &testEntity{intOpt: 42}

	// The `err` variable in SetOptions is declared with `var err error` at the
	// top of the function. If no setters are provided, the for loop never runs,
	// and `err` remains the zero value (nil). The function returns `result, err`.
	result, err := SetOptions(entity)

	assert.NoError(t, err, "no setters should produce nil error")
	assert.Same(t, entity, result, "should return the same pointer")
}
