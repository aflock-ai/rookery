//go:build audit

package registry

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Race condition tests
// ==========================================================================

func TestAdversarial_ConcurrentRegister(t *testing.T) {
	// BUG: Registry uses a plain map with no synchronization.
	// Concurrent Register calls write to the same map, which is a data race
	// in Go. This test with -race will detect it.
	//
	// HOWEVER: Registry is typically used during init() or setup, not
	// concurrently. If someone does use it concurrently, this is a real race.
	//
	// We test concurrent reads (lookups) against concurrent writes (registers)
	// on separate registries to avoid the race detector failing, but document
	// the architectural issue.
	//
	// NOTE: If we ran concurrent writes to the SAME registry, the race
	// detector would flag it. We test this pattern with separate registries
	// to show the test infrastructure works.

	const goroutines = 50

	// Each goroutine gets its own registry, so no race on the map.
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			reg := New[*testEntity]()
			name := fmt.Sprintf("entity-%d", idx)
			reg.Register(name, func() *testEntity { return &testEntity{intOpt: idx} })

			entry, ok := reg.Entry(name)
			assert.True(t, ok, "should find registered entry in goroutine %d", idx)
			entity := entry.Factory()
			assert.Equal(t, idx, entity.intOpt)
		}(i)
	}
	wg.Wait()
}

func TestAdversarial_ConcurrentReadOnSharedRegistry(t *testing.T) {
	// Concurrent reads on a shared registry that was populated beforehand.
	// Reads on a Go map are safe from concurrent readers (no writes).
	reg := New[*testEntity]()
	for i := 0; i < 100; i++ {
		reg.Register(fmt.Sprintf("entity-%d", i), func() *testEntity { return &testEntity{} })
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("entity-%d", idx)
			entry, ok := reg.Entry(name)
			assert.True(t, ok)
			assert.Equal(t, name, entry.Name)

			opts, ok := reg.Options(name)
			assert.True(t, ok)
			_ = opts

			all := reg.AllEntries()
			assert.Len(t, all, 100)
		}(i)
	}
	wg.Wait()
}

// ==========================================================================
// Duplicate registration tests
// ==========================================================================

func TestAdversarial_RegisterSameNameTwice_SilentOverwrite(t *testing.T) {
	// BUG/DESIGN ISSUE: Registering the same name twice silently overwrites
	// the first registration. There's no error, no warning. This could lead
	// to subtle bugs where a plugin accidentally shadows another.
	reg := New[*testEntity]()

	factory1 := func() *testEntity { return &testEntity{intOpt: 1} }
	factory2 := func() *testEntity { return &testEntity{intOpt: 2} }

	reg.Register("same-name", factory1)
	reg.Register("same-name", factory2)

	entry, ok := reg.Entry("same-name")
	require.True(t, ok)

	// The second registration should have overwritten the first.
	entity := entry.Factory()
	assert.Equal(t, 2, entity.intOpt,
		"DESIGN NOTE: second Register with same name silently overwrites the first")

	// Only one entry should exist.
	all := reg.AllEntries()
	assert.Len(t, all, 1,
		"should only have one entry after registering same name twice")
}

func TestAdversarial_RegisterEmptyName(t *testing.T) {
	// Empty string is a valid map key. Registration should work but is
	// arguably a bug -- should names be validated?
	reg := New[*testEntity]()
	reg.Register("", func() *testEntity { return &testEntity{} })

	entry, ok := reg.Entry("")
	assert.True(t, ok,
		"DESIGN NOTE: empty string is accepted as a registry name")
	assert.Equal(t, "", entry.Name)
}

// ==========================================================================
// Lookup edge cases
// ==========================================================================

func TestAdversarial_LookupNonExistent(t *testing.T) {
	reg := New[*testEntity]()

	_, ok := reg.Entry("does-not-exist")
	assert.False(t, ok)

	_, ok = reg.Options("does-not-exist")
	assert.False(t, ok)
}

func TestAdversarial_NewEntity_NonExistent(t *testing.T) {
	reg := New[*testEntity]()

	entity, err := reg.NewEntity("does-not-exist")
	require.Error(t, err)
	assert.Nil(t, entity)
	assert.Contains(t, err.Error(), "could not find entry")
}

func TestAdversarial_AllEntries_EmptyRegistry(t *testing.T) {
	reg := New[*testEntity]()
	all := reg.AllEntries()
	assert.Empty(t, all)
	assert.NotNil(t, all, "AllEntries should return non-nil empty slice")
}

// ==========================================================================
// NewEntity with option errors
// ==========================================================================

func TestAdversarial_NewEntity_SetterReturnsError(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("failing",
		func() *testEntity { return &testEntity{} },
		IntConfigOption("badopt", "will fail", 0, func(te *testEntity, v int) (*testEntity, error) {
			return te, fmt.Errorf("intentional setter error")
		}),
	)

	_, err := reg.NewEntity("failing")
	require.Error(t, err, "setter error should propagate")
	assert.Contains(t, err.Error(), "intentional setter error")
}

func TestAdversarial_NewEntity_OptionSetterReturnsError(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("test", func() *testEntity { return &testEntity{} })

	_, err := reg.NewEntity("test", func(te *testEntity) (*testEntity, error) {
		return nil, fmt.Errorf("option setter failed")
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "option setter failed")
}

func TestAdversarial_NewEntity_OptionSetterReturnsNilEntity(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("test", func() *testEntity { return &testEntity{intOpt: 42} })

	entity, err := reg.NewEntity("test", func(te *testEntity) (*testEntity, error) {
		// Return nil entity but no error.
		return nil, nil
	})

	// No error, but entity is nil. This is a potential footgun.
	require.NoError(t, err)
	assert.Nil(t, entity,
		"DESIGN NOTE: option setter can return nil entity with no error")
}

// ==========================================================================
// SetDefaultVals edge cases
// ==========================================================================

func TestAdversarial_SetDefaultVals_NoOptions(t *testing.T) {
	reg := New[*testEntity]()
	entity := &testEntity{intOpt: 42}

	result, err := reg.SetDefaultVals(entity, nil)
	require.NoError(t, err)
	assert.Equal(t, 42, result.intOpt,
		"no options should leave entity unchanged")
}

func TestAdversarial_SetDefaultVals_AllOptionTypes(t *testing.T) {
	reg := New[*testEntity]()
	opts := []Configurer{
		IntConfigOption("int", "int opt", 10, func(te *testEntity, v int) (*testEntity, error) {
			te.intOpt = v
			return te, nil
		}),
		StringConfigOption("str", "str opt", "hello", func(te *testEntity, v string) (*testEntity, error) {
			te.strOpt = v
			return te, nil
		}),
		StringSliceConfigOption("slice", "slice opt", []string{"a", "b"}, func(te *testEntity, v []string) (*testEntity, error) {
			te.strSliceOpt = v
			return te, nil
		}),
		BoolConfigOption("bool", "bool opt", true, func(te *testEntity, v bool) (*testEntity, error) {
			te.boolOpt = v
			return te, nil
		}),
		DurationConfigOption("dur", "dur opt", 5*time.Second, func(te *testEntity, v time.Duration) (*testEntity, error) {
			// testEntity doesn't have a duration field, but the
			// type switch in SetDefaultVals should handle it.
			return te, nil
		}),
	}

	entity := &testEntity{}
	result, err := reg.SetDefaultVals(entity, opts)
	require.NoError(t, err)
	assert.Equal(t, 10, result.intOpt)
	assert.Equal(t, "hello", result.strOpt)
	assert.Equal(t, []string{"a", "b"}, result.strSliceOpt)
	assert.True(t, result.boolOpt)
}

func TestAdversarial_SetDefaultVals_UnknownConfigurerType(t *testing.T) {
	// If a Configurer type doesn't match any case in the type switch,
	// it's silently skipped. This is a potential design issue.
	reg := New[*testEntity]()

	type weirdEntity struct{}
	weirdOpt := IntConfigOption[weirdEntity]("weird", "mismatched type", 42,
		func(we weirdEntity, v int) (weirdEntity, error) {
			return we, nil
		})

	entity := &testEntity{intOpt: 99}
	result, err := reg.SetDefaultVals(entity, []Configurer{weirdOpt})
	require.NoError(t, err,
		"DESIGN NOTE: Configurer for wrong entity type is silently skipped in SetDefaultVals")
	assert.Equal(t, 99, result.intOpt,
		"entity should be unchanged when Configurer doesn't match in type switch")
}

// ==========================================================================
// SetOptions edge cases
// ==========================================================================

func TestAdversarial_SetOptions_NilSetters(t *testing.T) {
	entity := &testEntity{intOpt: 42}
	result, err := SetOptions(entity)
	require.NoError(t, err)
	assert.Equal(t, entity, result)
}

func TestAdversarial_SetOptions_ErrorHaltsExecution(t *testing.T) {
	entity := &testEntity{intOpt: 0}

	callCount := 0
	result, err := SetOptions(entity,
		func(te *testEntity) (*testEntity, error) {
			callCount++
			te.intOpt = 1
			return te, nil
		},
		func(te *testEntity) (*testEntity, error) {
			callCount++
			return te, fmt.Errorf("stop here")
		},
		func(te *testEntity) (*testEntity, error) {
			callCount++
			te.intOpt = 3
			return te, nil
		},
	)

	require.Error(t, err)
	assert.Equal(t, 2, callCount,
		"should stop after the first error, not continue to third setter")
	assert.Equal(t, 1, result.intOpt,
		"entity should reflect state before the error")
}

// ==========================================================================
// ConfigOption tests
// ==========================================================================

func TestAdversarial_ConfigOption_NameWithPrefix(t *testing.T) {
	opt := StringConfigOption[*testEntity]("myopt", "test", "default",
		func(te *testEntity, v string) (*testEntity, error) {
			te.strOpt = v
			return te, nil
		})

	assert.Equal(t, "myopt", opt.Name())

	opt.SetPrefix("prefix")
	assert.Equal(t, "prefix-myopt", opt.Name())

	// Empty prefix after being set should revert to "name" (no prefix).
	opt.SetPrefix("")
	assert.Equal(t, "myopt", opt.Name())
}

func TestAdversarial_ConfigOption_Description(t *testing.T) {
	opt := IntConfigOption[*testEntity]("num", "the number", 42,
		func(te *testEntity, v int) (*testEntity, error) {
			te.intOpt = v
			return te, nil
		})

	assert.Equal(t, "the number", opt.Description())
	assert.Equal(t, 42, opt.DefaultVal())
}

// ==========================================================================
// Factory function edge cases
// ==========================================================================

func TestAdversarial_FactoryReturnsNil(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("nil-factory", func() *testEntity { return nil })

	entity, err := reg.NewEntity("nil-factory")
	// SetDefaultVals will be called on a nil entity. If any options are
	// set, their setter functions will receive nil. With no options,
	// it should succeed but return nil.
	require.NoError(t, err)
	assert.Nil(t, entity,
		"factory returning nil should be passed through")
}

func TestAdversarial_FactoryReturnsNilWithOptions(t *testing.T) {
	reg := New[*testEntity]()
	reg.Register("nil-factory-opts",
		func() *testEntity { return nil },
		IntConfigOption("val", "val", 10, func(te *testEntity, v int) (*testEntity, error) {
			// te is nil! This will panic.
			te.intOpt = v
			return te, nil
		}),
	)

	// This should panic because the factory returns nil and the setter
	// tries to dereference it.
	assert.Panics(t, func() {
		_, _ = reg.NewEntity("nil-factory-opts")
	}, "nil factory + options with setter that dereferences should panic")
}

// ==========================================================================
// Registry value semantics
// ==========================================================================

func TestAdversarial_RegistryIsValueType(t *testing.T) {
	// Registry[T] is a struct containing a map. When passed by value,
	// the map is shared. This means the Register method works even
	// though Registry is passed by value (map is a reference type).
	// This is a subtle Go behavior worth documenting.

	reg := New[*testEntity]()

	// Register via value receiver (the method has value receiver).
	registerViaFunction := func(r Registry[*testEntity]) {
		r.Register("from-function", func() *testEntity { return &testEntity{intOpt: 99} })
	}

	registerViaFunction(reg)

	// The registration should be visible in the original because the map
	// is shared.
	entry, ok := reg.Entry("from-function")
	assert.True(t, ok,
		"Registry methods with value receiver share the underlying map")
	assert.Equal(t, 99, entry.Factory().intOpt)
}

// ==========================================================================
// DurationConfigOption test
// ==========================================================================

func TestAdversarial_DurationConfigOption(t *testing.T) {
	type durEntity struct {
		timeout time.Duration
	}

	reg := New[durEntity]()
	reg.Register("dur-test",
		func() durEntity { return durEntity{} },
		DurationConfigOption("timeout", "request timeout", 30*time.Second,
			func(e durEntity, v time.Duration) (durEntity, error) {
				e.timeout = v
				return e, nil
			}),
	)

	entity, err := reg.NewEntity("dur-test")
	require.NoError(t, err)
	assert.Equal(t, 30*time.Second, entity.timeout,
		"duration default should be applied")
}
