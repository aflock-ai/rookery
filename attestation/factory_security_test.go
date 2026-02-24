//go:build audit

package attestation

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test helper ---

type securityAttestor struct {
	name          string
	predicateType string
	runType       RunType
	marker        int // used to distinguish instances
}

func (a *securityAttestor) Name() string                     { return a.name }
func (a *securityAttestor) Type() string                     { return a.predicateType }
func (a *securityAttestor) RunType() RunType                 { return a.runType }
func (a *securityAttestor) Schema() *jsonschema.Schema       { return jsonschema.Reflect(a) }
func (a *securityAttestor) Attest(*AttestationContext) error { return nil }

// ==========================================================================
// R3-300: PredicateType collision silently shadows attestor in type map
// ==========================================================================

// TestSecurity_R3_300_PredicateTypeCollisionShadows proves that two
// attestors with DIFFERENT names but the SAME predicateType silently
// overwrite each other in attestationsByType. Both remain in the name
// registry (attestorRegistry), but only the last registration is
// reachable by type. The first attestor's type mapping is irrecoverably
// lost with no error or warning.
//
// BUG [HIGH]: RegisterAttestation writes to attestationsByType[predicateType]
// without checking for existing entries. If two plugins register the same
// predicateType with different names, the first plugin's type entry is
// silently replaced. FactoryByType will return the wrong attestor. The
// name registry and type registry become inconsistent.
// File: factory.go:98-102
func TestSecurity_R3_300_PredicateTypeCollisionShadows(t *testing.T) {
	firstType := "https://test/r3-300-collision"
	first := &securityAttestor{
		name:          "r3-300-first",
		predicateType: firstType,
		runType:       PreMaterialRunType,
		marker:        1,
	}
	second := &securityAttestor{
		name:          "r3-300-second",
		predicateType: firstType, // SAME predicate type!
		runType:       MaterialRunType,
		marker:        2,
	}

	RegisterAttestation(first.name, first.predicateType, first.runType,
		func() Attestor { return first })
	RegisterAttestation(second.name, second.predicateType, second.runType,
		func() Attestor { return second })

	// Both are in the name registry
	_, okFirst := FactoryByName("r3-300-first")
	_, okSecond := FactoryByName("r3-300-second")
	require.True(t, okFirst, "first attestor should be in name registry")
	require.True(t, okSecond, "second attestor should be in name registry")

	// But type lookup returns only the SECOND one
	factory, ok := FactoryByType(firstType)
	require.True(t, ok, "predicate type should be found")
	att := factory()

	assert.Equal(t, "r3-300-second", att.Name(),
		"BUG [HIGH]: FactoryByType returns second attestor, not first. "+
			"First attestor is in name registry but unreachable by type. "+
			"The name registry and type registry are now inconsistent.")

	// The first attestor's type mapping is completely gone
	// There is NO way to retrieve the first attestor by its predicate type
	t.Logf("BUG [HIGH]: Two attestors with different names registered the same "+
		"predicateType %q. attestationsByType silently stores only the last one. "+
		"The first attestor's type mapping is irrecoverably lost. "+
		"File: factory.go:100", firstType)
}

// ==========================================================================
// R3-301: GetAttestors options lookup misroutes when found by type
// ==========================================================================

// TestSecurity_R3_301_GetAttestorsOptionsMisroute proves that when
// GetAttestors looks up an attestor by its predicate type URI, the
// subsequent AttestorOptions call uses the type URI as the lookup key.
// AttestorOptions first tries attestorRegistry.Entry(typeURI), which
// searches by NAME -- this fails because the registry is keyed by name,
// not type. It then falls through to attestationsByType[typeURI], which
// may return options from a DIFFERENT registration if the type was
// overwritten by RegisterLegacyAlias or a duplicate predicateType.
//
// BUG [MEDIUM]: GetAttestors at factory.go:157-158 calls
// AttestorOptions(nameOrType) where nameOrType is the user-supplied
// string. When the factory was found via FactoryByType (not FactoryByName),
// the options lookup uses the type URI against the NAME-indexed registry,
// which is always a miss. The fallback to attestationsByType works but
// is fragile -- it depends on the type mapping not having been altered
// by RegisterLegacyAlias.
// File: factory.go:146-168, 170-177
func TestSecurity_R3_301_GetAttestorsOptionsMisroute(t *testing.T) {
	// Register an attestor with a known name, type, and options
	testName := "r3-301-attestor"
	testType := "https://test/r3-301-type"
	optSetCount := 0

	opt := registry.IntConfigOption[Attestor](
		"r3-301-opt",
		"test option",
		42,
		func(a Attestor, val int) (Attestor, error) {
			optSetCount++
			return a, nil
		},
	)

	RegisterAttestation(testName, testType, ExecuteRunType,
		func() Attestor {
			return &securityAttestor{
				name:          testName,
				predicateType: testType,
				runType:       ExecuteRunType,
			}
		},
		opt,
	)

	// Lookup by NAME -- options should be found in attestorRegistry
	optsByName := AttestorOptions(testName)
	assert.NotNil(t, optsByName, "options should be found when looking up by name")
	assert.Len(t, optsByName, 1, "should have 1 option when looking up by name")

	// Lookup by TYPE URI -- options go through the fallback path
	optsByType := AttestorOptions(testType)
	// This works ONLY because attestationsByType[testType] still has the
	// original entry. But the primary path (attestorRegistry.Entry(typeURI))
	// fails because the registry is keyed by name, not type.
	assert.NotNil(t, optsByType, "options should be found when looking up by type (via fallback)")

	// Now demonstrate the fragility: if we register a legacy alias that
	// maps a different type to the same current type, the options lookup
	// by the original type still works, but the alias type's options are
	// whatever was in the entry at alias registration time.
	legacyType := "https://legacy/r3-301-type"
	RegisterLegacyAlias(legacyType, testType)

	// The legacy type inherits the entry from registration time
	legacyOpts := AttestorOptions(legacyType)
	assert.NotNil(t, legacyOpts,
		"legacy alias should inherit options from the entry at registration time")

	// Key insight: GetAttestors uses FactoryByName first, then FactoryByType.
	// When using FactoryByType, the nameOrType variable is a TYPE URI.
	// AttestorOptions then tries attestorRegistry.Entry(TYPE_URI) which misses,
	// and falls through to attestationsByType[TYPE_URI].
	//
	// This means: for type-based lookups, the options come from attestationsByType,
	// NOT from the name registry. If these diverge (which can happen via
	// RegisterLegacyAlias or duplicate predicateType registration), the wrong
	// options will be applied to the attestor.

	t.Logf("BUG [MEDIUM]: AttestorOptions uses dual lookup (name registry then type map). " +
		"When GetAttestors resolves by type, the name registry lookup always misses because " +
		"it's searching for a type URI in a name-indexed map. The fallback to attestationsByType " +
		"works but is fragile and can diverge from the name registry. File: factory.go:170-177")
}

// ==========================================================================
// R3-302: RegisterAttestationWithTypes with empty types slice
// ==========================================================================

// TestSecurity_R3_302_RegisterWithEmptyTypesSlice proves that calling
// RegisterAttestationWithTypes with an empty predicateTypes slice
// registers the attestor in the name registry and attestationsByRun,
// but creates NO entry in attestationsByType. The attestor is reachable
// by name but NOT by type. No error or warning is produced.
//
// BUG [MEDIUM]: RegisterAttestationWithTypes does not validate that
// predicateTypes is non-empty. An empty slice means the attestor has
// no type mapping, making it invisible to FactoryByType. This is a
// silent configuration error.
// File: factory.go:104-110
func TestSecurity_R3_302_RegisterWithEmptyTypesSlice(t *testing.T) {
	name := "r3-302-no-types"
	RegisterAttestationWithTypes(name, []string{}, ExecuteRunType,
		func() Attestor {
			return &securityAttestor{
				name:    name,
				runType: ExecuteRunType,
				marker:  302,
			}
		},
	)

	// Reachable by name
	factory, ok := FactoryByName(name)
	require.True(t, ok, "should be in name registry")
	att := factory()
	assert.Equal(t, name, att.Name())

	// NOT reachable by any type -- there's no type mapping
	// The attestor has no predicateType entry in attestationsByType at all
	// A user trying to look up this attestor by its type will get not-found

	t.Logf("BUG [MEDIUM]: RegisterAttestationWithTypes with empty predicateTypes " +
		"creates an attestor that is in the name registry but has NO type mapping. " +
		"FactoryByType will never find it. No error produced. File: factory.go:104-110")
}

// ==========================================================================
// R3-303: RegisterLegacyAlias silently no-ops for unknown current type
// ==========================================================================

// TestSecurity_R3_303_LegacyAliasSilentNoOp proves that
// RegisterLegacyAlias silently does nothing if the currentType is not
// in attestationsByType. No error, no warning. The caller has no way
// to know the alias was not created.
//
// BUG [MEDIUM]: RegisterLegacyAlias at factory.go:187-193 checks for
// the current type but returns silently if not found. In a startup
// sequence where RegisterLegacyAliases() is called before all attestors
// have registered (e.g., import order issues), aliases will silently
// fail to be created. There's no mechanism to detect this.
// File: factory.go:187-193
func TestSecurity_R3_303_LegacyAliasSilentNoOp(t *testing.T) {
	unknownCurrent := "https://test/r3-303-does-not-exist"
	legacyType := "https://legacy/r3-303-alias"

	// This should do nothing, silently
	RegisterLegacyAlias(legacyType, unknownCurrent)

	// The legacy alias was NOT created
	_, ok := FactoryByType(legacyType)
	assert.False(t, ok,
		"BUG [MEDIUM]: RegisterLegacyAlias silently did nothing because the "+
			"currentType doesn't exist in attestationsByType. No error was returned. "+
			"If this happens due to import order (RegisterLegacyAliases called before "+
			"all init() functions complete), legacy type resolution silently breaks. "+
			"File: factory.go:187-193")
}

// ==========================================================================
// R3-304: Name/Type/RunType triple has inconsistent overwrite semantics
// ==========================================================================

// TestSecurity_R3_304_InconsistentTripleOverwrite proves that registering
// two attestors where only SOME of the name/type/run triple overlap
// creates an inconsistent state across the three maps. The name registry,
// type map, and run map can point to different attestors for what the
// caller expects to be a single logical entity.
//
// BUG [HIGH]: RegisterAttestation writes to three independent maps with
// no transactional guarantee. If attestor A registers (name="x",
// type="t1", run=Execute) and attestor B registers (name="x", type="t2",
// run=Execute), then:
// - Name registry: "x" -> B (overwritten)
// - attestationsByType["t1"] -> A (STALE -- points to old entry)
// - attestationsByType["t2"] -> B (new)
// - attestationsByRun[Execute] -> B (overwritten)
//
// The stale entry in attestationsByType["t1"] still points to A's factory,
// even though A's name registration was overwritten by B.
// File: factory.go:98-102
func TestSecurity_R3_304_InconsistentTripleOverwrite(t *testing.T) {
	name := "r3-304-shared-name"
	typeA := "https://test/r3-304-type-a"
	typeB := "https://test/r3-304-type-b"

	attestorA := &securityAttestor{
		name:          name,
		predicateType: typeA,
		runType:       PreMaterialRunType,
		marker:        1,
	}
	attestorB := &securityAttestor{
		name:          name,
		predicateType: typeB,
		runType:       PreMaterialRunType,
		marker:        2,
	}

	RegisterAttestation(name, typeA, PreMaterialRunType,
		func() Attestor { return attestorA })
	RegisterAttestation(name, typeB, PreMaterialRunType,
		func() Attestor { return attestorB })

	// Name registry points to B (last writer wins)
	factoryByName, ok := FactoryByName(name)
	require.True(t, ok)
	attByName := factoryByName()
	sa, ok := attByName.(*securityAttestor)
	require.True(t, ok)
	assert.Equal(t, 2, sa.marker,
		"name registry should point to B (second registration)")

	// attestationsByType["t2"] points to B (correct)
	factoryByTypeB, ok := FactoryByType(typeB)
	require.True(t, ok)
	attByTypeB := factoryByTypeB()
	saB, ok := attByTypeB.(*securityAttestor)
	require.True(t, ok)
	assert.Equal(t, 2, saB.marker,
		"type B should point to B")

	// attestationsByType["t1"] STILL points to A (STALE!)
	factoryByTypeA, ok := FactoryByType(typeA)
	require.True(t, ok, "type A entry was never removed from attestationsByType")
	attByTypeA := factoryByTypeA()
	saA, ok := attByTypeA.(*securityAttestor)
	require.True(t, ok)
	assert.Equal(t, 1, saA.marker,
		"BUG [HIGH]: attestationsByType[typeA] still points to A's factory, "+
			"even though A's name registration was overwritten by B. "+
			"The type map and name registry are now inconsistent. "+
			"FactoryByType(typeA) returns A, but FactoryByName(name) returns B.")

	t.Logf("BUG [HIGH]: After two RegisterAttestation calls with same name " +
		"but different types, the type map retains a STALE entry for the first " +
		"type. Name lookup returns B, but typeA lookup still returns A. " +
		"The three maps (name, type, run) have no transactional consistency. " +
		"File: factory.go:98-102")
}

// ==========================================================================
// R3-305: FactoryByType returns nil factory on double miss
// ==========================================================================

// TestSecurity_R3_305_FactoryByTypeNilOnDoubleMiss proves that when
// FactoryByType fails both the primary lookup and the legacy alias
// fallback, it returns a nil factory function alongside ok=false.
// A caller that ignores the ok return and calls factory() will panic.
//
// BUG [MEDIUM]: FactoryByType at factory.go:112-121 returns
// registrationEntry.Factory where registrationEntry is the zero value
// of registry.Entry[Attestor]. The Factory field is nil. Combined with
// ok=false, this is standard Go, but callers skipping the ok check
// get a nil function panic.
// File: factory.go:112-121
func TestSecurity_R3_305_FactoryByTypeNilOnDoubleMiss(t *testing.T) {
	factory, ok := FactoryByType("https://does-not-exist/r3-305")
	assert.False(t, ok, "should not find non-existent type")

	// Factory is nil -- calling it will panic
	assert.Nil(t, factory,
		"BUG [MEDIUM]: FactoryByType returns nil factory on miss. "+
			"Callers that ignore the ok return will panic on factory().")

	// Prove the panic
	assert.Panics(t, func() {
		_ = factory()
	}, "calling nil factory from FactoryByType miss should panic")
}

// ==========================================================================
// R3-306: GetAttestors partial results on mid-list error
// ==========================================================================

// TestSecurity_R3_306_GetAttestorsPartialOnError proves that when
// GetAttestors processes a list of attestor names/types and encounters
// an error partway through (e.g., one name is not found), it returns
// nil for the attestors slice AND the error. All previously resolved
// attestors are discarded.
//
// This is actually correct fail-closed behavior. But the bug is in the
// interaction with SetDefaultVals: if the factory succeeds but
// SetDefaultVals fails (e.g., a setter error), the partially-built
// attestors list is also discarded. However, for pointer-based attestors
// that were already created by factory(), those objects may have been
// retained by the factory's closure and are now in an undefined state.
//
// BUG [LOW]: GetAttestors returns (nil, error) on any failure, discarding
// all previously successfully resolved attestors. This is correct but
// combined with factories that return shared state (common in init()
// closures that capture a single instance), the discarded attestors
// may still be reachable.
// File: factory.go:146-168
func TestSecurity_R3_306_GetAttestorsPartialOnError(t *testing.T) {
	// Register a valid attestor
	validName := "r3-306-valid"
	RegisterAttestation(validName, "https://test/r3-306-valid", ExecuteRunType,
		func() Attestor {
			return &securityAttestor{
				name:          validName,
				predicateType: "https://test/r3-306-valid",
				runType:       ExecuteRunType,
			}
		},
	)

	// Request valid + invalid -- the invalid one causes error
	attestors, err := GetAttestors([]string{validName, "r3-306-does-not-exist"})
	require.Error(t, err, "should error on unknown attestor")
	assert.Nil(t, attestors,
		"all previously resolved attestors are discarded on error")

	// The error is ErrAttestorNotFound
	_, isNotFound := err.(ErrAttestorNotFound)
	assert.True(t, isNotFound,
		"error should be ErrAttestorNotFound")

	// Now test the reverse order -- invalid first
	attestors2, err2 := GetAttestors([]string{"r3-306-does-not-exist", validName})
	require.Error(t, err2, "should error on first unknown attestor")
	assert.Nil(t, attestors2,
		"no attestors returned when first entry fails")

	t.Logf("BUG [LOW]: GetAttestors returns (nil, error) on any failure in the list. " +
		"Previously resolved attestors from the same call are discarded. " +
		"If factories return shared state, those objects are in undefined state. " +
		"File: factory.go:146-168")
}

// ==========================================================================
// R3-307: RegisterAttestation with nil factory stored in all three maps
// ==========================================================================

// TestSecurity_R3_307_NilFactoryPropagatesAcrossAllMaps proves that
// registering a nil factory function via RegisterAttestation propagates
// the nil across attestorRegistry, attestationsByType, and attestationsByRun.
// The nil factory is retrievable from ALL three maps, and calling any of
// them panics. The registration site gives no indication of the problem.
//
// BUG [HIGH]: RegisterAttestation does not validate factoryFunc. A nil
// factory is silently stored in three separate locations, creating three
// independent panic sources.
// File: factory.go:98-102
func TestSecurity_R3_307_NilFactoryPropagatesAcrossAllMaps(t *testing.T) {
	name := "r3-307-nil-factory"
	predType := "https://test/r3-307-nil"

	RegisterAttestation(name, predType, VerifyRunType, nil)

	// Nil factory is in name registry
	factoryByName, okName := FactoryByName(name)
	require.True(t, okName, "name should be registered")
	assert.Nil(t, factoryByName,
		"nil factory stored in name registry")

	// Nil factory is in type map
	factoryByType, okType := FactoryByType(predType)
	require.True(t, okType, "type should be registered")
	assert.Nil(t, factoryByType,
		"nil factory stored in type map")

	// Nil factory is in run map
	entry, okRun := attestationsByRun[VerifyRunType]
	require.True(t, okRun, "run type should be registered")
	assert.Nil(t, entry.Factory,
		"nil factory stored in run map")

	// All three panic when called
	assert.Panics(t, func() { factoryByName() },
		"BUG [HIGH]: nil factory from name registry panics on call")
	assert.Panics(t, func() { factoryByType() },
		"BUG [HIGH]: nil factory from type map panics on call")
	assert.Panics(t, func() { entry.Factory() },
		"BUG [HIGH]: nil factory from run map panics on call")

	// GetAttestors also panics
	assert.Panics(t, func() {
		_, _ = GetAttestors([]string{name})
	}, "BUG [HIGH]: GetAttestors panics when nil factory is in registry")

	t.Logf("BUG [HIGH]: RegisterAttestation with nil factory silently propagates " +
		"nil to all three maps. Three independent panic sources, all traceable " +
		"to a single unvalidated registration call. File: factory.go:98-102")
}

// ==========================================================================
// R3-308: GetAttestors with duplicate name returns duplicate attestors
// ==========================================================================

// TestSecurity_R3_308_GetAttestorsDuplicateNames proves that passing
// the same name twice to GetAttestors creates two separate attestor
// instances from the same factory. There is no deduplication.
//
// BUG [LOW]: GetAttestors does not deduplicate its input. Passing the
// same name twice creates two independent instances, which wastes
// resources and could confuse downstream consumers that expect unique
// attestors per name.
// File: factory.go:146-168
func TestSecurity_R3_308_GetAttestorsDuplicateNames(t *testing.T) {
	name := "r3-308-dedup"
	predType := "https://test/r3-308-dedup"
	callCount := 0

	RegisterAttestation(name, predType, ExecuteRunType,
		func() Attestor {
			callCount++
			return &securityAttestor{
				name:          name,
				predicateType: predType,
				runType:       ExecuteRunType,
				marker:        callCount,
			}
		},
	)

	callCount = 0
	attestors, err := GetAttestors([]string{name, name, name})
	require.NoError(t, err)

	assert.Len(t, attestors, 3,
		"BUG [LOW]: GetAttestors creates 3 instances for 3 duplicate names. "+
			"No deduplication is performed.")
	assert.Equal(t, 3, callCount,
		"factory was called 3 times for 3 duplicate names")

	// Each instance is independent
	for i, att := range attestors {
		sa := att.(*securityAttestor)
		assert.Equal(t, i+1, sa.marker,
			"each duplicate call creates a new instance (instance %d)", i)
	}

	t.Logf("BUG [LOW]: GetAttestors does not deduplicate input names. " +
		"Duplicate names create duplicate attestor instances. " +
		"File: factory.go:146-168")
}

// ==========================================================================
// R3-309: GetAttestors can resolve same attestor by both name and type
// ==========================================================================

// TestSecurity_R3_309_GetAttestorsNameAndTypeBothResolve proves that
// passing both a name and its corresponding type to GetAttestors
// creates two separate instances of the same attestor. The caller
// gets duplicates with no indication they're the same logical entity.
//
// BUG [LOW]: GetAttestors has no mechanism to detect that a name and
// a type refer to the same registered attestor. This creates duplicate
// instances in the attestation pipeline.
// File: factory.go:146-168
func TestSecurity_R3_309_GetAttestorsNameAndTypeBothResolve(t *testing.T) {
	name := "r3-309-name-type-dup"
	predType := "https://test/r3-309-name-type"
	instanceCount := 0

	RegisterAttestation(name, predType, ExecuteRunType,
		func() Attestor {
			instanceCount++
			return &securityAttestor{
				name:          name,
				predicateType: predType,
				runType:       ExecuteRunType,
				marker:        instanceCount,
			}
		},
	)

	instanceCount = 0
	// Pass both the name and the type -- both resolve to the same attestor
	attestors, err := GetAttestors([]string{name, predType})
	require.NoError(t, err)

	assert.Len(t, attestors, 2,
		"BUG [LOW]: GetAttestors creates 2 instances when given both name and type "+
			"for the same attestor. No deduplication.")
	assert.Equal(t, 2, instanceCount,
		"factory called twice for the same logical attestor")

	// Both resolve to attestors with the same name
	assert.Equal(t, name, attestors[0].Name())
	assert.Equal(t, name, attestors[1].Name())

	t.Logf("BUG [LOW]: GetAttestors resolves both name and type independently. " +
		"Passing both for the same attestor creates duplicate instances. " +
		"File: factory.go:146-168")
}

// ==========================================================================
// R3-310: attestationsByRun single-slot lossy overwrite
// ==========================================================================

// TestSecurity_R3_310_AttestationsByRunSingleSlot proves that
// attestationsByRun is a plain map[RunType]Entry, meaning only ONE
// attestor can be stored per RunType. Multiple attestors with the same
// RunType silently overwrite each other. Since most attestors use one
// of a small number of RunTypes (PreMaterial, Execute, PostProduct),
// this map only stores the LAST registered attestor for each phase.
//
// BUG [MEDIUM]: attestationsByRun is declared as map[RunType]Entry but
// the design expects many attestors per RunType (e.g., multiple
// PreMaterial attestors like git, environment). The map can only store
// one per RunType. It appears to be dead code or a design mistake.
// File: factory.go:28, 101, 109
func TestSecurity_R3_310_AttestationsByRunSingleSlot(t *testing.T) {
	// Register three attestors with the same RunType
	for i := 1; i <= 3; i++ {
		name := "r3-310-" + string(rune('a'+i-1))
		RegisterAttestation(name,
			"https://test/r3-310-"+name,
			ProductRunType,
			func() Attestor {
				return &securityAttestor{
					name:    name,
					runType: ProductRunType,
					marker:  i,
				}
			},
		)
	}

	// attestationsByRun[ProductRunType] only has the LAST one
	entry, ok := attestationsByRun[ProductRunType]
	require.True(t, ok, "ProductRunType should have an entry")

	att := entry.Factory()
	sa := att.(*securityAttestor)
	assert.Equal(t, "r3-310-c", sa.Name(),
		"BUG [MEDIUM]: attestationsByRun only stores last-writer for each RunType. "+
			"First two attestors (a, b) were silently dropped from the run map.")

	// All three are still in the name registry
	for _, suffix := range []string{"a", "b", "c"} {
		_, ok := FactoryByName("r3-310-" + suffix)
		assert.True(t, ok, "attestor %s should be in name registry", suffix)
	}

	t.Logf("BUG [MEDIUM]: attestationsByRun[ProductRunType] stores exactly one entry. " +
		"Three attestors registered with ProductRunType, only the last survives. " +
		"This map is structurally incapable of storing multiple attestors per RunType. " +
		"File: factory.go:28, 101, 109")
}

// ==========================================================================
// R3-311: FactoryByName name lookup prioritized over FactoryByType
// ==========================================================================

// TestSecurity_R3_311_NamePriorityOverType proves that in GetAttestors,
// name lookup takes priority over type lookup. If a name matches an
// attestor A but the same string also appears as a predicate type for
// attestor B, only A is returned. There's no disambiguation or warning.
//
// BUG [LOW]: GetAttestors at factory.go:149-155 tries FactoryByName first.
// If the user-supplied string matches a name, the type lookup is skipped
// entirely. If someone registers an attestor with name="https://some/type"
// (a URI string as the name), it would shadow the type-based lookup.
// File: factory.go:146-168
func TestSecurity_R3_311_NamePriorityOverType(t *testing.T) {
	// Register attestor A with a name that is a URI
	uriName := "https://test/r3-311-ambiguous"
	RegisterAttestation(uriName,
		"https://test/r3-311-type-a",
		ExecuteRunType,
		func() Attestor {
			return &securityAttestor{
				name:          uriName,
				predicateType: "https://test/r3-311-type-a",
				marker:        1,
			}
		},
	)

	// Register attestor B with the URI as its predicate type
	RegisterAttestation("r3-311-attestor-b",
		uriName, // predicateType is the same string as A's name!
		MaterialRunType,
		func() Attestor {
			return &securityAttestor{
				name:          "r3-311-attestor-b",
				predicateType: uriName,
				marker:        2,
			}
		},
	)

	// GetAttestors with the URI string finds A (by name), NOT B (by type)
	attestors, err := GetAttestors([]string{uriName})
	require.NoError(t, err)
	require.Len(t, attestors, 1)

	sa := attestors[0].(*securityAttestor)
	assert.Equal(t, 1, sa.marker,
		"BUG [LOW]: name lookup shadows type lookup. Attestor A's name matches "+
			"the URI, so B (which has the URI as its predicate type) is unreachable "+
			"via this string. There's no disambiguation.")

	t.Logf("BUG [LOW]: GetAttestors name-first priority means a name that " +
		"collides with another attestor's predicate type causes the type-based " +
		"attestor to be shadowed. File: factory.go:149-155")
}
