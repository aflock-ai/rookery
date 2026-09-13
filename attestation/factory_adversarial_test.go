//go:build audit

package attestation

import (
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

type registrationWarningLog struct {
	log.Logger
	warnings []string
}

func (l *registrationWarningLog) Warnf(format string, args ...interface{}) {
	l.warnings = append(l.warnings, fmt.Sprintf(format, args...))
}

// --- Test helpers ---

type adversarialAttestor struct {
	name          string
	predicateType string
	runType       RunType
}

func (a *adversarialAttestor) Name() string                     { return a.name }
func (a *adversarialAttestor) Type() string                     { return a.predicateType }
func (a *adversarialAttestor) RunType() RunType                 { return a.runType }
func (a *adversarialAttestor) Schema() *jsonschema.Schema       { return jsonschema.Reflect(a) }
func (a *adversarialAttestor) Attest(*AttestationContext) error { return nil }

// --- Tests ---

// TestFactoryByName_NotFound verifies that looking up a non-existent name
// returns ok=false.
func TestFactoryByName_NotFound(t *testing.T) {
	_, ok := FactoryByName("this-does-not-exist-ever")
	if ok {
		t.Errorf("BUG: FactoryByName should return ok=false for non-existent name")
	} else {
		t.Logf("OK: FactoryByName correctly returns ok=false for unknown name")
	}
}

// TestFactoryByType_NotFound verifies that looking up a non-existent type
// returns ok=false.
func TestFactoryByType_NotFound(t *testing.T) {
	_, ok := FactoryByType("https://does-not-exist/v999")
	if ok {
		t.Errorf("BUG: FactoryByType should return ok=false for non-existent type")
	} else {
		t.Logf("OK: FactoryByType correctly returns ok=false for unknown type")
	}
}

// TestGetAttestors_UnknownNameOrType verifies that requesting an unknown
// attestor returns ErrAttestorNotFound.
func TestGetAttestors_UnknownNameOrType(t *testing.T) {
	_, err := GetAttestors([]string{"totally-unknown"})
	if err == nil {
		t.Errorf("BUG: GetAttestors should error for unknown name/type")
	} else {
		t.Logf("OK: GetAttestors correctly errors for unknown: %v", err)
	}
}

// TestGetAttestor_UnknownSingle verifies GetAttestor for unknown name.
func TestGetAttestor_UnknownSingle(t *testing.T) {
	_, err := GetAttestor("totally-unknown")
	if err == nil {
		t.Errorf("BUG: GetAttestor should error for unknown name")
	} else {
		t.Logf("OK: GetAttestor correctly errors for unknown: %v", err)
	}
}

// TestRegisterAttestation_DuplicateName verifies that registering the same
// name twice silently overwrites the first registration.
func TestRegisterAttestation_DuplicateName(t *testing.T) {
	previousRegistry, previousTypes := attestorRegistry, attestationsByType
	attestorRegistry = registry.New[Attestor]()
	attestationsByType = map[string]registry.Entry[Attestor]{}
	t.Cleanup(func() { attestorRegistry, attestationsByType = previousRegistry, previousTypes })
	previousLogger := log.GetLogger()
	warnings := &registrationWarningLog{Logger: previousLogger}
	log.SetLogger(warnings)
	t.Cleanup(func() { log.SetLogger(previousLogger) })
	first := &adversarialAttestor{
		name:          "adv-dup-test",
		predicateType: "https://test/adv-dup-1",
		runType:       ExecuteRunType,
	}
	second := &adversarialAttestor{
		name:          "adv-dup-test",
		predicateType: "https://test/adv-dup-2",
		runType:       MaterialRunType,
	}

	RegisterAttestation(first.name, first.predicateType, first.runType, func() Attestor { return first })
	require.Empty(t, warnings.warnings, "a new registration must not report replacement")
	RegisterAttestation(second.name, second.predicateType, second.runType, func() Attestor { return second })

	factory, ok := FactoryByName("adv-dup-test")
	if !ok {
		t.Fatalf("FactoryByName should find 'adv-dup-test'")
	}

	require.Same(t, second, factory(), "preserve the registry's replacement contract")
	require.Len(t, warnings.warnings, 1, "replacement must not be silent")
	require.Contains(t, warnings.warnings[0], first.name)
}

// Scheduling must preserve every selected attestor, including shared stages.
func TestRegisterAttestation_SameRunTypePreservesAll(t *testing.T) {
	a1 := &adversarialAttestor{
		name:          "adv-run-first",
		predicateType: "https://test/run-first",
		runType:       PostProductRunType,
	}
	a2 := &adversarialAttestor{
		name:          "adv-run-second",
		predicateType: "https://test/run-second",
		runType:       PostProductRunType,
	}

	RegisterAttestation(a1.name, a1.predicateType, a1.runType, func() Attestor { return a1 })
	RegisterAttestation(a2.name, a2.predicateType, a2.runType, func() Attestor { return a2 })

	attestors, err := GetAttestors([]string{a1.name, a2.name})
	require.NoError(t, err)
	require.Len(t, attestors, 2)
	ctx, err := NewContext("same-stage", attestors)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	completed := ctx.CompletedAttestors()
	require.Len(t, completed, 2, "both attestors in one stage must execute")
	require.ElementsMatch(t, []string{a1.name, a2.name}, []string{completed[0].Attestor.Name(), completed[1].Attestor.Name()})
}

// TestRegisterAttestationWithTypes_MultiplePredicateTypes verifies that
// registering with multiple predicate types indexes all of them.
func TestRegisterAttestationWithTypes_MultiplePredicateTypes(t *testing.T) {
	att := &adversarialAttestor{
		name:          "adv-multi-type",
		predicateType: "https://test/multi-type-primary",
		runType:       ExecuteRunType,
	}

	types := []string{
		"https://test/multi-type-primary",
		"https://test/multi-type-alias",
	}

	RegisterAttestationWithTypes(att.name, types, att.runType, func() Attestor { return att })

	for _, typ := range types {
		factory, ok := FactoryByType(typ)
		if !ok {
			t.Errorf("BUG: FactoryByType should find type %q", typ)
			continue
		}
		a := factory()
		if a.Name() != att.name {
			t.Errorf("BUG: factory for type %q returned name %q, expected %q", typ, a.Name(), att.name)
		}
	}

	t.Logf("OK: RegisterAttestationWithTypes correctly indexes all predicate types")
}

// TestResolveLegacyType_KnownAlias verifies that known legacy types resolve correctly.
func TestResolveLegacyType_KnownAlias(t *testing.T) {
	legacy := "https://witness.dev/attestations/git/v0.1"
	resolved := ResolveLegacyType(legacy)
	expected := "https://aflock.ai/attestations/git/v0.1"

	if resolved != expected {
		t.Errorf("BUG: ResolveLegacyType(%q) = %q, want %q", legacy, resolved, expected)
	} else {
		t.Logf("OK: legacy type correctly resolved: %q -> %q", legacy, resolved)
	}
}

// TestResolveLegacyType_UnknownPassthrough verifies that unknown types pass through unchanged.
func TestResolveLegacyType_UnknownPassthrough(t *testing.T) {
	unknown := "https://example.com/custom/v1"
	resolved := ResolveLegacyType(unknown)
	if resolved != unknown {
		t.Errorf("BUG: ResolveLegacyType should pass through unknown types, got %q", resolved)
	} else {
		t.Logf("OK: unknown type passed through unchanged")
	}
}

// TestLegacyAlternate_Bidirectional verifies that LegacyAlternate works
// in both directions.
func TestLegacyAlternate_Bidirectional(t *testing.T) {
	legacy := "https://witness.dev/attestations/git/v0.1"
	current := "https://aflock.ai/attestations/git/v0.1"

	// Legacy -> Current
	alt := LegacyAlternate(legacy)
	if alt != current {
		t.Errorf("BUG: LegacyAlternate(%q) = %q, want %q", legacy, alt, current)
	}

	// Current -> Legacy
	alt = LegacyAlternate(current)
	if alt != legacy {
		t.Errorf("BUG: LegacyAlternate(%q) = %q, want %q", current, alt, legacy)
	}

	// Unknown -> empty string
	alt = LegacyAlternate("https://unknown/type")
	if alt != "" {
		t.Errorf("BUG: LegacyAlternate for unknown type should return empty string, got %q", alt)
	}

	t.Logf("OK: LegacyAlternate correctly works bidirectionally")
}

// TestRegistrationEntries_ReturnsAll verifies that AllEntries returns
// all registered entries.
func TestRegistrationEntries_ReturnsAll(t *testing.T) {
	// Register a unique attestor
	uniqueName := "adv-all-entries-test"
	RegisterAttestation(uniqueName, "https://test/all-entries", ExecuteRunType, func() Attestor {
		return &adversarialAttestor{name: uniqueName, predicateType: "https://test/all-entries", runType: ExecuteRunType}
	})

	entries := RegistrationEntries()
	found := false
	for _, e := range entries {
		if e.Name == uniqueName {
			found = true
		}
	}

	if !found {
		t.Errorf("BUG: RegistrationEntries() should include recently registered %q", uniqueName)
	} else {
		t.Logf("OK: RegistrationEntries() includes all registered attestors (%d total)", len(entries))
	}
}

// TestAttestorOptions_UnknownName verifies behavior when querying options
// for an unknown attestor.
func TestAttestorOptions_UnknownName(t *testing.T) {
	opts := AttestorOptions("definitely-not-registered")
	if opts != nil {
		t.Logf("OK: AttestorOptions for unknown name returns non-nil: %v (from zero-value entry)", opts)
	} else {
		t.Logf("OK: AttestorOptions for unknown name returns nil")
	}
}

// TestRegisterAttestation_NilFactory verifies behavior when registering
// a nil factory function (not the return value, the function itself).
func TestRegisterAttestation_NilFactory(t *testing.T) {
	require.PanicsWithValue(t, "nil attestation factory", func() {
		RegisterAttestation("adv-nil-factory", "https://test/nil", ExecuteRunType, nil)
	})
	_, ok := FactoryByName("adv-nil-factory")
	require.False(t, ok)
	_, ok = FactoryByType("https://test/nil")
	require.False(t, ok)
	require.PanicsWithValue(t, "nil attestation factory", func() {
		RegisterAttestationWithTypes("adv-nil-types", []string{"https://test/nil-a", "https://test/nil-b"}, ExecuteRunType, nil)
	})
	_, ok = FactoryByName("adv-nil-types")
	require.False(t, ok)
	for _, predicate := range []string{"https://test/nil-a", "https://test/nil-b"} {
		_, ok = FactoryByType(predicate)
		require.False(t, ok)
	}
}

// TestRegisterLegacyAliases_AfterRegistration verifies that legacy aliases
// work after calling RegisterLegacyAliases.
func TestRegisterLegacyAliases_AfterRegistration(t *testing.T) {
	// Register an attestor with the current URI
	currentType := "https://aflock.ai/attestations/git/v0.1"
	RegisterAttestation("adv-git-alias", currentType, PreMaterialRunType, func() Attestor {
		return &adversarialAttestor{name: "adv-git-alias", predicateType: currentType, runType: PreMaterialRunType}
	})

	// Register legacy aliases
	RegisterLegacyAliases()

	// Now the legacy URI should resolve
	legacyType := "https://witness.dev/attestations/git/v0.1"
	factory, ok := FactoryByType(legacyType)
	if !ok {
		t.Errorf("BUG: FactoryByType should resolve legacy type %q after RegisterLegacyAliases", legacyType)
	} else {
		att := factory()
		t.Logf("OK: legacy type %q resolved to attestor %q", legacyType, att.Name())
	}
}

// TestGetAttestors_Empty verifies behavior with empty input slice.
func TestGetAttestors_Empty(t *testing.T) {
	attestors, err := GetAttestors([]string{})
	if err != nil {
		t.Errorf("BUG: GetAttestors with empty input should not error: %v", err)
	}
	if len(attestors) != 0 {
		t.Errorf("BUG: expected 0 attestors, got %d", len(attestors))
	} else {
		t.Logf("OK: GetAttestors with empty input returns empty slice")
	}
}

// TestGetAttestors_SetDefaultVals verifies that factory-created attestors
// get default values applied from registered options.
func TestGetAttestors_SetDefaultVals(t *testing.T) {
	type configAttestor struct {
		adversarialAttestor
		value string
	}

	ca := &configAttestor{
		adversarialAttestor: adversarialAttestor{
			name:          "adv-config-test",
			predicateType: "https://test/config",
			runType:       ExecuteRunType,
		},
		value: "default",
	}

	opt := registry.StringConfigOption[Attestor](
		"test-value",
		"a test configuration value",
		"applied-default",
		func(a Attestor, val string) (Attestor, error) {
			if c, ok := a.(*configAttestor); ok {
				c.value = val
			}
			return a, nil
		},
	)

	RegisterAttestation(ca.name, ca.predicateType, ca.runType,
		func() Attestor {
			return &configAttestor{
				adversarialAttestor: adversarialAttestor{
					name:          "adv-config-test",
					predicateType: "https://test/config",
					runType:       ExecuteRunType,
				},
				value: "not-set",
			}
		},
		opt,
	)

	attestors, err := GetAttestors([]string{"adv-config-test"})
	if err != nil {
		t.Fatalf("GetAttestors failed: %v", err)
	}

	if len(attestors) != 1 {
		t.Fatalf("expected 1 attestor, got %d", len(attestors))
	}

	ca2, ok := attestors[0].(*configAttestor)
	if !ok {
		t.Fatalf("expected *configAttestor, got %T", attestors[0])
	}

	if ca2.value != "applied-default" {
		t.Errorf("BUG: GetAttestors did not apply default value. Got %q, want %q", ca2.value, "applied-default")
	} else {
		t.Logf("OK: GetAttestors correctly applies default configuration values")
	}
}
