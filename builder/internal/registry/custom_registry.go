package registry

import (
	"fmt"
	"sync"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/registry"
)

// CustomAttestorRegistry provides a replacement for the global attestation registry.
// This allows us to control which attestors are registered without relying on init() functions.
type CustomAttestorRegistry struct {
	registry registry.Registry[attestation.Attestor]
	mu       sync.RWMutex
	entries  map[string]registry.Entry[attestation.Attestor]
	byType   map[string]registry.Entry[attestation.Attestor]
	byRun    map[attestation.RunType][]registry.Entry[attestation.Attestor]
}

// NewCustomAttestorRegistry creates a new custom attestor registry.
func NewCustomAttestorRegistry() *CustomAttestorRegistry {
	return &CustomAttestorRegistry{
		registry: registry.New[attestation.Attestor](),
		entries:  make(map[string]registry.Entry[attestation.Attestor]),
		byType:   make(map[string]registry.Entry[attestation.Attestor]),
		byRun:    make(map[attestation.RunType][]registry.Entry[attestation.Attestor]),
	}
}

// Register registers an attestor with the custom registry.
func (r *CustomAttestorRegistry) Register(name string, factory registry.FactoryFunc[attestation.Attestor], opts ...registry.Configurer) registry.Entry[attestation.Attestor] {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry := r.registry.Register(name, factory, opts...)
	r.entries[name] = entry

	// Get the attestor to determine its type and run type
	attestor := factory()
	r.byType[attestor.Type()] = entry
	r.byRun[attestor.RunType()] = append(r.byRun[attestor.RunType()], entry)

	return entry
}

// GetAttestor returns a single attestor by name or type.
func (r *CustomAttestorRegistry) GetAttestor(nameOrType string) (attestation.Attestor, error) {
	attestors, err := r.GetAttestors([]string{nameOrType})
	if err != nil {
		return nil, err
	}

	if len(attestors) == 0 {
		return nil, attestation.ErrAttestorNotFound(nameOrType)
	}

	return attestors[0], nil
}

// GetAttestors returns multiple attestors by name or type.
func (r *CustomAttestorRegistry) GetAttestors(nameOrTypes []string) ([]attestation.Attestor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var attestors []attestation.Attestor
	for _, nameOrType := range nameOrTypes {
		var entry registry.Entry[attestation.Attestor]
		var found bool

		// First try by name
		if entry, found = r.entries[nameOrType]; !found {
			// Then try by type
			entry, found = r.byType[nameOrType]
		}

		if !found {
			return nil, attestation.ErrAttestorNotFound(nameOrType)
		}

		attestor := entry.Factory()
		opts := r.getAttestorOptions(nameOrType)

		// Apply default values if configured
		processedAttestor, err := r.registry.SetDefaultVals(attestor, opts)
		if err != nil {
			return nil, err
		}

		attestors = append(attestors, processedAttestor)
	}

	return attestors, nil
}

// GetAttestorsByRunType returns all attestors for a specific run type.
func (r *CustomAttestorRegistry) GetAttestorsByRunType(runType attestation.RunType) []attestation.Attestor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var attestors []attestation.Attestor
	for _, entry := range r.byRun[runType] {
		attestors = append(attestors, entry.Factory())
	}

	return attestors
}

// FactoryByName returns the factory function for an attestor by name.
func (r *CustomAttestorRegistry) FactoryByName(name string) (registry.FactoryFunc[attestation.Attestor], bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.entries[name]
	return entry.Factory, ok
}

// FactoryByType returns the factory function for an attestor by type.
func (r *CustomAttestorRegistry) FactoryByType(predicateType string) (registry.FactoryFunc[attestation.Attestor], bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	entry, ok := r.byType[predicateType]
	return entry.Factory, ok
}

// AllEntries returns all registered entries.
func (r *CustomAttestorRegistry) AllEntries() []registry.Entry[attestation.Attestor] {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var entries []registry.Entry[attestation.Attestor]
	for _, entry := range r.entries {
		entries = append(entries, entry)
	}

	return entries
}

// ListNames returns all registered attestor names.
func (r *CustomAttestorRegistry) ListNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name := range r.entries {
		names = append(names, name)
	}

	return names
}

// Count returns the number of registered attestors.
func (r *CustomAttestorRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.entries)
}

// getAttestorOptions returns the configuration options for an attestor.
func (r *CustomAttestorRegistry) getAttestorOptions(nameOrType string) []registry.Configurer {
	// First try by name
	if entry, ok := r.entries[nameOrType]; ok {
		return entry.Options
	}

	// Then try by type
	if entry, ok := r.byType[nameOrType]; ok {
		return entry.Options
	}

	return nil
}

// Reset clears all registered attestors.
func (r *CustomAttestorRegistry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries = make(map[string]registry.Entry[attestation.Attestor])
	r.byType = make(map[string]registry.Entry[attestation.Attestor])
	r.byRun = make(map[attestation.RunType][]registry.Entry[attestation.Attestor])
	r.registry = registry.New[attestation.Attestor]()
}

// String returns a string representation of the registry.
func (r *CustomAttestorRegistry) String() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for name := range r.entries {
		names = append(names, name)
	}
	return fmt.Sprintf("CustomAttestorRegistry{count: %d, attestors: %v}",
		len(r.entries), names)
}
