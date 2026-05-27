// Copyright 2026 TestifySec, Inc.
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

package detection

import (
	"fmt"
	"sort"
	"sync"

	"github.com/aflock-ai/rookery/attestation/log"
)

// Registry holds the embedded detector.yaml bytes for every plugin that
// registered one. Lookup is by plugin name. YAML parsing is deferred to
// the first call to Lookup or LookupAll — a malformed file is reported
// then, with a real stack, instead of crashing at init() before main has
// a chance to set up logging.
//
// The package-level default registry is the one cilock uses at runtime.
// Tests construct their own Registry via NewRegistry to avoid touching
// global state.
type Registry struct {
	mu       sync.RWMutex
	raw      map[string][]byte
	parsed   map[string]*DetectorYAML
	parseErr map[string]error

	// Long-form documentation, keyed by detector name. Populated from the
	// embedded docs/ catalog (see doc.go). Parsed lazily like detector.yaml.
	docRaw    map[string][]byte
	docParsed map[string]*DetectorDoc
	docErr    map[string]error
}

// defaultRegistry is the singleton plugins write to from init().
var defaultRegistry = NewRegistry()

// NewRegistry returns a new empty detector registry suitable for use in
// tests. Production code uses Default().
func NewRegistry() *Registry {
	return &Registry{
		raw:       make(map[string][]byte),
		parsed:    make(map[string]*DetectorYAML),
		parseErr:  make(map[string]error),
		docRaw:    make(map[string][]byte),
		docParsed: make(map[string]*DetectorDoc),
		docErr:    make(map[string]error),
	}
}

// Default returns the package-level registry that plugins register into.
func Default() *Registry {
	return defaultRegistry
}

// Register stores the raw YAML bytes for the named plugin. Called from
// each plugin's init() right after attestation.RegisterAttestation. The
// YAML is *not* parsed here — parsing happens lazily on first Lookup.
//
// Re-registering the same plugin name is a build-config bug (two
// init() functions claiming the same name). We log loudly and keep
// the first registration — silent first-write-wins beats crashing
// every binary that links both plugins.
func (r *Registry) Register(pluginName string, yamlBytes []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.raw[pluginName]; dup {
		log.Errorf("(detection/registry) duplicate detector registration for plugin %q — keeping first registration, dropping second", pluginName)
		return
	}
	r.raw[pluginName] = yamlBytes
}

// Register is the shorthand for Default().Register. Use this from a
// plugin's init() function.
func Register(pluginName string, yamlBytes []byte) {
	defaultRegistry.Register(pluginName, yamlBytes)
}

// Lookup returns the parsed detector for the named plugin. If the plugin
// did not register a detector.yaml, returns (nil, false, nil). If a YAML
// was registered but fails to parse, returns the parse error — the
// detector is treated as "not registered" by callers and the run
// continues without it (with a warning if appropriate).
func (r *Registry) Lookup(pluginName string) (*DetectorYAML, bool, error) {
	r.mu.RLock()
	if cached, ok := r.parsed[pluginName]; ok {
		err := r.parseErr[pluginName]
		r.mu.RUnlock()
		if err != nil {
			return nil, true, err
		}
		return cached, true, nil
	}
	rawBytes, ok := r.raw[pluginName]
	r.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}

	// Upgrade the lock; another goroutine might have parsed in between
	// (cheap path) — re-check under write lock.
	r.mu.Lock()
	defer r.mu.Unlock()
	if cached, ok := r.parsed[pluginName]; ok {
		return cached, true, r.parseErr[pluginName]
	}
	d, err := ParseDetectorYAML(rawBytes)
	if err != nil {
		r.parseErr[pluginName] = err
		// Cache a sentinel so we don't retry parsing on every Lookup;
		// a developer fixes the YAML and rebuilds. Note: caching the
		// error is intentional — same input, same outcome.
		r.parsed[pluginName] = nil
		return nil, true, err
	}
	if d.Name != pluginName {
		err := fmt.Errorf("detector.yaml name %q does not match registration plugin name %q", d.Name, pluginName)
		r.parseErr[pluginName] = err
		r.parsed[pluginName] = nil
		return nil, true, err
	}
	r.parsed[pluginName] = d
	return d, true, nil
}

// Names returns the registered plugin names in sorted order. Sorted to
// make planning deterministic across runs.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.raw))
	for n := range r.raw {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// LookupAll parses every registered detector, returning the successful
// ones plus a map of plugin → parse error for the failures. Intended
// for the drift-guard test and cilock plan / explain subcommands.
func (r *Registry) LookupAll() (map[string]*DetectorYAML, map[string]error) {
	names := r.Names()
	ok := make(map[string]*DetectorYAML, len(names))
	failures := make(map[string]error)
	for _, n := range names {
		d, _, err := r.Lookup(n)
		if err != nil {
			failures[n] = err
			continue
		}
		if d != nil {
			ok[n] = d
		}
	}
	return ok, failures
}

// Reset clears every registered detector. Test-only — never call from
// production code.
func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.raw = make(map[string][]byte)
	r.parsed = make(map[string]*DetectorYAML)
	r.parseErr = make(map[string]error)
	r.docRaw = make(map[string][]byte)
	r.docParsed = make(map[string]*DetectorDoc)
	r.docErr = make(map[string]error)
}
