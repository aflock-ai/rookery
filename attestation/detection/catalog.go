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
	"embed"
	"fmt"
	"io/fs"
	"path"
	"strings"
)

// catalogYAMLs is the embedded directory of detection-only entries —
// tools cilock recognizes but doesn't have a dedicated Go attestor for.
// These entries surface in `cilock plan` and `cilock tools list` so an
// upstream agent / platform can route evidence by tool name. Format
// attestors (sbom, sarif, vex, test-results) capture the actual data.
//
// To add a new tool to the catalog, drop a YAML file in catalog/. The
// init() below loads it automatically — no Go code changes required.
//
//go:embed catalog/*.yaml
var catalogYAMLs embed.FS

// loadCatalog walks catalogYAMLs and registers each file with the
// default detection registry. Called from init() at package load.
func loadCatalog() error {
	entries, err := fs.ReadDir(catalogYAMLs, "catalog")
	if err != nil {
		// Empty embed dir is fine — early-bring-up state.
		if errIsNoSuchFile(err) {
			return nil
		}
		return fmt.Errorf("detection catalog: read catalog/: %w", err)
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		raw, err := catalogYAMLs.ReadFile(path.Join("catalog", name))
		if err != nil {
			return fmt.Errorf("detection catalog: read %s: %w", name, err)
		}
		// Use the filename stem as the registry key. Parsing happens
		// lazily on first Lookup — same error path as plugin yamls.
		key := strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
		defaultRegistry.Register(key, raw)
	}
	return nil
}

func errIsNoSuchFile(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "file does not exist") ||
		strings.Contains(err.Error(), "no such file")
}

func init() {
	if err := loadCatalog(); err != nil {
		// init() panics on a malformed embedded catalog — this is a
		// developer / build configuration bug, not a runtime input
		// error. Bake-time mistake; bake-time crash.
		panic(err)
	}
}
