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

// Command gen-catalog emits the MACHINE-READABLE attestor catalog
// (docs/attestor-catalog.json) by live registry introspection enriched with
// detector.yaml metadata. It is the JSON counterpart to
// scripts/gen-attestor-catalog.sh (which still owns the markdown) — instead of
// grepping Go source, it blank-imports presets/all (via the catalog package),
// reads every registered attestor's Name/Type/RunType from the live
// attestation registry, joins detector.yaml enrichment from the detection
// registry, and writes a deterministic (timestamp-free) JSON document.
//
// Regenerate (from the rookery repo root):
//
//	cd presets/all && GOWORK=off go run ./cmd/gen-catalog
//
// or with an explicit output path:
//
//	cd presets/all && GOWORK=off go run ./cmd/gen-catalog -out ../../docs/attestor-catalog.json
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/presets/all/internal/catalog"
)

func main() {
	// Default: docs/attestor-catalog.json at the rookery root, two levels up
	// from this command's module dir (presets/all). The command is meant to be
	// run from presets/all (see the package doc + Makefile), matching how the
	// catalogtest harness resolves the plugins dir.
	out := flag.String("out", "../../docs/attestor-catalog.json", "output path for the catalog JSON")
	flag.Parse()

	data, err := catalog.Render()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-catalog: build catalog: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*out, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "gen-catalog: write %s: %v\n", *out, err)
		os.Exit(1)
	}

	// Re-read the catalog count from the rendered struct for the operator
	// summary. Build() is cheap and deterministic, so a second call is fine.
	cat, _ := catalog.Build()
	if cat != nil {
		fmt.Printf("gen-catalog: wrote %s (%d attestors)\n", *out, cat.AttestorCount)
	} else {
		fmt.Printf("gen-catalog: wrote %s\n", *out)
	}
}
