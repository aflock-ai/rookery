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

//go:debug fips140=on

// cilock-all is the dev/test cilock build with every attestor +
// signer linked in. Used by scripts/test-catalog-tools.py to validate
// catalog tools against the full attestor surface.
//
// For production, prefer the canonical cilock (cilock/cmd/cilock) —
// it links only the curated default set. Use rookery-builder for
// custom subsets.
package main

import (
	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/cilock/cli"

	_ "github.com/aflock-ai/rookery/presets/all"
)

func main() {
	attestation.RegisterLegacyAliases()
	cli.Execute()
}
