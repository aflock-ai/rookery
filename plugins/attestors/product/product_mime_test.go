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

package product

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// machO64LE is the little-endian 64-bit Mach-O magic (0xFEEDFACF) followed by
// enough header bytes for content sniffing to commit to the type.
const machO64LE = "\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x00\x00\x00\x00\x02\x00\x00\x00" +
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

// TestLeavesCarryMimeType: the attestor already sniffs every product's MIME
// type (productForSurvivor / fromCaptureEntries), and the Products() map
// exposes it to sibling attestors — but the SIGNED leaves carried only
// path+digest, so a policy could say "caddy-darwin is among the outputs"
// and never "the output is a Mach-O binary". The leaf must carry the
// sniffed type, and it must survive the JSON round trip a verifier performs.
func TestLeavesCarryMimeType(t *testing.T) {
	a := makeAttestor(t, map[string]string{
		"caddy-darwin": machO64LE,
		"notes.txt":    "hello v0.3\n",
	})

	byPath := map[string]ProductLeaf{}
	for _, l := range a.Leaves() {
		byPath[l.Path] = l
	}
	require.Contains(t, byPath, "caddy-darwin")
	require.Contains(t, byPath, "notes.txt")
	require.Equal(t, "application/x-mach-binary", byPath["caddy-darwin"].MimeType,
		"a Mach-O product leaf must name its type so policy can gate on it")
	require.True(t, strings.HasPrefix(byPath["notes.txt"].MimeType, "text/plain"),
		"text product leaf mime = %q", byPath["notes.txt"].MimeType)

	// Round trip: what the signer marshals is what the verifier decodes.
	raw, err := json.Marshal(a)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"mimeType":"application/x-mach-binary"`)

	var rt Attestor
	require.NoError(t, json.Unmarshal(raw, &rt))
	rtByPath := map[string]ProductLeaf{}
	for _, l := range rt.Leaves() {
		rtByPath[l.Path] = l
	}
	require.Equal(t, "application/x-mach-binary", rtByPath["caddy-darwin"].MimeType)
	require.NoError(t, rt.VerifyInlineLeaves(), "adding leaf metadata must not disturb the Merkle commitment")
}
