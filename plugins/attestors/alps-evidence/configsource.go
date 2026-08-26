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

package alpsevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// configDigestLimit caps how large a configuration file may be before we record
// its presence without a digest — or any values. Agent settings files are
// kilobytes; anything vastly larger is not a settings file and is not worth
// streaming.
const configDigestLimit = 4 << 20 // 4 MiB

// configSnapshot is ONE bounded read of a configuration file, immutable once
// taken. The digest and every value are computed from the same byte slice.
//
// This is the mechanism, not an optimization: reading values and digest
// through separate opens of the same path lets a concurrent writer replace the
// file in between, pairing one version's values with another version's digest
// in signed evidence. Per-key value reads (the old readTOMLString shape) made
// the window several reads wide, and — because those reads were unbounded —
// also let a file the digest limit refused to hash still hand us values.
// A snapshot closes both: values without a digest cannot happen, and a value
// the bound rejects does not exist.
type configSnapshot struct {
	path string

	// data is the file content this snapshot describes. nil for an oversize
	// file, which contributes presence only: a value we could not afford to
	// digest is a value we cannot bind to evidence.
	data []byte

	// sha256 is the hex digest of data. Empty exactly when data is nil.
	sha256 string
}

// loadConfigSnapshot performs the single bounded read. A nil snapshot means
// there is no config content to observe at the path, and denied says WHY that
// matters: false is plain absence, while true means an entry EXISTS there and
// could not safely be read — permission denied, a deliberately refused
// symlink, and a FIFO/device standing where a file belongs are measured cases.
//
// Callers resolving a precedence chain must fail closed on denied: an
// unreadable higher-precedence file may set anything, so answering from a
// lower-precedence file would claim a default the unreadable file may
// override. That is the same rule the unreadable-environment and
// unparseable-file cases already follow; a file the kernel refuses to show us
// is no better evidence of "sets nothing" than one that does not parse.
//
// The open goes through openAgentPath, which is not a formality here: the
// Codex user config lives at $CODEX_HOME, read out of the AGENT'S OWN
// environment, so the agent picks the directory this opens. A FIFO there used
// to block collection outright. openAgentPath opens non-blocking and fstats
// the HANDLE — never the path, which would be the TOCTOU this package already
// killed once for the digest — so a pipe, a device or a directory is recorded
// as a present but unresolved tier and never lets lower-precedence config win.
//
// File CONTENT never enters the predicate. A settings file can contain an
// API base URL, a proxy with credentials in it, or MCP server definitions with
// tokens. The digest plus the specific fields parsed out of the snapshot is
// the whole evidence budget.
func loadConfigSnapshot(path string) (snap *configSnapshot, denied bool) {
	f, _, denied := openAgentPathState(path)
	if f == nil {
		return nil, denied
	}
	defer func() { _ = f.Close() }()

	// Read one byte past the cap so a file that grew between fstat and read is
	// caught by the read itself instead of trusted from the earlier size.
	data, err := io.ReadAll(io.LimitReader(f, configDigestLimit+1))
	if err != nil {
		// The file opened and then would not read. That is a failed look, not
		// an absence.
		return nil, true
	}
	if int64(len(data)) > configDigestLimit {
		return &configSnapshot{path: path}, false
	}
	sum := sha256.Sum256(data)
	return &configSnapshot{path: path, data: data, sha256: hex.EncodeToString(sum[:])}, false
}

// describeUnreadableConfig is the ConfigSource entry for a file that exists
// and could not be read. Recorded so a reader can see the file was THERE —
// silently omitting it made an unreadable managed-settings file
// indistinguishable from no managed settings at all — while the absent digest
// and fields say nothing was learned from it. The caller's warning carries the
// why.
func describeUnreadableConfig(path, scope string) *ConfigSource {
	return &ConfigSource{Path: path, Scope: scope, Role: RoleObserved}
}

// describe returns the ConfigSource for this snapshot. fields lists the keys
// the snapshot was actually consulted for — not a static inventory of what the
// provider knows how to read — so a reader can see which parts of the file were
// looked at.
//
// There is no role parameter. Every recorded file is observed, and a provider
// that wanted to say otherwise would have to invent a value the vocabulary no
// longer contains.
func (s *configSnapshot) describe(scope string, fields ...string) *ConfigSource {
	return &ConfigSource{Path: s.path, Scope: scope, Role: RoleObserved, FieldsUsed: fields, SHA256: s.sha256}
}

// jsonObjectParseable reports whether the snapshot's bytes parse as a JSON
// object — the shape every Claude Code settings file has. False for an
// oversize snapshot (nil data) and for malformed content. Callers use it to
// tell "this file demonstrably sets no value" from "what this file sets is
// unknown": the second must block lower-precedence resolution rather than
// fall through to it (see ClaudeCodeProvider.resolveModel).
//
// The nil check after decoding is load-bearing: json.Unmarshal("null", &m)
// returns NO error and leaves the map nil, so without it a settings file
// containing the JSON document `null` read as a parseable object that set
// nothing — and a lower-precedence file's model was signed as the configured
// default under a higher-precedence file whose meaning was never established.
// Every other non-object document (array, string, number) already fails the
// map decode; null must block the same way.
func (s *configSnapshot) jsonObjectParseable() bool {
	if s.data == nil {
		return false
	}
	var doc map[string]any
	if json.Unmarshal(s.data, &doc) != nil {
		return false
	}
	return doc != nil
}

// jsonString reads a dotted path out of the snapshot's JSON object and returns
// it only if the value is a string.
//
//nolint:unparam // every current caller reads "model"; the dotted-path walk is the general shape these settings files share
func (s *configSnapshot) jsonString(dotted string) (string, bool) {
	if s.data == nil {
		return "", false
	}
	var doc any
	if json.Unmarshal(s.data, &doc) != nil {
		return "", false
	}
	cur := doc
	for _, part := range strings.Split(dotted, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = obj[part]
		if !ok {
			return "", false
		}
	}
	str, ok := cur.(string)
	if !ok || str == "" {
		return "", false
	}
	return str, true
}

// tomlObjectParseable reports whether the snapshot is a bounded, parseable
// TOML document. A selected Codex profile is a separate overlay file in the
// current CLI; both the base and overlay must be parseable before this
// observer resolves their layered values. Oversize snapshots carry nil data
// and therefore fail closed here.
func (s *configSnapshot) tomlObjectParseable() bool {
	if s.data == nil {
		return false
	}
	var doc map[string]any
	return toml.Unmarshal(s.data, &doc) == nil
}

// tomlString reads a top-level or single-section scalar string out of the
// snapshot's TOML content.
//
// Decoding is delegated to a real TOML parser (the same go-toml/v2 the
// secretscan attestor already depends on) rather than a hand-rolled scanner.
// TOML basic strings carry escapes — \" \\ \uXXXX \UXXXXXXXX — that a
// quote-matching scanner truncates or records literally, and signed evidence
// must never contain a silently-mangled value. Content the parser refuses,
// including any escape TOML does not define, yields no values at all: reading
// a wrong value would be worse than reading none, so the failure mode stays
// silence — the same refusal the agent's own TOML parser gives such a file.
//
// section is a dotted table path ("profiles.work"); "" means the top-level
// table. Only genuine string values are returned: numbers, booleans, arrays,
// inline tables and arrays-of-tables report not-found.
func (s *configSnapshot) tomlString(section, key string) (string, bool) {
	if s.data == nil {
		return "", false
	}
	var doc map[string]any
	if toml.Unmarshal(s.data, &doc) != nil {
		return "", false
	}
	table := any(doc)
	if section != "" {
		for _, part := range strings.Split(section, ".") {
			m, ok := table.(map[string]any)
			if !ok {
				return "", false
			}
			table, ok = m[part]
			if !ok {
				return "", false
			}
		}
	}
	m, ok := table.(map[string]any)
	if !ok {
		return "", false
	}
	return tomlScalarString(m, key)
}

// tomlScalarString reads one genuine string value out of a decoded table.
func tomlScalarString(table map[string]any, key string) (string, bool) {
	str, ok := table[key].(string)
	if !ok || str == "" {
		return "", false
	}
	return str, true
}
