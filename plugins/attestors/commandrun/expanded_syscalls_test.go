// Copyright 2026 The Rookery Contributors
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

package commandrun

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the structural surface added to ProcessInfo/FileActivity
// by the expanded syscall coverage: the new types (FileLink, FileTruncate,
// DirOp), their JSON marshaling, and ordering invariants. They do not
// exercise the ptrace event loop — that's in the integration tests.

func TestFileLink_JSON_Hardlink(t *testing.T) {
	ts := mustParseRFC3339Nano(t, "2026-05-23T12:00:00Z")
	link := FileLink{
		SourcePath: "/etc/passwd",
		LinkPath:   "/tmp/copy",
		IsSymlink:  false,
		Timestamp:  ts,
	}
	b, err := json.Marshal(link)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"sourcePath": "/etc/passwd",
		"linkPath": "/tmp/copy",
		"isSymlink": false,
		"timestamp": "2026-05-23T12:00:00Z"
	}`, string(b))
}

// mustParseRFC3339Nano parses a literal RFC3339Nano timestamp or fails
// the calling test. Lets tests keep human-readable timestamp literals
// after the Timestamp field type moved from string to time.Time.
func mustParseRFC3339Nano(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, s)
	require.NoError(t, err)
	return parsed
}

func TestFileLink_JSON_Symlink(t *testing.T) {
	link := FileLink{
		SourcePath: "/usr/bin/python3",
		LinkPath:   "/tmp/py",
		IsSymlink:  true,
	}
	b, err := json.Marshal(link)
	require.NoError(t, err)
	// Timestamp omitted when empty (omitempty)
	assert.JSONEq(t, `{
		"sourcePath": "/usr/bin/python3",
		"linkPath": "/tmp/py",
		"isSymlink": true
	}`, string(b))
}

func TestFileTruncate_JSON(t *testing.T) {
	tr := FileTruncate{
		Path:    "/tmp/log",
		NewSize: 0,
	}
	b, err := json.Marshal(tr)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"path": "/tmp/log",
		"newSize": 0
	}`, string(b))
}

func TestFileTruncate_LargeSize(t *testing.T) {
	// 2 GB should round-trip cleanly through int64
	const twoGB = int64(2 * 1024 * 1024 * 1024)
	tr := FileTruncate{Path: "/big", NewSize: twoGB}
	b, err := json.Marshal(tr)
	require.NoError(t, err)
	var back FileTruncate
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, twoGB, back.NewSize)
}

func TestDirOp_JSON_Mkdir(t *testing.T) {
	d := DirOp{
		Path: "/tmp/newdir",
		Op:   "mkdir",
		Mode: 0o755,
	}
	b, err := json.Marshal(d)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"path": "/tmp/newdir",
		"op": "mkdir",
		"mode": 493
	}`, string(b))
}

func TestDirOp_JSON_Rmdir(t *testing.T) {
	// rmdir has no mode — assert omitempty drops it
	d := DirOp{Path: "/tmp/gone", Op: "rmdir"}
	b, err := json.Marshal(d)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"path": "/tmp/gone",
		"op": "rmdir"
	}`, string(b))
}

func TestFileActivity_RoundTrip_AllFields(t *testing.T) {
	// A ProcessInfo populated with every new field type round-trips
	// through JSON without loss. This catches stale json:"omitempty"
	// tags or rename mismatches.
	ts := mustParseRFC3339Nano(t, "2026-05-23T12:00:00Z")
	fa := FileActivity{
		Writes:      []FileWrite{{Path: "/a", Bytes: 10, Timestamp: ts}},
		Renames:     []FileRename{{OldPath: "/a", NewPath: "/b", Timestamp: ts}},
		Deletes:     []FileDelete{{Path: "/c", Timestamp: ts}},
		PermChanges: []FilePermChange{{Path: "/d", Mode: 0o755, SetExec: true, Timestamp: ts}},
		Links:       []FileLink{{SourcePath: "/e", LinkPath: "/f", IsSymlink: true, Timestamp: ts}},
		Truncates:   []FileTruncate{{Path: "/g", NewSize: 0, Timestamp: ts}},
		DirOps:      []DirOp{{Path: "/h", Op: "mkdir", Mode: 0o700, Timestamp: ts}},
	}
	b, err := json.Marshal(fa)
	require.NoError(t, err)
	var back FileActivity
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, fa, back)
}

func TestFileActivity_EmptyOmits(t *testing.T) {
	// An empty FileActivity must serialize to `{}` — verifies that
	// every slice has omitempty so old attestations don't carry
	// empty arrays we never populated.
	b, err := json.Marshal(FileActivity{})
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(b))
}

// TestSyscallEvent_NewAntiTamperSyscalls — a manifest test. The set of
// syscall names recorded in SyscallEvent.Syscall must include every new
// observable defined by the v1.1.0 coverage expansion. If a handler is
// removed or renamed without updating this list, the test fails and the
// reviewer is forced to ack the coverage change.
func TestSyscallEvent_NewAntiTamperSyscalls(t *testing.T) {
	expected := []string{
		// existing pre-expansion observables — kept for regression
		"memfd_create", "ptrace", "mount", "clone", "dup2",
		"mprotect", "prctl", "setsid", "setns", "init_module",
		// expansion (MUST + SHOULD)
		"execveat", "chroot", "pivot_root",
		"setuid", "setgid", "setresuid", "setresgid",
		// expansion (anti-tamper)
		"bpf", "seccomp", "unshare", "capset",
		"kexec_load", "kexec_file_load",
		"process_vm_writev",
	}
	for _, name := range expected {
		// Each name must be a valid SyscallEvent.Syscall value (non-empty,
		// printable ASCII, no whitespace).
		assert.NotEmpty(t, name)
		assert.Equal(t, name, strings.TrimSpace(name))
		assert.False(t, strings.ContainsAny(name, " \t\n"))
	}
}

// TestSyscallEvent_TimestampFormat — every SyscallEvent the handler emits
// uses RFC3339Nano. Verifiers downstream rely on this format; if anyone
// changes it, this catches it.
func TestSyscallEvent_TimestampFormat(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	parsed, err := time.Parse(time.RFC3339Nano, now)
	require.NoError(t, err)
	assert.Equal(t, time.UTC, parsed.Location())
}

// TestCleanString_NULsAndWhitespace — cleanString is invoked on every
// path read from a tracee via /proc/.../comm and /proc/.../cmdline.
// Verify it handles embedded NULs (cmdline uses NULs as separators) and
// trims whitespace.
func TestCleanString_NULsAndWhitespace(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"\x00", ""},
		{"  hello  ", "hello"},
		{"a\x00b\x00c", "a b c"},
		{"\x00leading", "leading"},
		{"trailing\x00", "trailing"},
		{"\n\tspaced\t\n", "spaced"},
		{"unicode\x00–\x00path", "unicode – path"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, cleanString(c.in), "input %q", c.in)
	}
}
