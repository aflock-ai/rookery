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

//go:build darwin

package alpsevidence

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildProcArgs2Strings assembles the strings region of a KERN_PROCARGS2
// buffer exactly as the kernel lays it out (measured on macOS across eight
// exec-path lengths, one per 8-byte residue): exec path, its NUL terminator,
// NUL pad to an 8-byte boundary, argv entries each NUL-terminated, then the
// environment entries.
func buildProcArgs2Strings(exe string, argv []string, env []string) []byte {
	var b []byte
	b = append(b, exe...)
	b = append(b, 0)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	for _, a := range argv {
		b = append(b, a...)
		b = append(b, 0)
	}
	for _, e := range env {
		b = append(b, e...)
		b = append(b, 0)
	}
	return b
}

// TestProcArgs2BoundaryWithEmptyArgv0 is the regression for the argv/env
// boundary shift: the greedy pad skip consumed an empty argv[0]'s own NUL, so
// argv absorbed the first environment entry and env[0] was published as the
// last argv element. The pad is derived from the exec path length now, and an
// empty argv[0] keeps its terminator.
func TestProcArgs2BoundaryWithEmptyArgv0(t *testing.T) {
	want := map[string]struct{}{"FOO": {}, "EMPTY": {}}

	// Every residue of len(path)+1 mod 8, so the derived pad is exercised at
	// each width the kernel can produce.
	for _, exe := range []string{
		"/bin/sl", "/bin/sle", "/bin/slee", "/bin/sleep",
		"/bin/sleep1", "/bin/sleep12", "/bin/sleep123", "/bin/sleep1234",
	} {
		raw := buildProcArgs2Strings(exe, []string{"", "5"}, []string{"FOO=bar", "EMPTY="})
		snap, err := decodeProcArgs2(1, 2, raw, want)
		require.NoError(t, err, "exe %q", exe)
		assert.Equal(t, exe, snap.exe)
		assert.Equal(t, []string{"", "5"}, snap.argv,
			"exe %q: an empty argv[0] must keep its own slot", exe)
		assert.True(t, snap.envRegionSeen)
		assert.Equal(t, map[string]string{"FOO": "bar", "EMPTY": ""}, snap.env,
			"exe %q: the environment must start at FOO, not one entry late", exe)
	}
}

func TestProcArgs2BoundaryWithOrdinaryArgv(t *testing.T) {
	raw := buildProcArgs2Strings("/bin/sleep", []string{"sleep", "5"}, []string{"FOO=bar"})
	snap, err := decodeProcArgs2(1, 2, raw, map[string]struct{}{"FOO": {}})
	require.NoError(t, err)
	assert.Equal(t, []string{"sleep", "5"}, snap.argv)
	assert.Equal(t, map[string]string{"FOO": "bar"}, snap.env)
}

// TestProcArgs2ClippedEnvironmentReadsAsWithheld: for a protected target the
// kernel returns the path and argv and clips the buffer at the end of the
// argv region (measured: /bin/sleep). That is a WITHHELD environment, and it
// must be distinguishable from one that was read.
func TestProcArgs2ClippedEnvironmentReadsAsWithheld(t *testing.T) {
	raw := buildProcArgs2Strings("/bin/sleep", []string{"sleep", "5"}, nil)
	snap, err := decodeProcArgs2(1, 2, raw, map[string]struct{}{"FOO": {}})
	require.NoError(t, err)
	assert.False(t, snap.envRegionSeen, "no bytes past argv means the environment was withheld, not empty")
	assert.Empty(t, snap.env)
}

func TestProcArgs2TruncatedArgvIsAnError(t *testing.T) {
	raw := buildProcArgs2Strings("/bin/sleep", []string{"sleep"}, nil)
	_, err := decodeProcArgs2(1, 3, raw, nil)
	require.Error(t, err, "fewer than argc entries is a failed read, not a short argv")
}

// TestDarwinReadEnvironmentOfOwnProcess exercises the real sysctl end to end:
// reading our own environment must work, and — load-bearing — the generation
// computed by the capture read and by the environment read must agree, since
// ReadEnvironment now validates the env-fetch's own generation against the
// captured instance.
func TestDarwinReadEnvironmentOfOwnProcess(t *testing.T) {
	src := NewOSProcessSource()
	self, err := src.ReadProcess(os.Getpid())
	require.NoError(t, err)

	env, err := src.ReadEnvironment(self.instance(), []string{"PATH"})
	require.NoError(t, err)
	assert.NotEmpty(t, env["PATH"], "our own PATH is set and must be readable")
}

// TestDarwinWithheldEnvironmentFailsClosed: a platform binary exposes argv
// while the kernel clips its environment region — the sysctl SUCCEEDS. That
// must surface as ErrEnvironmentUnreadable, never as an authoritative empty
// environment.
func TestDarwinWithheldEnvironmentFailsClosed(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "5")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	src := NewOSProcessSource()
	p, err := src.ReadProcess(cmd.Process.Pid)
	require.NoError(t, err)

	_, err = src.ReadEnvironment(p.instance(), []string{"PATH"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEnvironmentUnreadable,
		"a clipped environment region must read as unreadable, not as empty")
}
