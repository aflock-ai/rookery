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

// jade:ring local

package commandrun

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestCilockBinaryBuildRechecksInputsAndNeverFallsBack(t *testing.T) {
	realGo, err := exec.LookPath("go")
	require.NoError(t, err)
	root := t.TempDir()
	module := filepath.Join(root, "module with spaces")
	dep := filepath.Join(root, "dep")
	bin := filepath.Join(root, "tools")
	for _, dir := range []string{filepath.Join(module, "cmd", "fixture"), dep, bin} {
		require.NoError(t, os.MkdirAll(dir, 0o700))
	}
	write := func(name, body string) {
		t.Helper()
		require.NoError(t, os.WriteFile(name, []byte(body), 0o600))
	}
	write(filepath.Join(module, "go.mod"), "module example.org/fixture\n\ngo 1.26.3\n\nrequire example.org/dep v0.0.0\nreplace example.org/dep => ../dep\n")
	write(filepath.Join(module, "cmd", "fixture", "main.go"), "package main\nimport (\"fmt\"; \"example.org/dep\")\nvar label = \"plain\"\nfunc main() { fmt.Print(dep.Value + \"/\" + label) }\n")
	write(filepath.Join(dep, "go.mod"), "module example.org/dep\n\ngo 1.26.3\n")
	depSource := filepath.Join(dep, "dep.go")
	write(depSource, "package dep\nconst Value = \"one\"\n")
	shim := filepath.Join(bin, "go")
	require.NoError(t, os.WriteFile(shim, []byte("#!/bin/sh\nprintf 'build\\n' >> \"$FIXTURE_BUILD_CALLS\"\nif [ \"${FIXTURE_BUILD_FAIL:-}\" = 1 ]; then exit 42; fi\nexec \"$FIXTURE_REAL_GO\" \"$@\"\n"), 0o700))
	calls := filepath.Join(root, "calls")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FIXTURE_REAL_GO", realGo)
	t.Setenv("FIXTURE_BUILD_CALLS", calls)
	t.Setenv("FIXTURE_BUILD_FAIL", "")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOFLAGS", "-p=1 -buildvcs=false")
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	build := func() []byte {
		t.Helper()
		data, err := buildCilockBytes(ctx, module)
		require.NoError(t, err)
		return data
	}
	stage := func(data []byte) string {
		t.Helper()
		name := filepath.Join(t.TempDir(), "fixture")
		require.NoError(t, os.WriteFile(name, data, 0o700))
		return name
	}
	run := func(name, want string) {
		t.Helper()
		out, err := exec.CommandContext(ctx, name).CombinedOutput()
		require.NoError(t, err, "%s", out)
		require.Equal(t, want, string(out))
	}

	first := build()
	private := stage(first)
	run(private, "one/plain")
	cache := filepath.Join(module, ".bin", "commandrun-verdict", "cilock")
	before, err := os.Stat(cache)
	require.NoError(t, err)
	second := build()
	after, err := os.Stat(cache)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after), "unchanged go build relinked the output")
	// Go may refresh the output mtime even when it retains the executable.
	require.True(t, bytes.Equal(first, second))
	second[0] ^= 0xff
	run(private, "one/plain")

	stamp, err := os.Stat(depSource)
	require.NoError(t, err)
	write(depSource, "package dep\nconst Value = \"two\"\n")
	require.NoError(t, os.Chtimes(depSource, stamp.ModTime(), stamp.ModTime()))
	run(stage(build()), "two/plain")
	t.Setenv("GOFLAGS", "-p=1 -buildvcs=false -ldflags=-X=main.label=flagged")
	run(stage(build()), "two/flagged")
	run(private, "one/plain") // another build cannot replace an executing test's copy
	write(depSource, "package dep\nconst Value = \"new\"\n")
	t.Setenv("GOFLAGS", "-p=1 -buildvcs=false -n")
	run(stage(build()), "new/plain")

	t.Setenv("GOFLAGS", "-p=1 -buildvcs=false")
	t.Setenv("FIXTURE_BUILD_FAIL", "1")
	data, err := buildCilockBytes(ctx, module)
	require.Error(t, err)
	require.Empty(t, data, "failed tool invocation returned the old binary")
	t.Setenv("FIXTURE_BUILD_FAIL", "")
	write(depSource, "package dep\nthis does not compile\n")
	data, err = buildCilockBytes(ctx, module)
	require.Error(t, err)
	require.Empty(t, data, "compile failure returned the old binary")
	log, err := os.ReadFile(calls)
	require.NoError(t, err)
	require.Equal(t, 7, strings.Count(string(log), "build\n"), "every request must invoke go build")
}

func TestCilockBinaryBuildCancellationReapsPipeHolder(t *testing.T) {
	module, bin := t.TempDir(), t.TempDir()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\n/bin/sleep 30 &\nprintf '%s\\n' \"$!\" > \"$FIXTURE_CHILD_PID\"\nwait\n"), 0o700))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FIXTURE_CHILD_PID", pidFile)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		data, err := buildCilockBytes(ctx, module)
		if len(data) != 0 {
			err = errors.New("cancelled build returned binary bytes")
		}
		done <- err
	}()
	pid := 0
	t.Cleanup(func() {
		if pid > 1 {
			_ = unix.Kill(pid, unix.SIGKILL)
		}
	})
	require.Eventually(t, func() bool {
		body, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pid, err = strconv.Atoi(strings.TrimSpace(string(body)))
		return err == nil && pid > 1
	}, 3*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		// Reap only our recorded child, including when exercising the old bug.
		_ = unix.Kill(pid, unix.SIGKILL)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("build did not release its pipe after fixture cleanup")
		}
		t.Fatal("cancelled build retained a live pipe holder and its cache lock")
	}
	lock, err := os.OpenFile(filepath.Join(module, ".bin", "commandrun-verdict", "lock"), os.O_RDWR, 0o600)
	require.NoError(t, err)
	defer func() { _ = lock.Close() }()
	require.NoError(t, unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB), "cancelled build retained its lock")
}

func TestCilockBinaryBuildWaitIsCancellable(t *testing.T) {
	module := t.TempDir()
	cache := filepath.Join(module, ".bin", "commandrun-verdict")
	require.NoError(t, os.MkdirAll(cache, 0o700))
	lock, err := os.OpenFile(filepath.Join(cache, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lock.Close()) })
	require.NoError(t, unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB))
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	data, err := buildCilockBytes(ctx, module)
	require.True(t, errors.Is(err, context.DeadlineExceeded), "lock wait: %v", err)
	require.Empty(t, data)
	_, err = os.Stat(filepath.Join(cache, "cilock"))
	require.True(t, os.IsNotExist(err), "a blocked build must not write output")
}

func TestCilockBinaryBuildRefusesRedirectedCachePaths(t *testing.T) {
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "go"), []byte("#!/bin/sh\nprintf called > \"$FIXTURE_UNEXPECTED_GO\"\nexit 98\n"), 0o700))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, component := range []string{".bin", ".bin/commandrun-verdict", ".bin/commandrun-verdict/lock", ".bin/commandrun-verdict/cilock"} {
		t.Run(component, func(t *testing.T) {
			module, outside := t.TempDir(), t.TempDir()
			called := filepath.Join(t.TempDir(), "called")
			t.Setenv("FIXTURE_UNEXPECTED_GO", called)
			name := filepath.Join(module, component)
			require.NoError(t, os.MkdirAll(filepath.Dir(name), 0o700))
			target := outside
			if filepath.Base(name) == "lock" || filepath.Base(name) == "cilock" {
				target = filepath.Join(outside, "untouched")
				require.NoError(t, os.WriteFile(target, []byte("unchanged"), 0o600))
			}
			require.NoError(t, os.Symlink(target, name))
			data, err := buildCilockBytes(t.Context(), module)
			require.Error(t, err)
			require.Empty(t, data)
			_, err = os.Stat(called)
			require.True(t, os.IsNotExist(err), "redirected cache reached go build")
			if target != outside {
				body, err := os.ReadFile(target)
				require.NoError(t, err)
				require.Equal(t, "unchanged", string(body))
			}
		})
	}
}
