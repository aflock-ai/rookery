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
	"fmt"
	"sort"
)

// fixtureSource is a ProcessSource backed by a hand-built process tree.
type fixtureSource struct {
	procs map[int]ProcessInfo

	// unreadableEnv models a process whose environment the kernel refuses to
	// disclose. macOS does this for SIP-protected binaries even when the caller
	// owns the process: /bin/zsh returns argv but no environment.
	unreadableEnv map[int]bool

	// readErr models a process that vanished or belongs to another user.
	readErr map[int]bool

	envReads []envRead
}

type envRead struct {
	pid  int
	keys []string
}

func newFixtureSource(procs ...ProcessInfo) *fixtureSource {
	src := &fixtureSource{
		procs:         map[int]ProcessInfo{},
		unreadableEnv: map[int]bool{},
		readErr:       map[int]bool{},
	}
	for _, p := range procs {
		src.procs[p.PID] = vouchedFixture(p)
	}
	return src
}

// vouchedFixture runs a hand-written ProcessInfo through the REAL builder, with
// every identity read reported as successful.
//
// A fixture models a kernel read that WORKED, so it must carry the same
// coverage record a working platform source produces — otherwise every
// fixture-based walk would report incomplete and the fixtures would stop
// meaning what they say. Going through the builder rather than stamping the
// unexported field keeps the test suite honest about the same rule the sources
// follow: coverage is only ever created by recording reads. A fixture that
// wants to model a FAILED read passes an error to the builder itself.
func vouchedFixture(p ProcessInfo) ProcessInfo {
	built := newProcessInfo(p.PID, p.PPID, p.StartTime).
		executable(p.Executable, nil).
		comm(p.Comm, nil).
		argv(p.Argv, nil).
		build()
	built.Env = p.Env
	return built
}

func (f *fixtureSource) ReadProcess(pid int) (ProcessInfo, error) {
	if f.readErr[pid] {
		return ProcessInfo{}, ErrProcessNotFound
	}
	p, ok := f.procs[pid]
	if !ok {
		return ProcessInfo{}, ErrProcessNotFound
	}
	return p, nil
}

func (f *fixtureSource) ReadEnvironment(instance processInstance, keys []string) (map[string]string, error) {
	pid := instance.pid
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	f.envReads = append(f.envReads, envRead{pid: pid, keys: sorted})

	out := map[string]string{}
	if f.unreadableEnv[pid] {
		// Mirrors the platform sources: an environment the kernel refuses to
		// disclose is reported as unreadable, never as empty.
		return out, fmt.Errorf("%w: pid %d", ErrEnvironmentUnreadable, pid)
	}
	p, ok := f.procs[pid]
	if !ok {
		return out, ErrProcessNotFound
	}
	// The environment is handed out only against the exact instance the walk
	// captured. Struct equality with the stored process's instance is the
	// fixture-visible form of the platform sources' post-read validation
	// (fixtures carry no start times, so the kernel-grade check would refuse
	// everything): a caller that fabricates an instance from a bare pid
	// instead of threading the captured ProcessInfo through is refused here,
	// so the binding regresses on fixtures rather than only on a racing
	// production box.
	if p.instance() != instance {
		return map[string]string{}, fmt.Errorf("%w: pid %d environment requested with an instance that does not describe the captured process", ErrEnvironmentUnreadable, pid)
	}
	for _, k := range keys {
		if v, present := p.Env[k]; present {
			out[k] = v
		}
	}
	return out, nil
}

// keysRequestedFor returns every environment key the code asked the SOURCE for,
// against a given pid. Used to prove that a variable outside a provider's
// allowlist is never requested — of the source, which is the boundary a
// fixture can observe. What the real kernel copies out underneath is not
// visible here and is not claimed to be.
func (f *fixtureSource) keysRequestedFor(pid int) []string {
	var out []string
	for _, read := range f.envReads {
		if read.pid != pid {
			continue
		}
		out = append(out, read.keys...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Fixtures modelling real, measured process layouts.
//
// The Claude Code and Codex trees below are transcriptions of layouts read off
// a live macOS machine with sysctl (KERN_PROC_PID + KERN_PROCARGS2) on
// 2026-08-20, not invented shapes. Where a field looked surprising it is
// surprising in reality too, and the comments say why.
// ---------------------------------------------------------------------------

const (
	pidCilock  = 44795
	pidGo      = 44778
	pidZsh     = 44776
	pidSpare   = 44515
	pidPtyHost = 44502
	pidInit    = 1
)

// claudeCodeMacOSDaemonChain is the layout that breaks naive detectors.
//
// Measured chain: cilock -> go -> zsh -> "claude bg-spare" -> "claude
// bg-pty-host" -> launchd. Three things about it are load-bearing:
//
//  1. The nearest Claude Code process is a BACKGROUND SPARE WORKER. The
//     interactive session process is not an ancestor at all — the pty host's
//     parent is PID 1.
//  2. The executable basename is "2.1.234", because the binary on disk is
//     ~/.local/share/claude/versions/2.1.234. A matcher comparing the image
//     basename to "claude" finds nothing.
//  3. argv[0] is the rewritten process title "claude bg-spare", so its basename
//     is the whole two-word string. Only the first token is "claude".
//
// The pty host's argv carries the versioned path explicitly, which is why the
// vendor-chain walk exists as a fallback version source.
func claudeCodeMacOSDaemonChain() *fixtureSource {
	src := newFixtureSource(
		ProcessInfo{
			PID: pidCilock, PPID: pidGo,
			Executable: "/tmp/go-build/b001/exe/cilock",
			Comm:       "cilock",
			Argv:       []string{"cilock", "run", "--", "go", "build", "./..."},
			Env: map[string]string{
				"CLAUDECODE":                "1",
				"CLAUDE_CODE_ENTRYPOINT":    "cli",
				"CLAUDE_CODE_SESSION_ID":    "6f1c0f5e-6a1a-4a63-9f1e-2f2a4a0b1c33",
				"CLAUDE_CODE_CHILD_SESSION": "1",
				"CLAUDE_CODE_EXECPATH":      "/Users/dev/.local/share/claude/versions/2.1.234",
				// Present in the real environment and deliberately never
				// requested: a credential and a capability handle.
				"CLAUDE_CODE_MESSAGING_TOKEN":  "tok-do-not-record",
				"CLAUDE_CODE_MESSAGING_SOCKET": "/tmp/cc-daemon-501/61b3a5e4/messaging.sock",
				"CLAUDE_JOB_DIR":               "/Users/dev/.claude/jobs/3b71492b",
			},
		},
		ProcessInfo{
			PID: pidGo, PPID: pidZsh,
			Executable: "/opt/homebrew/bin/go",
			Comm:       "go",
			Argv:       []string{"go", "build", "./..."},
		},
		ProcessInfo{
			PID: pidZsh, PPID: pidSpare,
			Executable: "/bin/zsh",
			Comm:       "zsh",
			// Real argv. It names a shell-snapshot file under the user's home
			// and a temp cwd file; on a shared machine this routinely discloses
			// an unrelated project. Nothing from here may reach the predicate.
			Argv: []string{
				"/bin/zsh", "-c",
				"source /Users/dev/.claude/shell-snapshots/snapshot-zsh-1787028458755-2dy6q7.sh 2>/dev/null || true && " +
					"eval 'cd /Users/dev/proj/other-customer-repo && cilock run -- go build ./...' && pwd -P >| /tmp/claude-e519-cwd",
			},
		},
		ProcessInfo{
			PID: pidSpare, PPID: pidPtyHost,
			Executable: "/Users/dev/.local/share/claude/versions/2.1.234",
			Comm:       "2.1.234",
			Argv: []string{
				"claude bg-spare",
				"--bg-spare", "/tmp/cc-daemon-501/61b3a5e4/spare/8b1c57cc.claim.sock",
			},
			Env: map[string]string{
				"CLAUDE_CODE_ENTRYPOINT":       "cli",
				"CLAUDE_CODE_SESSION_KIND":     "background",
				"CLAUDE_CODE_MESSAGING_TOKEN":  "tok-do-not-record",
				"CLAUDE_BG_SOCKET_TOKENS_PATH": "/tmp/cc-daemon-501/61b3a5e4/tokens.json",
			},
		},
		ProcessInfo{
			PID: pidPtyHost, PPID: pidInit,
			Executable: "/Users/dev/.local/share/claude/versions/2.1.234",
			Comm:       "2.1.234",
			Argv: []string{
				"claude bg-pty-host",
				"--bg-pty-host", "/tmp/cc-daemon-501/61b3a5e4/spare/8b1c57cc.pty.sock", "200", "50",
				"--", "/Users/dev/.local/share/claude/versions/2.1.234",
				"--bg-spare", "/tmp/cc-daemon-501/61b3a5e4/spare/8b1c57cc.claim.sock",
			},
		},
		ProcessInfo{PID: pidInit, PPID: 0, Executable: "/sbin/launchd", Comm: "launchd"},
	)
	// macOS refuses the environment of SIP-protected binaries. /bin/zsh is one.
	src.unreadableEnv[pidZsh] = true
	// PID 1 refuses KERN_PROCARGS2 entirely.
	src.unreadableEnv[pidInit] = true
	return src
}

// claudeCodeShimLaunch models the other measured install shape: the process was
// exec'd through ~/.local/bin/claude, a symlink whose target carries the
// version. procargs2 records the path passed to execve — the link — while the
// kernel names the process after the image it actually loaded.
func claudeCodeShimLaunch() *fixtureSource {
	return newFixtureSource(
		ProcessInfo{PID: 100, PPID: 200, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{
			PID: 200, PPID: 1,
			Executable: "/Users/dev/.local/bin/claude",
			Comm:       "2.1.237",
			Argv:       []string{"claude", "--dangerously-skip-permissions"},
		},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/launchd", Comm: "launchd"},
	)
}

// codexHomebrewCask models `codex` installed by Homebrew: /opt/homebrew/bin/codex
// is a symlink into a Caskroom directory whose name is the version, and the real
// image basename is the release target triple.
func codexHomebrewCask() *fixtureSource {
	return newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 90, PPID: 80, Executable: "/bin/bash", Comm: "bash"},
		ProcessInfo{
			PID: 80, PPID: 1,
			Executable: "/opt/homebrew/Caskroom/codex/0.143.0/codex-aarch64-apple-darwin",
			Comm:       "codex-aarch64-a",
			Argv:       []string{"codex", "exec", "--model", "gpt-5.6-sol"},
		},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/launchd", Comm: "launchd"},
	)
}

// codexNpmInstall models the npm install shape. The `codex` on PATH is a
// `#!/usr/bin/env node` script that spawns the native binary from the
// @openai/codex-<platform> package, so cilock's nearest Codex ancestor is that
// native binary and the node shim sits one further out.
func codexNpmInstall() *fixtureSource {
	const pkgRoot = "/Users/dev/.nvm/versions/node/v22.17.1/lib/node_modules/@openai/codex"
	return newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{
			PID: 90, PPID: 80,
			Executable: pkgRoot + "/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex",
			Comm:       "codex",
			Argv:       []string{"codex", "-c", "model=gpt-5.6-sol", "-c", "model_reasoning_effort=xhigh"},
		},
		ProcessInfo{
			PID: 80, PPID: 1,
			Executable: "/Users/dev/.nvm/versions/node/v22.17.1/bin/node",
			Comm:       "node",
			Argv:       []string{"node", pkgRoot + "/bin/codex.js"},
		},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/init", Comm: "init"},
	)
}

// codexLinuxNested is the handoff's headline acceptance case:
// cilock -> bash -> codex -> cursor-agent must attest Codex.
func codexLinuxNested() *fixtureSource {
	return newFixtureSource(
		ProcessInfo{PID: 100, PPID: 90, Executable: "/usr/local/bin/cilock", Comm: "cilock"},
		ProcessInfo{PID: 90, PPID: 80, Executable: "/bin/bash", Comm: "bash"},
		ProcessInfo{
			PID: 80, PPID: 70,
			Executable: "/usr/local/bin/codex",
			Comm:       "codex",
			Argv:       []string{"codex", "--model", "gpt-test"},
		},
		ProcessInfo{PID: 70, PPID: 1, Executable: "/opt/cursor/cursor-agent", Comm: "cursor-agent"},
		ProcessInfo{PID: 1, PPID: 0, Executable: "/sbin/init", Comm: "init"},
	)
}
