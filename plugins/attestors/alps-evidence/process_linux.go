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

//go:build linux

package alpsevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// osProcessSource reads /proc. Everything it needs is a plain file read; no
// ptrace, no privilege escalation, no subprocess.
type osProcessSource struct {
	root string

	// readFile is injectable only for the torn-/proc regression. Production
	// uses os.ReadFile. Keeping the hook on the source avoids a package global
	// and makes concurrent detectors independent.
	readFile func(string) ([]byte, error)
}

// NewOSProcessSource returns the native process source for this platform.
func NewOSProcessSource() ProcessSource { return osProcessSource{root: "/proc"} }

func (s osProcessSource) read(path string) ([]byte, error) {
	if s.readFile != nil {
		return s.readFile(path)
	}
	return os.ReadFile(path) //nolint:gosec // paths are /proc/<int>/<fixed name>
}

func (s osProcessSource) ReadProcess(pid int) (ProcessInfo, error) {
	base := filepath.Join(s.root, strconv.Itoa(pid))

	statPath := filepath.Join(base, "stat")
	statBytes, err := s.read(statPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ProcessInfo{}, fmt.Errorf("%w: pid %d", ErrProcessNotFound, pid)
		}
		return ProcessInfo{}, err
	}

	ppid, startTime, err := parseProcStat(string(statBytes))
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("pid %d: %w", pid, err)
	}

	// Each identity read hands its (value, error) pair straight to the builder.
	// Readlink on exe fails for kernel threads, for processes owned by another
	// user, and for a process that exited between the stat above and this line
	// — that last case is a real, measured zombie. None of those is an error
	// worth aborting the walk over, but none of them is an ABSENCE either: the
	// builder records the gap so the verdict cannot claim this process was
	// examined.
	//
	// The identity reads are BRACKETED by the generation. /proc files are read
	// one syscall apiece, so an execve landing mid-sequence hands back a torn
	// identity — the old image's comm beside the new execution's argv — and,
	// worse, a generation belonging to a different execution than the fields
	// it travels with, which instance validation would then happily match.
	// Reading auxv before AND after closes that: the generation is published
	// only when both reads succeeded and agree, and a disagreement (an exec
	// was observed mid-capture) voids every identity field read in between,
	// so the process reports as unexamined rather than as a stitched-together
	// one. An auxv that could not be read on either side voids the identity
	// fields the same way — without the bracket nothing proves they describe
	// one execution — while the process itself still reads as a partial,
	// gap-recorded observation rather than an error (see below).
	genBefore, genBeforeErr := auxvGeneration(filepath.Join(base, "auxv"))
	exe, exeErr := os.Readlink(filepath.Join(base, "exe"))
	comm, commErr := readTrimmed(filepath.Join(base, "comm"))
	argv, argvErr := readNULSeparated(filepath.Join(base, "cmdline"))
	genAfter, genAfterErr := auxvGeneration(filepath.Join(base, "auxv"))
	statAfterBytes, statAfterErr := s.read(statPath)
	if statAfterErr != nil {
		return ProcessInfo{}, fmt.Errorf("%w: pid %d changed while its identity was read: %v", ErrProcessNotFound, pid, statAfterErr)
	}
	ppidAfter, startTimeAfter, statParseErr := parseProcStat(string(statAfterBytes))
	if statParseErr != nil {
		return ProcessInfo{}, fmt.Errorf("%w: pid %d changed while its identity was read: %v", ErrProcessNotFound, pid, statParseErr)
	}
	if ppidAfter != ppid || startTimeAfter != startTime {
		return ProcessInfo{}, fmt.Errorf("%w: pid %d changed process slot or parent while its identity was read", ErrProcessNotFound, pid)
	}
	gen, genErr := genAfter, error(nil)
	switch {
	case genBeforeErr != nil || genAfterErr != nil:
		// Without both sides of the generation bracket, the executable, comm
		// and argv reads above may describe different executions, so none of
		// them is published: every identity field is voided into a recorded
		// gap, exactly as a torn bracket below voids them. This is a PARTIAL
		// read, not a missing process — a zombie is the measured shape (its
		// pid still resolves and its stat is readable, while its mm is gone
		// and /proc/<pid>/auxv reads back empty) — and "could not look" is
		// what identityCoverage exists to record. Returning an error here
		// instead aborted the walk at the zombie and reported an ancestor
		// that was merely unreadable as a process that did not exist. The
		// fail-closed outcomes are unchanged, just carried by the builder:
		// the gaps make the ancestor incomplete (never not-detected), and
		// the empty generation makes processInstance.validate refuse every
		// follow-up read.
		unbracketed := fmt.Errorf("pid %d: execution-generation bracket unavailable: before: %v; after: %v", pid, genBeforeErr, genAfterErr)
		exeErr, commErr, argvErr, genErr = unbracketed, unbracketed, unbracketed, unbracketed
	case genBefore != genAfter:
		torn := fmt.Errorf("pid %d exec'd while its identity was being read; the fields do not describe one execution", pid)
		exeErr, commErr, argvErr, genErr = torn, torn, torn, torn
	}

	return newProcessInfo(pid, ppid, startTime).
		executable(exe, exeErr).
		comm(comm, commErr).
		argv(argv, argvErr).
		execGeneration(gen, genErr).
		build(), nil
}

// auxvGeneration derives the per-execution token from /proc/<pid>/auxv.
//
// The kernel rebuilds the auxiliary vector at EVERY execve — including one
// that re-executes the same pathname — and with stack ASLR its pointer-valued
// entries (AT_RANDOM, AT_EXECFN, AT_PLATFORM live on the freshly randomized
// stack) differ between executions regardless of whether the binary itself is
// PIE. Unlike argv (/proc/<pid>/cmdline is live process memory) and comm
// (prctl PR_SET_NAME), a process cannot rewrite its saved auxv without
// CAP_SYS_RESOURCE (prctl PR_SET_MM_AUXV), so this is the kernel-owned signal
// that separates one execution of a path from the next. Residual, accepted:
// a CAP_SYS_RESOURCE-holding process, or one that disables ASLR for itself
// (personality ADDR_NO_RANDOMIZE) before BOTH executions, can replay a
// generation — this attestor observes unprivileged agents, it does not gate
// adversaries with those levers (they could as easily ptrace the reader).
//
// auxv sits behind the same ptrace-mode-read gate as environ and exe, so
// every process whose environment or image this source can read at all also
// yields a generation; failing closed on an unreadable one (via the empty
// token, see processInfoBuilder.execGeneration) costs no reachable coverage.
// An EMPTY auxv (kernel threads) is no signal, not a matching constant.
func auxvGeneration(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is /proc/<int>/auxv
	if err != nil {
		return "", err
	}
	if len(b) == 0 {
		return "", fmt.Errorf("empty auxv: no execution-generation signal")
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// readTrimmed reads a small /proc file and trims it, reporting the read error
// rather than folding it into an empty string.
func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is /proc/<int>/<fixed name>
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s osProcessSource) ReadEnvironment(instance processInstance, keys []string) (map[string]string, error) {
	pid := instance.pid
	out := map[string]string{}
	if len(keys) == 0 {
		return out, nil
	}
	want := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		want[k] = struct{}{}
	}

	// /proc/<pid>/environ is unreadable for processes we do not own. That is a
	// normal outcome for the walk, but it must stay distinguishable from an
	// environment that was read and simply lacked the keys: an unreadable
	// environment may hold a higher-precedence override, so callers degrade
	// rather than fall through to lower-precedence sources (see collectEnv).
	b, err := os.ReadFile(filepath.Join(s.root, strconv.Itoa(pid), "environ"))
	if err != nil {
		return out, fmt.Errorf("%w: pid %d: %v", ErrEnvironmentUnreadable, pid, err)
	}

	// The read is bracketed by an instance check, exactly as OpenProcessImage
	// brackets its open: pid and start time both survive execve, and a pid can
	// be recycled outright, so environment bytes read by number alone could
	// belong to a different program than the captured executable, argv and
	// ancestry describe. Re-reading the process AFTER the environ read and
	// validating it against the captured instance refuses that pairing rather
	// than publishing it.
	current, rerr := s.ReadProcess(pid)
	if rerr != nil {
		return map[string]string{}, fmt.Errorf("%w: pid %d vanished while its environment was read: %v", ErrEnvironmentUnreadable, pid, rerr)
	}
	if verr := instance.validate(current); verr != nil {
		return map[string]string{}, fmt.Errorf("%w: %v", ErrEnvironmentUnreadable, verr)
	}

	for _, kv := range strings.Split(string(b), "\x00") {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		if _, ok := want[kv[:i]]; ok {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out, nil
}

// OpenProcessImage opens /proc/<pid>/exe: a handle to the binary the process
// actually exec'd, maintained by the kernel, valid even after the path on disk
// was replaced or deleted. This is the strongest executable-evidence binding
// available anywhere in this attestor — see processImageOpener.
//
// The open is bracketed by an instance check. /proc/<pid> is addressed by a
// REUSABLE number: between the walk capturing this process and this open, the
// original can exit and its pid be handed to something else, at which point the
// handle would describe a different program entirely. Re-reading the start time
// AFTER the open and comparing it to the captured one closes that window — a
// pid recycled at any point before the handle existed changes the start time,
// and a change refuses the handle rather than publishing it.
func (s osProcessSource) OpenProcessImage(instance processInstance) (*os.File, error) {
	f, err := os.Open(filepath.Join(s.root, strconv.Itoa(instance.pid), "exe"))
	if err != nil {
		return nil, err
	}
	// Read the process back through the same /proc directory the handle came
	// from. A mismatch means the number was reused and the handle is not this
	// process's image.
	current, rerr := s.ReadProcess(instance.pid)
	if rerr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("alps-evidence: pid %d vanished while its image was opened: %w", instance.pid, rerr)
	}
	if verr := instance.validate(current); verr != nil {
		_ = f.Close()
		return nil, verr
	}
	return f, nil
}

// parseProcStat pulls ppid (field 4) and starttime (field 22) out of
// /proc/<pid>/stat.
//
// The comm field is field 2 and is wrapped in parentheses; it can itself
// contain spaces and parentheses, so the only safe split point is the LAST
// closing parenthesis in the line.
func parseProcStat(stat string) (ppid int, startTime string, err error) {
	end := strings.LastIndex(stat, ")")
	if end < 0 || end+2 > len(stat) {
		return 0, "", fmt.Errorf("malformed /proc stat line")
	}
	fields := strings.Fields(stat[end+2:])
	// fields[0] is state (original field 3), so ppid (field 4) is fields[1]
	// and starttime (field 22) is fields[19].
	const startTimeIdx = 19
	if len(fields) <= startTimeIdx {
		return 0, "", fmt.Errorf("short /proc stat line: %d fields after comm", len(fields))
	}
	ppid, err = strconv.Atoi(fields[1])
	if err != nil {
		return 0, "", fmt.Errorf("parse ppid: %w", err)
	}
	return ppid, fields[startTimeIdx], nil
}

// readNULSeparated reads a NUL-separated /proc file. The error is RETURNED
// rather than collapsed into a nil slice: an empty argv and an unreadable argv
// are different facts, and conflating them is what let a partially-read process
// pass for an examined one.
func readNULSeparated(path string) ([]string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is /proc/<int>/<fixed name>
	if err != nil {
		return nil, err
	}
	return splitNULTerminated(b), nil
}
