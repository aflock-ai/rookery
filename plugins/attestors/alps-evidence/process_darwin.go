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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// osProcessSource reads process state through sysctl.
//
// The obvious alternative — shelling out to ps(1) — cannot do the job. `ps -o
// command=` prints argv, and an agent's argv[0] is a rewritten process title,
// so ps never reveals the real image path. On this machine Claude Code's argv[0]
// is "claude bg-spare" while the executable is
// /Users/<u>/.local/share/claude/versions/2.1.234; only the latter carries the
// version. ps also cannot return another process's environment at all, and its
// space-separated output cannot be tokenized back into argv unambiguously.
//
// KERN_PROC_PID supplies ppid and start time; KERN_PROCARGS2 supplies the exec
// path, the untruncated argv, and the environment. Both are plain sysctls
// through golang.org/x/sys/unix, so this needs no cgo and no libproc linkage.
type osProcessSource struct{}

// NewOSProcessSource returns the native process source for this platform.
func NewOSProcessSource() ProcessSource { return osProcessSource{} }

func (s osProcessSource) ReadProcess(pid int) (ProcessInfo, error) {
	ki, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return ProcessInfo{}, fmt.Errorf("%w: pid %d: %v", ErrProcessNotFound, pid, err)
	}
	if ki == nil {
		return ProcessInfo{}, fmt.Errorf("%w: pid %d", ErrProcessNotFound, pid)
	}

	// PID 1 and other restricted processes refuse KERN_PROCARGS2, as does a
	// process that exited between the kinfo read above and this call — a real
	// zombie, measured. Losing the exec path and argv is not fatal: kinfo
	// already gave us the ancestry link, so the walk continues with less
	// evidence rather than stopping. It is not an ABSENCE of evidence either,
	// which is the distinction the builder records: both sources are marked as
	// gaps, and a verdict about this process degrades accordingly.
	//
	// A nil allowlist: this call wants the exec path and argv, so not one
	// environment entry is turned into a retained value here.
	snap, aerr := procArgs2(pid, nil)

	// comm comes from the kinfo read above; exe, argv and the generation come
	// from the ONE procargs2 snapshot, so those three cannot be torn across an
	// execve. comm CAN be: an exec landing between the two sysctls leaves the
	// old image's comm beside the new execution's argv. Re-reading kinfo AFTER
	// the snapshot closes that — a comm that reads the same on both sides of
	// the snapshot belongs to the same image the snapshot described (a
	// same-name re-exec keeps comm, and then the old reading is the new one).
	comm := nulTerminated(ki.Proc.P_comm[:])
	var commErr error
	if aerr == nil {
		ki2, kerr := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if kerr != nil || ki2 == nil {
			return ProcessInfo{}, fmt.Errorf("%w: pid %d changed while its identity was read", ErrProcessNotFound, pid)
		}
		if !sameDarwinProcessSlot(ki, ki2) {
			return ProcessInfo{}, fmt.Errorf("%w: pid %d changed process slot or parent while its identity was read", ErrProcessNotFound, pid)
		}
		if nulTerminated(ki2.Proc.P_comm[:]) != comm {
			commErr = fmt.Errorf("pid %d exec'd while its identity was being read; comm cannot be paired with the captured argv", pid)
		}
	}

	return newProcessInfo(
		pid,
		int(ki.Eproc.Ppid),
		formatStartTime(ki.Proc.P_starttime.Sec, int64(ki.Proc.P_starttime.Usec)),
	).
		comm(comm, commErr).
		executable(snap.exe, aerr).
		argv(snap.argv, aerr).
		execGeneration(snap.gen, aerr).
		build(), nil
}

// sameDarwinProcessSlot binds the kinfo fields captured before procargs2 to a
// second kinfo read after it. Comparing only comm does not catch PID reuse by
// another process with the same short name, and would stitch the first
// process's parent/start time to the replacement's executable and argv.
// Reparenting during capture is also refused: no single ancestry edge was
// observed for the identity snapshot.
func sameDarwinProcessSlot(before, after *unix.KinfoProc) bool {
	return before.Eproc.Ppid == after.Eproc.Ppid &&
		before.Proc.P_starttime.Sec == after.Proc.P_starttime.Sec &&
		before.Proc.P_starttime.Usec == after.Proc.P_starttime.Usec
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
	snap, err := procArgs2(pid, want)
	if err != nil {
		// macOS withholds the process-args block of some protected binaries
		// outright. That is an observation gap, not a walk failure, but it
		// must stay distinguishable from an environment that was read and
		// lacked the keys: the unreadable environment may hold a
		// higher-precedence override, so callers degrade rather than fall
		// through to lower-precedence sources (see collectEnv).
		return map[string]string{}, fmt.Errorf("%w: pid %d: %v", ErrEnvironmentUnreadable, pid, err)
	}
	if !snap.envRegionSeen {
		// The other way macOS withholds an environment, and the sneaky one:
		// for a protected target (platform binaries — /bin/zsh, /bin/sleep,
		// measured) the sysctl SUCCEEDS and returns the exec path and full
		// argv with the buffer CLIPPED at the end of the argv region. Reading
		// that as "environment read, empty" would let every lower-precedence
		// source answer questions the withheld environment may override, so
		// an absent region is reported exactly like a refused call. A
		// genuinely empty environment is indistinguishable from the clip and
		// pays the same price — fail closed toward the observation gap.
		return map[string]string{}, fmt.Errorf("%w: pid %d: the kernel returned argv but withheld the environment region", ErrEnvironmentUnreadable, pid)
	}

	// The values about to be returned come from THIS snapshot, so it is this
	// snapshot's generation that must match the captured instance — the
	// snapshot's own bytes prove which execution the environment belongs to.
	// The shape this replaces validated a THIRD read taken after the fetch: an
	// exec away and back between the fetch and that read (A→B→A) passed the
	// validation while the fetched bytes were B's, publishing one execution's
	// environment under another's identity.
	if instance.execGeneration == "" || snap.gen != instance.execGeneration {
		return map[string]string{}, fmt.Errorf("%w: pid %d exec'd between capture and environment read; the fetched environment does not belong to the captured execution", ErrEnvironmentUnreadable, pid)
	}

	// The generation digests the exec path and environment bytes, which a
	// RECYCLED pid running the same program under the same environment would
	// reproduce. The start time is what tells two runs of a pid apart, so the
	// read stays bracketed by an instance check against a fresh kinfo read.
	current, rerr := s.ReadProcess(pid)
	if rerr != nil {
		return map[string]string{}, fmt.Errorf("%w: pid %d vanished while its environment was read: %v", ErrEnvironmentUnreadable, pid, rerr)
	}
	if verr := instance.validate(current); verr != nil {
		return map[string]string{}, fmt.Errorf("%w: %v", ErrEnvironmentUnreadable, verr)
	}
	return snap.env, nil
}

// procArgs2Snapshot is ONE decoded KERN_PROCARGS2 read. The fields travel
// together because they came from a single kernel copy: exe, argv, the
// environment values and the generation all describe the same execution by
// construction, and a consumer holding the snapshot cannot pair its env with
// another read's identity — which is exactly what ReadEnvironment needs to
// validate (the previous shape returned five loose values, and the env
// consumer validated a LATER read's generation instead of this one's).
type procArgs2Snapshot struct {
	exe  string
	argv []string
	env  map[string]string
	gen  string

	// envRegionSeen reports whether any bytes existed past the argc'th argv
	// entry. For a protected target macOS returns the path and argv and CLIPS
	// the buffer at the end of argv (measured: /bin/sleep), so an absent
	// region means the environment was WITHHELD, not empty. ReadEnvironment
	// fails closed on it.
	envRegionSeen bool
}

// procArgs2 reads and decodes KERN_PROCARGS2 for pid.
//
// Layout, per the XNU sysctl implementation:
//
//	int32   argc
//	char[]  exec_path, NUL-terminated, then NUL pad to an 8-byte boundary
//	char[]  argv[0..argc-1], each NUL-terminated
//	char[]  environ entries, each NUL-terminated, then the kernel's own
//	        NUL-padded "apple" strings, to the end of the buffer
//
// The pad length is DERIVED, not scanned for: the kernel aligns the start of
// the argv strings to 8 bytes, so the pad after the exec path's terminator is
// exactly (8 - (len(path)+1) % 8) % 8 bytes (measured on macOS across eight
// path lengths covering every residue; see the boundary test). The greedy
// skip-all-NULs this replaces could not tell the pad from an EMPTY argv[0] —
// whose entire representation is one more NUL — so it consumed argv[0]'s
// terminator, shifted the argv/environment boundary one entry late, and
// published the first environment entry as the last argv element.
//
// wantEnv is the set of environment keys the caller may keep. There is no
// per-key interface to ask for: KERN_PROCARGS2 returns the whole block or
// nothing, so every variable the process holds — credentials included —
// arrives in raw. What wantEnv controls is what is turned into a RETAINED
// value: entries outside it are never converted from the buffer's bytes into
// a Go string, so nothing unlisted outlives this function or can reach the
// predicate. A nil wantEnv keeps none of it, which is what ReadProcess uses.
// The environment claims elsewhere in this package are worded to match; see
// the Privacy note in the package doc.
//
// gen is the per-execution token for processInstance.validate: a digest over
// the exec path and the environment region of this one snapshot. macOS has no
// kernel-owned exec counter, but KERN_PROCARGS2 is written by the kernel at
// exec time and returned in a single sysctl copy, so the digest names the
// exec-time (path, environment) pair this snapshot came from. The argv region
// is deliberately EXCLUDED: both priority agents rewrite their process title
// in place ("claude bg-spare"), and a live title change is not an exec.
// What the digest guarantees is exactly what ReadEnvironment needs: if the
// generation still matches at read time, the environment bytes being returned
// are byte-identical to the captured execution's, so even a re-exec this
// signal cannot see (same path, byte-identical exec-time environment) cannot
// pair one execution's values with another execution's identity — the values
// are the same bytes by construction. Hashing retains no entry as a string,
// keeping the privacy contract above; the digest is one-way, unexported and
// never serialized.
func procArgs2(pid int, wantEnv map[string]struct{}) (procArgs2Snapshot, error) {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return procArgs2Snapshot{}, fmt.Errorf("kern.procargs2 pid %d: %w", pid, err)
	}
	if len(raw) < 4 {
		return procArgs2Snapshot{}, fmt.Errorf("kern.procargs2 pid %d: short buffer (%d bytes)", pid, len(raw))
	}

	argc := int(binary.NativeEndian.Uint32(raw[:4]))
	if argc < 0 {
		return procArgs2Snapshot{}, fmt.Errorf("kern.procargs2 pid %d: negative argc", pid)
	}
	return decodeProcArgs2(pid, argc, raw[4:], wantEnv)
}

// decodeProcArgs2 decodes the strings region of a KERN_PROCARGS2 buffer. Split
// from the sysctl so the boundary arithmetic is unit-testable against
// hand-built buffers.
func decodeProcArgs2(pid, argc int, rest []byte, wantEnv map[string]struct{}) (procArgs2Snapshot, error) {
	snap := procArgs2Snapshot{env: map[string]string{}}

	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return procArgs2Snapshot{}, fmt.Errorf("kern.procargs2 pid %d: unterminated exec path", pid)
	}
	snap.exe = string(rest[:i])
	generation := sha256.New()
	generation.Write(rest[:i])
	generation.Write([]byte{0})

	// Consume exactly the path's own terminator, then AT MOST the derived pad
	// — see the layout comment above. Stopping at the first non-NUL inside the
	// pad window tolerates a shorter pad; never skipping past the window is
	// what keeps an empty argv[0]'s terminator out of it.
	i++
	for pad := (8 - (len(snap.exe)+1)%8) % 8; pad > 0 && i < len(rest) && rest[i] == 0; pad-- {
		i++
	}
	rest = rest[i:]

	// Exactly argc NUL-terminated argv entries. Fewer than argc means the
	// buffer ended inside the argv region: the identity is partial and the
	// environment region was never reached, so this is a failed read, not a
	// short argv.
	for n := 0; n < argc; n++ {
		j := bytes.IndexByte(rest, 0)
		if j < 0 {
			return procArgs2Snapshot{}, fmt.Errorf("kern.procargs2 pid %d: buffer ends inside argv (%d of %d entries)", pid, n, argc)
		}
		snap.argv = append(snap.argv, string(rest[:j]))
		rest = rest[j+1:]
	}

	snap.envRegionSeen = len(rest) > 0

	// bytes.Split, not strings.Split over the whole block: the segmentation is
	// identical, but the entries stay slices INTO raw instead of becoming a
	// string apiece. Only allowlisted variables are then converted.
	for _, entry := range bytes.Split(rest, []byte{0}) {
		// Environment region: every byte feeds the generation digest, whether
		// or not the entry is allowlisted — hashing is not retention.
		generation.Write(entry)
		generation.Write([]byte{0})
		if len(entry) == 0 {
			continue
		}
		eq := bytes.IndexByte(entry, '=')
		if eq <= 0 {
			continue
		}
		// m[string(b)] is the allocation-free lookup form, so an unlisted key
		// is compared without ever being materialized.
		if _, ok := wantEnv[string(entry[:eq])]; ok {
			snap.env[string(entry[:eq])] = string(entry[eq+1:])
		}
	}
	snap.gen = hex.EncodeToString(generation.Sum(nil))
	return snap, nil
}

func nulTerminated(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// formatStartTime renders the process start time as "sec.usec". The value is
// only meaningful when compared against another reading on the same host, which
// is exactly its purpose: distinguishing a live process from a recycled PID.
func formatStartTime(sec, usec int64) string {
	return strconv.FormatInt(sec, 10) + "." + fmt.Sprintf("%06d", usec)
}
