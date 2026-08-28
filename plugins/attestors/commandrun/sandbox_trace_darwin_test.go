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

package commandrun

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
)

// traceScript runs a real command through the whole attestor with tracing on
// and returns the resulting CommandRun. Nothing is mocked: this is
// sandbox-exec, the live unified log, and the real kernel report channel.
func traceScript(t *testing.T, cmd []string) (*CommandRun, error) {
	t.Helper()
	actx, err := attestation.NewContext(
		"darwin-sandbox-trace-test",
		[]attestation.Attestor{},
		attestation.WithWorkingDir(t.TempDir()),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(WithCommand(cmd), WithTracing(true), WithSilent(true))
	return rc, rc.Attest(actx)
}

// execedImages is the set of image paths the attestation says ran, taken from
// the per-process exec records rather than from any bookkeeping of our own.
func execedImages(rc *CommandRun) map[string]bool {
	out := make(map[string]bool)
	for i := range rc.Processes {
		if rc.Processes[i].Program != "" {
			out[rc.Processes[i].Program] = true
		}
		for _, ev := range rc.Processes[i].SyscallEvents {
			if ev.Syscall == "execve" && ev.Path != "" {
				out[ev.Path] = true
			}
		}
	}
	return out
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "step.sh")
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return p
}

// TestDarwinTraceCapturesRealProcessTree is the core claim: a real command's
// descendants are observed, INCLUDING SIP-protected platform binaries.
//
// /bin/sh is the load-bearing case. It is the exact process DYLD interposition
// cannot see — SIP strips DYLD_INSERT_LIBRARIES from platform binaries — so a
// tracer that reports /bin/sh here is doing something injection cannot.
func TestDarwinTraceCapturesRealProcessTree(t *testing.T) {
	script := writeScript(t, "#!/bin/sh\n/usr/bin/true\n/usr/bin/awk 'BEGIN{}' </dev/null\n")
	rc, err := traceScript(t, []string{"/bin/sh", script})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	images := execedImages(rc)
	for _, want := range []string{"/bin/sh", "/usr/bin/true", "/usr/bin/awk"} {
		if !images[want] {
			t.Errorf("traced tree is missing %s; got %v", want, sortedKeys(images))
		}
	}
	if rc.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", rc.ExitCode)
	}
	if len(rc.Processes) < 3 {
		t.Errorf("tree has %d processes, want at least 3 (the shell plus its children)", len(rc.Processes))
	}

	root := rc.Processes[0]
	if root.ParentPID != os.Getpid() {
		t.Errorf("root parentpid = %d, want this test process %d", root.ParentPID, os.Getpid())
	}
	// ProgramDigest is deliberately EMPTY on this backend — it reads as
	// "these bytes ran" and an allow report cannot support that. The digest
	// lives on the per-exec syscall event, where the claim is explicit.
	if root.ProgramDigest != nil {
		t.Errorf("root ProgramDigest = %v, want empty on this backend", root.ProgramDigest)
	}
	var execDigests int
	for _, sev := range root.SyscallEvents {
		if sev.Syscall == "execve" && len(sev.PathDigestAtCollectorOpen) > 0 && sev.DigestSource != "" {
			execDigests++
		}
	}
	if execDigests == 0 {
		t.Errorf("root %q carried no exec event with a digest; the per-exec evidence is where the bytes are named", root.Program)
	}

	// Every child must be attributed by kernel-read parentage or dropped;
	// a record whose parent is unknown is allowed (documented as 0) but a
	// record whose parent is a pid NOT in the tree is a bug.
	inTree := map[int]bool{}
	for i := range rc.Processes {
		inTree[rc.Processes[i].ProcessID] = true
	}
	for i := 1; i < len(rc.Processes); i++ {
		p := rc.Processes[i]
		if p.ParentPID != 0 && !inTree[p.ParentPID] {
			t.Errorf("process %d claims parent %d which is not in the tree", p.ProcessID, p.ParentPID)
		}
	}

	if rc.Summary == nil || rc.Summary.TraceModeDetail != darwinTraceBackend {
		t.Errorf("summary backend = %+v, want %q", rc.Summary, darwinTraceBackend)
	}
	if rc.Summary.Diagnostics.Darwin == nil {
		t.Fatal("summary carries no darwin diagnostics")
	}
	if rc.Summary.Diagnostics.Darwin.ExecReports == 0 {
		t.Error("darwin diagnostics report zero execs for a tree that clearly exec'd")
	}
	t.Logf("images: %v", sortedKeys(images))
	t.Logf("diagnostics: %+v", rc.Summary.Diagnostics.Darwin)
}

// TestDarwinTraceCheatDoesNotShowWork is the whole product in one test.
//
// Both commands exit 0. One does the work, the other is the cheapest possible
// lie — the `"test": "exit 0"` shortcut an agent reaches for when a policy pins
// a command. Before this tracer both produced byte-identical evidence, because
// a macOS attestation carried only cmd and exitcode. The tree is what tells
// them apart, and this test fails the moment that stops being true.
func TestDarwinTraceCheatDoesNotShowWork(t *testing.T) {
	honest := writeScript(t, "#!/bin/sh\n/usr/bin/true\n")
	cheat := writeScript(t, "#!/bin/sh\nexit 0\n")

	honestRun, err := traceScript(t, []string{"/bin/sh", honest})
	if err != nil {
		t.Fatalf("honest Attest: %v", err)
	}
	cheatRun, err := traceScript(t, []string{"/bin/sh", cheat})
	if err != nil {
		t.Fatalf("cheat Attest: %v", err)
	}

	// The exit codes agree — that is the point. Anything gating on exit
	// status alone cannot separate these two runs.
	if honestRun.ExitCode != 0 || cheatRun.ExitCode != 0 {
		t.Fatalf("both runs must exit 0; got honest=%d cheat=%d", honestRun.ExitCode, cheatRun.ExitCode)
	}

	honestImages := execedImages(honestRun)
	cheatImages := execedImages(cheatRun)
	if !honestImages["/usr/bin/true"] {
		t.Errorf("honest run's tree lacks the work it did: %v", sortedKeys(honestImages))
	}
	if cheatImages["/usr/bin/true"] {
		t.Errorf("cheating run's tree claims work it never did: %v", sortedKeys(cheatImages))
	}
	if !cheatImages["/bin/sh"] {
		t.Errorf("cheating run's tree lost the shell that ran it: %v", sortedKeys(cheatImages))
	}
	t.Logf("honest tree: %v", sortedKeys(honestImages))
	t.Logf("cheat  tree: %v", sortedKeys(cheatImages))
}

// TestDarwinSignedBytesCarryTheTree checks the SIGNED BYTES, not the struct.
//
// v2_marshal.go emits only the sections in its specs list, each behind its own
// inclusion predicate; a populated struct field whose section is missing or
// gated off is silently dropped from what actually gets signed. That already
// cost a production outage once with exitcode. Populating Processes is worth
// nothing if MarshalJSON drops it, so assert on the wire form.
func TestDarwinSignedBytesCarryTheTree(t *testing.T) {
	script := writeScript(t, "#!/bin/sh\n/usr/bin/true\n")
	rc, err := traceScript(t, []string{"/bin/sh", script})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}

	signed, err := rc.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var body map[string]json.RawMessage
	if err := json.Unmarshal(signed, &body); err != nil {
		t.Fatalf("signed body is not an object: %v", err)
	}
	for _, key := range []string{"_meta", "processes", "paths", "digests", "exitcode", "summary"} {
		if _, ok := body[key]; !ok {
			t.Errorf("signed body has no %q section; keys = %v", key, sortedKeys(rawKeys(body)))
		}
	}

	var v02 V02Predicate
	if err := json.Unmarshal(signed, &v02); err != nil {
		t.Fatalf("decode signed body: %v", err)
	}
	if len(v02.Processes) == 0 {
		t.Fatal("signed body carries an EMPTY processes array — exactly the pre-tracer shape")
	}
	// PATHS must be populated from the exec'd images. DIGESTS is the interned
	// digest table, which on this backend is fed by the per-exec events rather
	// than by OpenedFiles — that map is withheld here, because a generic
	// file-digest map cannot carry a collector-time observation without its
	// consumers reading it as the bytes that ran.
	if len(v02.Paths) == 0 {
		t.Fatalf("signed body has paths=%d, want the exec'd images", len(v02.Paths))
	}

	// The exec'd images must survive interning: resolve the ids the same way
	// a verifier would rather than trusting a substring match on the bytes.
	seen := map[string]bool{}
	for _, p := range v02.Processes {
		if p.ExecPathID >= 0 && p.ExecPathID < len(v02.Paths) {
			seen[v02.Paths[p.ExecPathID]] = true
		}
		for _, sc := range p.Syscalls {
			if sc.Path != "" {
				seen[sc.Path] = true
			}
		}
	}
	// The root is always proven: it is the pid this code started.
	if !seen["/bin/sh"] {
		t.Errorf("signed body's interned tree is missing /bin/sh; got %v", sortedKeys(seen))
	}
	// The CHILD is the contract's interesting case. /usr/bin/true exits in
	// microseconds, so on a loaded machine its kernel facts can be gone
	// before the poll — the documented residual — and this backend then
	// carries it as an UNPROVEN exec instead of a tree member. Both are
	// valid; the thing that must never happen is the exec disappearing from
	// both, which is exactly what an earlier revision did and what this
	// assertion exists to catch. (Demanding it always land in the tree
	// asserted the lucky path: it failed roughly one run in six at load ~50,
	// and it would pass while unprovenExecs was broken.)
	darwin := v02.Summary.Diagnostics.Darwin
	if !seen["/usr/bin/true"] {
		if darwin == nil || (len(darwin.UnprovenExecs) == 0 && darwin.UnprovenPIDs == 0) {
			t.Errorf("the child's exec is in neither the tree nor the unproven list; it was silently dropped. tree=%v diag=%+v",
				sortedKeys(seen), darwin)
		} else {
			t.Logf("child exec'd /usr/bin/true and exited before its facts could be read: carried as unproven (execs=%d pids=%d), which is the documented behaviour",
				len(darwin.UnprovenExecs), darwin.UnprovenPIDs)
		}
	}
	if v02.Summary == nil || darwin == nil {
		t.Error("signed body dropped the darwin trace diagnostics")
	} else if darwin.Note == "" {
		t.Error("signed body carries darwin diagnostics with no statement of the backend's limits")
	}

	// The shape a verifier actually receives, printed so a reader of CI
	// output can compare it against the pre-tracer macOS predicate, whose
	// keys were the same list with processes EMPTY and paths/digests null.
	t.Logf("signed top-level keys: %v", sortedKeys(rawKeys(body)))
	t.Logf("signed _meta: version=%s captureMode=%s traceBackend=%s counts=%+v",
		v02.Meta.Version, v02.Meta.CaptureMode, v02.Meta.TraceBackend, v02.Meta.Counts)
	if v02.Meta.TraceBackend != darwinTraceBackend {
		t.Errorf("_meta.traceBackend = %q, want %q", v02.Meta.TraceBackend, darwinTraceBackend)
	}

	// Round-trip through the verifier-side decoder: what a policy reads back
	// must be the tree the producer recorded.
	var decoded CommandRun
	if err := decoded.UnmarshalJSON(signed); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	// Same contract as above, on the verifier's side: whatever the producer
	// recorded must survive the round trip. When the child was proven, the
	// decoded tree carries its image; when the facts race lost, the
	// diagnostics carry the gap — and losing THAT would be the same silent
	// drop in a different place.
	if seen["/usr/bin/true"] {
		if !execedImages(&decoded)["/usr/bin/true"] {
			t.Error("verifier-side decode lost the exec the producer recorded")
		}
	} else {
		dd := decoded.Summary
		if dd == nil || dd.Diagnostics.Darwin == nil ||
			(len(dd.Diagnostics.Darwin.UnprovenExecs) == 0 && dd.Diagnostics.Darwin.UnprovenPIDs == 0) {
			t.Errorf("verifier-side decode lost the unproven-exec accounting the producer recorded: %+v", dd)
		}
	}
}

// TestDarwinTraceRefusesWithoutSandboxExec proves the honest-degradation rule:
// when the sandbox tool is unusable the attestor FAILS instead of running the
// command untraced and emitting an attestation shaped as though a tree had
// been observed.
func TestDarwinTraceRefusesWithoutSandboxExec(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	restore := sandboxExecPath
	sandboxExecPath = filepath.Join(t.TempDir(), "no-such-sandbox-exec")
	t.Cleanup(func() { sandboxExecPath = restore })

	rc, err := traceScript(t, []string{"/bin/sh", "-c", "/usr/bin/touch " + marker})
	if err == nil {
		t.Fatal("Attest succeeded with no sandbox-exec; it must refuse")
	}
	if !strings.Contains(err.Error(), "sandbox-exec") {
		t.Errorf("error does not name the missing tool: %v", err)
	}
	if len(rc.Processes) != 0 {
		t.Errorf("a refused trace still published %d processes", len(rc.Processes))
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Error("the command RAN despite tracing being impossible; it must not have")
	}
}

// TestDarwinTraceRefusesWhenLogChannelIsDead covers the other half: the
// sandbox works but the report channel delivers nothing. A tracer that shrugged
// here would emit an empty tree, which reads exactly like a command that did
// nothing — the cheat's signature.
func TestDarwinTraceRefusesWhenLogChannelIsDead(t *testing.T) {
	restore := logToolPath
	logToolPath = "/usr/bin/false"
	t.Cleanup(func() { logToolPath = restore })

	_, err := traceScript(t, []string{"/bin/sh", "-c", "/usr/bin/true"})
	if err == nil {
		t.Fatal("Attest succeeded with a dead log channel; it must refuse")
	}
	if !strings.Contains(err.Error(), "process tracing") {
		t.Errorf("error is not attributable to tracing: %v", err)
	}
}

// TestDarwinNestedSandboxFailsLoudly runs this very test binary inside a
// sandbox and asserts the tracer refuses there.
//
// Sandboxes do not nest: a build that already uses sandbox-exec (Bazel's
// darwin-sandbox) makes sandbox_apply fail with "Operation not permitted". The
// unacceptable outcome is running untraced while still producing an
// attestation, so this asserts on the message the inner run prints.
func TestDarwinNestedSandboxFailsLoudly(t *testing.T) {
	if os.Getenv("CILOCK_TEST_NESTED_CHILD") == "1" {
		_, err := traceScript(t, []string{"/bin/sh", "-c", "/usr/bin/true"})
		if err == nil {
			fmt.Println("NESTED-RESULT: attestor did NOT refuse")
			return
		}
		fmt.Printf("NESTED-RESULT: %v\n", err)
		return
	}

	// #nosec G204 -- the test binary's own path and fixed arguments.
	child := exec.Command(sandboxExecPath, "-p", sandboxProfile, "--",
		os.Args[0], "-test.run", "TestDarwinNestedSandboxFailsLoudly", "-test.v")
	child.Env = append(os.Environ(), "CILOCK_TEST_NESTED_CHILD=1")
	out, err := child.CombinedOutput()
	if err != nil {
		t.Fatalf("nested child run failed outright: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "NESTED-RESULT:") {
		t.Fatalf("nested child never reported a result:\n%s", text)
	}
	if strings.Contains(text, "attestor did NOT refuse") {
		t.Fatalf("inside a sandbox the attestor kept going; it must refuse:\n%s", text)
	}
	if !strings.Contains(text, "sandboxes do not nest") {
		t.Errorf("refusal does not explain nesting to the operator:\n%s", text)
	}
	t.Logf("nested refusal: %s", firstLineContaining(text, "NESTED-RESULT:"))
}

// TestDarwinReapsSessionWhenCommandNeverStarts guards the one path where the
// collector has no consumer: enableTracing succeeded, then Start failed, so
// trace() — the session's only reaper — never runs. In a CLI the leak is
// masked by process exit; in a long-lived host it is a stray `log stream` per
// failed command.
func TestDarwinReapsSessionWhenCommandNeverStarts(t *testing.T) {
	restore := darwinUnstartedReapDelay
	darwinUnstartedReapDelay = 50 * time.Millisecond
	t.Cleanup(func() { darwinUnstartedReapDelay = restore })

	c := exec.Command("/usr/bin/true")
	enableTracing(c)
	if c.Err != nil {
		t.Fatalf("enableTracing refused unexpectedly: %v", c.Err)
	}
	raw, ok := darwinSessions.Load(c)
	if !ok {
		t.Fatal("no session was registered")
	}
	sess := raw.(*sandboxSession)

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if sess.stopping.Load() {
			if _, still := darwinSessions.Load(c); still {
				t.Error("session was shut down but left in the registry")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	darwinSessions.Delete(c)
	sess.shutdown()
	t.Fatal("an unstarted command's report collector was never released")
}

// TestDarwinTraceScale runs a genuinely cold Go build under the tracer.
//
// Opt-in (CILOCK_DARWIN_SCALE_TEST=1) because it burns a private GOCACHE and
// takes minutes. It exists because the unit tests exercise trees of four
// processes, and the properties that actually matter at 10,000 — no truncation,
// no unattributed drift, tolerable overhead — cannot be inferred from four.
func TestDarwinTraceScale(t *testing.T) {
	if os.Getenv("CILOCK_DARWIN_SCALE_TEST") != "1" {
		t.Skip("set CILOCK_DARWIN_SCALE_TEST=1 to run the cold-build scale measurement")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain on PATH: %v", err)
	}
	cache := t.TempDir()
	body := fmt.Sprintf("#!/bin/sh\nexport GOCACHE=%s\nexec %s build ./...\n", cache, goBin)
	// An override so the same measurement can be pointed at a bigger tree (or
	// a synthetic exec storm) without editing the test.
	if custom := os.Getenv("CILOCK_DARWIN_SCALE_CMD"); custom != "" {
		body = "#!/bin/sh\n" + custom + "\n"
	}
	script := writeScript(t, body)

	actx, err := attestation.NewContext(
		"darwin-scale",
		[]attestation.Attestor{},
		attestation.WithWorkingDir("."),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(WithCommand([]string{"/bin/sh", script}), WithTracing(true), WithSilent(true))
	start := time.Now()
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	elapsed := time.Since(start)

	d := rc.Summary.Diagnostics.Darwin
	t.Logf("cold build traced in %v: processes=%d execs=%d forks=%d unattributed=%d unproven=%d "+
		"coalesced=%d unhashed=%d uniqueImages=%d",
		elapsed, len(rc.Processes), d.ExecReports, d.ForkReports, d.UnattributedReports,
		d.UnprovenPIDs, d.CoalescedDuplicates, d.ImagesUnhashed, len(execedImages(rc)))
	// The network stream at the same volume. Printed next to the exec numbers
	// because the question the scale run answers is whether the two streams
	// coexist: adding network reporting must not cost exec capture, and a
	// machine-wide network stream must not leak into the tree at scale either.
	t.Logf("  network: observed=%v reports=%d unattributed=%d noDestination=%d unrecognized=%d",
		d.NetworkObserved, d.NetworkReports, d.NetworkReportsUnattributed,
		d.NetworkReportsWithoutDestination, d.NetworkReportsUnrecognizedDestination)
	if d.ExecReports < 100 {
		t.Errorf("only %d execs captured from a cold Go build; that is not a scale run", d.ExecReports)
	}
	if d.UnattributedReports > d.ExecReports/10 {
		t.Errorf("dropped %d of %d reports as unattributable", d.UnattributedReports, d.ExecReports)
	}
}

func TestParseSandboxReport(t *testing.T) {
	cases := []struct {
		name   string
		msg    string
		want   sandboxEvent
		wantOK bool
	}{
		{
			name:   "exec",
			msg:    "Sandbox: bash(16171) allow process-exec* /usr/bin/true",
			want:   sandboxEvent{pid: 16171, comm: "bash", op: opExecStar, detail: "/usr/bin/true"},
			wantOK: true,
		},
		{
			name:   "shebang interpreter",
			msg:    "Sandbox: sandbox-exec(16165) allow process-exec-interpreter /bin/sh",
			want:   sandboxEvent{pid: 16165, comm: "sandbox-exec", op: opExecInterpreter, detail: "/bin/sh"},
			wantOK: true,
		},
		{
			name:   "fork carries no detail",
			msg:    "Sandbox: bash(16165) allow process-fork",
			want:   sandboxEvent{pid: 16165, comm: "bash", op: opFork},
			wantOK: true,
		},
		{
			name:   "coalesced duplicates are counted, not dropped",
			msg:    "3 duplicate reports for Sandbox: sh(16165) allow process-exec* /bin/bash",
			want:   sandboxEvent{pid: 16165, comm: "sh", op: opExecStar, detail: "/bin/bash", duplicates: 3},
			wantOK: true,
		},
		{
			name:   "path containing spaces survives",
			msg:    "Sandbox: sh(9) allow process-exec* /Users/x/My Tools/run me.sh",
			want:   sandboxEvent{pid: 9, comm: "sh", op: opExecStar, detail: "/Users/x/My Tools/run me.sh"},
			wantOK: true,
		},
		{
			name:   "comm containing parens binds to the last pid group",
			msg:    "Sandbox: weird(name)(4242) allow process-exec* /bin/ls",
			want:   sandboxEvent{pid: 4242, comm: "weird(name)", op: opExecStar, detail: "/bin/ls"},
			wantOK: true,
		},
		{
			name:   "denied exec parses and carries its refusal",
			msg:    "Sandbox: sh(77) deny(1) process-exec* /bin/ls",
			want:   sandboxEvent{pid: 77, comm: "sh", op: opExecStar, detail: "/bin/ls", denied: true},
			wantOK: true,
		},
		{name: "unrelated operation", msg: "Sandbox: passd(98302) deny(1) file-read-data /tmp/x"},
		{name: "not a sandbox report", msg: "some other kernel message"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSandboxReport(tc.msg)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (event %+v)", ok, tc.wantOK, got)
			}
			if ok && got != tc.want {
				t.Errorf("event = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestResolveTreeMembersRefusesStrangers pins the attribution rule. The report
// stream is machine-wide, so a concurrent cilock run on the same Mac emits
// byte-identical exec reports; counting those as this build's work is how an
// agent would pass a gate by starting a decoy build next to it.
func TestResolveTreeMembersRefusesStrangers(t *testing.T) {
	const root, rootPgid = 100, 100
	facts := map[int]procFacts{
		100: {ppid: 1, pgid: 100, ok: true},   // the root itself
		101: {ppid: 100, pgid: 100, ok: true}, // child of the root
		102: {ppid: 101, pgid: 999, ok: true}, // grandchild that changed group
		200: {ppid: 7, pgid: 7, ok: true},     // a stranger's process
		201: {ok: false},                      // poll lost the race: unprovable
		300: {ppid: 100, pgid: 100, ok: true}, // our own canary probe
	}
	members, unproven, groupOnly := resolveTreeMembers(root, rootPgid, facts, map[int]bool{300: true})

	for _, pid := range []int{100, 101, 102} {
		if !members[pid] {
			t.Errorf("pid %d should be in the tree", pid)
		}
	}
	for _, pid := range []int{200, 201, 300} {
		if members[pid] {
			t.Errorf("pid %d must NOT be in the tree", pid)
		}
	}
	if unproven != 1 {
		t.Errorf("unproven = %d, want 1", unproven)
	}
	if groupOnly != 0 {
		t.Errorf("groupOnly = %d, want 0 — no pid here shares the group without a proven parent", groupOnly)
	}

	// A root that is not a group leader leaves the parent chain as the only
	// evidence there is, and it must still hold the tree together.
	members, _, _ = resolveTreeMembers(root, 0, facts, map[int]bool{})
	if !members[101] || !members[102] {
		t.Error("the parent chain failed to hold the tree together for a root with no group of its own")
	}
	if members[200] {
		t.Error("a stranger entered the tree")
	}
}

// TestResolveTreeMembersRefusesASetpgidIntruder is the attack the attribution
// rule exists to refuse, written as the syscall that performs it.
//
// POSIX setpgid lets any process in the same session join an existing process
// group. An agent under gate pressure starts a helper, calls
// setpgid(0, tracee_pid), and the helper now shares the traced root's group
// while its parent chain leads somewhere else entirely. Admitting it on group
// equality would sign the helper's execs and its network connections as this
// build's work, with no parent edge in the predicate to give it away — and a
// connection admitted that way inverts the hermeticity verdict as surely as a
// dropped one does.
func TestResolveTreeMembersRefusesASetpgidIntruder(t *testing.T) {
	const root, rootPgid = 100, 100
	facts := map[int]procFacts{
		100: {ppid: 1, pgid: 100, ok: true},   // the root
		101: {ppid: 100, pgid: 100, ok: true}, // a genuine child
		// The intruder: a stranger's descendant that called setpgid(0, 100).
		// Group matches; the parent chain reaches pid 7, never the root.
		900: {ppid: 7, pgid: 100, ok: true},
		// Its own child, riding in behind it.
		901: {ppid: 900, pgid: 100, ok: true},
	}
	members, _, groupOnly := resolveTreeMembers(root, rootPgid, facts, map[int]bool{})

	if !members[100] || !members[101] {
		t.Fatal("the genuine tree did not survive, so this test proves nothing about the intruder")
	}
	for _, pid := range []int{900, 901} {
		if members[pid] {
			t.Errorf("pid %d joined the traced process group with setpgid and was admitted to the "+
				"SIGNED tree; sharing a process group is one syscall away for any process in the "+
				"session and is not evidence of descent", pid)
		}
	}
	if groupOnly != 2 {
		t.Errorf("groupOnly = %d, want 2 — an excluded intruder must be counted, so the "+
			"attestation says how much it declined to claim", groupOnly)
	}
}

// sortedKeys is shared with the rest of the package's tests (see
// script_grammar_probe_test.go) — deliberately not redeclared here.

func rawKeys(m map[string]json.RawMessage) map[string]bool {
	out := make(map[string]bool, len(m))
	for k := range m {
		out[k] = true
	}
	return out
}

func firstLineContaining(text, needle string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}
