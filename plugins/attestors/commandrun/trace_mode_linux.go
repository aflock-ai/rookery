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

//go:build linux

// Trace mode selection and capability detection (#167 follow-up).
//
// Policy (per Cole's direction):
//   - DEFAULT: eBPF. The fastest path. Fails loudly if unavailable
//     with a clear message telling the user how to enable it OR how
//     to opt into ptrace as a fallback.
//   - EXPLICIT eBPF (CILOCK_TRACE_MODE=ebpf): same as default.
//   - EXPLICIT ptrace (CILOCK_TRACE_MODE=ptrace): use ptrace+seccomp,
//     skip eBPF detection. For environments where eBPF can't be
//     enabled (most non-root container configs).
//
// The detection probe mirrors the standalone tool at
// .github/probes/trace-capability-probe — kept identical so changes
// to the probe surface keep both in sync. See that tool's README for
// the matrix of GH Actions configurations tested.

package commandrun

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// traceMode is the resolved backend choice for this run.
type traceMode int

const (
	traceModeEBPF traceMode = iota
	traceModePtrace
)

func (m traceMode) String() string {
	switch m {
	case traceModeEBPF:
		return "ebpf"
	case traceModePtrace:
		return "ptrace+seccomp"
	default:
		return fmt.Sprintf("unknown(%d)", int(m))
	}
}

// selectTraceMode resolves the trace backend by inspecting the env
// var and (for the default case) probing eBPF availability. Returns
// the chosen mode, or a non-nil error if the requested backend is
// unavailable.
//
// On error, the error message is structured for human readers — it
// includes remediation steps the user can copy-paste into their CI
// config. Caller should print err.Error() to stderr and exit.
func selectTraceMode() (traceMode, error) {
	requested := strings.ToLower(strings.TrimSpace(os.Getenv(EnvVarTraceMode)))

	switch requested {
	case traceModeNamePtrace:
		// Explicit opt-in: skip detection.
		return traceModePtrace, nil

	case "", "ebpf", "auto":
		// Default behavior: detect eBPF. If available, use it. If not,
		// FAIL with a clear remediation message. (Auto is currently
		// an alias for ebpf — same hard-fail semantics. A future
		// "auto-fallback" mode could differ if there's demand.)
		probe := probeEBPFAvailable()
		if probe.available {
			return traceModeEBPF, nil
		}
		return 0, ebpfUnavailableError(probe)

	default:
		return 0, fmt.Errorf("CILOCK_TRACE_MODE=%q is not recognized; valid values: ebpf, ptrace", requested)
	}
}

// ebpfProbeResult records why eBPF was or was not available, so the
// error message can be specific.
type ebpfProbeResult struct {
	available        bool
	bpfSyscallExists bool
	mapCreateError   string // empty if succeeded
	progLoadError    string // empty if succeeded
	capEffective     string
	euid             int
}

// probeEBPFAvailable tries the minimum bpf(2) operations cilock needs
// (currently: BPF_MAP_CREATE + BPF_PROG_LOAD with PROG_TYPE_KPROBE).
// Returns success if both work; the result struct records why for
// the error message.
// MAP_CREATE + PROG_LOAD; pulling it apart would lose the audit trail.
//
//nolint:funlen // raw bpf(2) probe: minimum syscall sequence to test
func probeEBPFAvailable() ebpfProbeResult {
	var r ebpfProbeResult
	r.euid = os.Geteuid()

	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				r.capEffective = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
				break
			}
		}
	}

	const (
		bpfMapCreate      = 0
		bpfProgLoad       = 5
		bpfMapTypeHash    = 1
		bpfProgTypeKprobe = 2
	)
	sysBpf := uintptr(321) // amd64 default
	if runtime.GOARCH == "arm64" {
		sysBpf = 280
	}

	// 1. BPF_MAP_CREATE
	type bpfMapAttr struct {
		MapType    uint32
		KeySize    uint32
		ValueSize  uint32
		MaxEntries uint32
		MapFlags   uint32
	}
	mapAttr := bpfMapAttr{
		MapType:    bpfMapTypeHash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 16,
	}
	mapFd, _, errno := syscall.Syscall(sysBpf, bpfMapCreate,
		uintptr(unsafe.Pointer(&mapAttr)), unsafe.Sizeof(mapAttr)) //nolint:gosec // G103: bpf(2) requires an unsafe pointer to the attr struct by syscall contract
	if errno != 0 {
		if errors.Is(errno, unix.ENOSYS) {
			r.bpfSyscallExists = false
			r.mapCreateError = "bpf(2) syscall not available (kernel too old or removed?)"
			return r
		}
		r.bpfSyscallExists = true
		r.mapCreateError = errno.Error()
		return r
	}
	r.bpfSyscallExists = true
	_ = syscall.Close(int(mapFd)) //nolint:gosec // G115: kernel fd values fit in int

	// 2. BPF_PROG_LOAD — trivial kprobe program: r0=0; exit.
	type bpfInsn struct {
		Code   uint8
		DstReg uint8
		Off    int16
		Imm    int32
	}
	insns := []bpfInsn{
		{Code: 0xb7, Imm: 0}, // BPF_MOV64_IMM(BPF_REG_0, 0)
		{Code: 0x95},         // BPF_EXIT_INSN
	}
	type bpfProgAttr struct {
		ProgType    uint32
		InsnCnt     uint32
		Insns       uint64
		License     uint64
		LogLevel    uint32
		LogSize     uint32
		LogBuf      uint64
		KernVersion uint32
		_pad        uint32
	}
	license := []byte("GPL\x00")
	progAttr := bpfProgAttr{
		ProgType: bpfProgTypeKprobe,
		InsnCnt:  uint32(len(insns)),                           //nolint:gosec // G115: insn count for a 2-element slice always fits
		Insns:    uint64(uintptr(unsafe.Pointer(&insns[0]))),   //nolint:gosec // G103: bpf attr expects userspace pointer as u64
		License:  uint64(uintptr(unsafe.Pointer(&license[0]))), //nolint:gosec // G103: same
	}
	progFd, _, errno := syscall.Syscall(sysBpf, bpfProgLoad,
		uintptr(unsafe.Pointer(&progAttr)), unsafe.Sizeof(progAttr)) //nolint:gosec // G103: see above
	if errno != 0 {
		r.progLoadError = errno.Error()
		return r
	}
	_ = syscall.Close(int(progFd)) //nolint:gosec // G115: same

	r.available = true
	return r
}

// ebpfUnavailableError builds the user-facing error explaining how to
// either enable eBPF or opt into the ptrace fallback.
func ebpfUnavailableError(p ebpfProbeResult) error {
	var b strings.Builder
	b.WriteString("eBPF tracing is unavailable in this environment.\n\n")

	b.WriteString("Detail:\n")
	if !p.bpfSyscallExists {
		b.WriteString("  bpf(2) syscall is not implemented on this kernel.\n")
	} else if p.mapCreateError != "" {
		fmt.Fprintf(&b, "  bpf(BPF_MAP_CREATE) failed: %s\n", p.mapCreateError)
	} else if p.progLoadError != "" {
		fmt.Fprintf(&b, "  bpf(BPF_PROG_LOAD) failed: %s\n", p.progLoadError)
	}
	if p.capEffective != "" {
		fmt.Fprintf(&b, "  Current process capEff=%s, euid=%d.\n", p.capEffective, p.euid)
		b.WriteString("  eBPF requires CAP_BPF (bit 39) + CAP_PERFMON (bit 38).\n")
	}
	b.WriteString("\n")

	b.WriteString("To enable eBPF tracing (significantly faster than ptrace+seccomp):\n\n")
	b.WriteString("  [1] Grant capabilities to the cilock binary:\n")
	b.WriteString("        sudo setcap cap_bpf,cap_perfmon+ep $(which cilock)\n")
	b.WriteString("      (cilock-action attempts this automatically on hosted GH Actions runners)\n\n")
	b.WriteString("  [2] Or run cilock as root:\n")
	b.WriteString("        sudo cilock run ...\n\n")
	b.WriteString("  [3] Docker — add the required capabilities to the container:\n")
	b.WriteString("        docker run \\\n")
	b.WriteString("          --cap-add=BPF \\\n")
	b.WriteString("          --cap-add=PERFMON \\\n")
	b.WriteString("          your-image cilock run ...\n\n")
	b.WriteString("  [4] GitHub Actions with a container: config:\n")
	b.WriteString("        jobs:\n")
	b.WriteString("          build:\n")
	b.WriteString("            runs-on: ubuntu-latest\n")
	b.WriteString("            container:\n")
	b.WriteString("              image: your-image\n")
	b.WriteString("              options: --cap-add=BPF --cap-add=PERFMON\n\n")
	b.WriteString("  [5] Kubernetes — set the pod securityContext:\n")
	b.WriteString("        securityContext:\n")
	b.WriteString("          capabilities:\n")
	b.WriteString("            add: [\"BPF\", \"PERFMON\"]\n\n")

	b.WriteString("Alternatively, opt into the slower ptrace+seccomp tracing instead:\n\n")
	b.WriteString("  export CILOCK_TRACE_MODE=ptrace\n\n")
	b.WriteString("  Note: ptrace+seccomp is significantly slower than eBPF for typical builds.\n")
	b.WriteString("  Use this only if eBPF cannot be enabled in your environment.\n")

	return errors.New(b.String())
}

// logTraceModeStartup writes a one-line stderr message announcing the
// chosen mode at trace start, so users can see what cilock picked in
// their build logs.
func logTraceModeStartup(mode traceMode, requested string) {
	switch mode {
	case traceModeEBPF:
		fmt.Fprintf(os.Stderr, "cilock: tracing mode = eBPF (kernel-side capture)\n")
	case traceModePtrace:
		if requested == traceModeNamePtrace {
			fmt.Fprintf(os.Stderr, "cilock: tracing mode = ptrace+seccomp (explicitly requested via CILOCK_TRACE_MODE=ptrace)\n")
			fmt.Fprintf(os.Stderr, "cilock: note: eBPF mode is significantly faster — see https://docs.cilock.dev/tracing#ebpf if your environment supports it\n")
		} else {
			fmt.Fprintf(os.Stderr, "cilock: tracing mode = ptrace+seccomp\n")
		}
	}
}
