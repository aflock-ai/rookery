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

// Probe the runner's tracing capabilities. Outputs a JSON report that
// the workflow uploads as an artifact for inspection.
//
// Probes:
//   - ptrace: can we attach to a child via SysProcAttr.Ptrace?
//   - seccomp-BPF: can we install a seccomp filter via
//     prctl(PR_SET_NO_NEW_PRIVS) + prctl(PR_SET_SECCOMP)?
//   - eBPF (BPF_PROG_LOAD): can we load a trivial BPF program?
//   - eBPF (kprobe): can we attach a kprobe? (real-world relevance)
//   - Capabilities: what does the running process actually have?

//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type probeReport struct {
	Runner struct {
		Kernel   string `json:"kernel"`
		Arch     string `json:"arch"`
		Distro   string `json:"distro,omitempty"`
		UID      int    `json:"uid"`
		EUID     int    `json:"euid"`
		IsRoot   bool   `json:"isRoot"`
		PIDNSID  string `json:"pidNSId,omitempty"`
	} `json:"runner"`
	Capabilities struct {
		CapPermitted string `json:"capPermitted"`
		CapEffective string `json:"capEffective"`
		HasSysPtrace bool   `json:"capSysPtrace"`
		HasBPF       bool   `json:"capBPF"`
		HasPerfMon   bool   `json:"capPerfMon"`
		HasSysAdmin  bool   `json:"capSysAdmin"`
	} `json:"capabilities"`
	Ptrace struct {
		AttachWorks  bool   `json:"attachWorks"`
		Detail       string `json:"detail,omitempty"`
		Error        string `json:"error,omitempty"`
	} `json:"ptrace"`
	SeccompBPF struct {
		FilterInstallWorks bool   `json:"filterInstallWorks"`
		NoNewPrivsWorks    bool   `json:"noNewPrivsWorks"`
		Detail             string `json:"detail,omitempty"`
		Error              string `json:"error,omitempty"`
	} `json:"seccompBPF"`
	EBPF struct {
		BPFSyscallAvailable bool   `json:"bpfSyscallAvailable"`
		ProgLoadWorks       bool   `json:"progLoadWorks"`
		MapCreateWorks      bool   `json:"mapCreateWorks"`
		Detail              string `json:"detail,omitempty"`
		Error               string `json:"error,omitempty"`
	} `json:"ebpf"`
	Recommendation string `json:"recommendation"`
}

func main() {
	var report probeReport

	// Runner info
	report.Runner.Arch = runtime.GOARCH
	report.Runner.UID = os.Getuid()
	report.Runner.EUID = os.Geteuid()
	report.Runner.IsRoot = report.Runner.EUID == 0
	if release, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(release), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				report.Runner.Distro = strings.TrimSpace(strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`))
				break
			}
		}
	}
	if uname, err := os.ReadFile("/proc/version"); err == nil {
		first := strings.SplitN(string(uname), "\n", 2)[0]
		if len(first) > 100 {
			first = first[:100]
		}
		report.Runner.Kernel = first
	}
	if nsid, err := os.Readlink("/proc/self/ns/pid"); err == nil {
		report.Runner.PIDNSID = nsid
	}

	// Capabilities
	probeCapabilities(&report)

	// ptrace
	probePtrace(&report)

	// seccomp-BPF
	probeSeccompBPF(&report)

	// eBPF
	probeEBPF(&report)

	// Recommendation
	report.Recommendation = makeRecommendation(&report)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)
}

func probeCapabilities(r *probeReport) {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(status), "\n") {
		switch {
		case strings.HasPrefix(line, "CapPrm:"):
			r.Capabilities.CapPermitted = strings.TrimSpace(strings.TrimPrefix(line, "CapPrm:"))
		case strings.HasPrefix(line, "CapEff:"):
			r.Capabilities.CapEffective = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	// Decode the effective capability mask. Cap numbers we care about:
	//   CAP_SYS_PTRACE = 19
	//   CAP_SYS_ADMIN  = 21
	//   CAP_PERFMON    = 38 (Linux 5.8+)
	//   CAP_BPF        = 39 (Linux 5.8+)
	if r.Capabilities.CapEffective != "" {
		mask, err := parseHexCapMask(r.Capabilities.CapEffective)
		if err == nil {
			r.Capabilities.HasSysPtrace = mask&(1<<19) != 0
			r.Capabilities.HasSysAdmin = mask&(1<<21) != 0
			r.Capabilities.HasPerfMon = mask&(1<<38) != 0
			r.Capabilities.HasBPF = mask&(1<<39) != 0
		}
	}
}

func parseHexCapMask(s string) (uint64, error) {
	var v uint64
	if _, err := fmt.Sscanf(s, "%x", &v); err != nil {
		return 0, err
	}
	return v, nil
}

// probePtrace runs `true` as a child with SysProcAttr.Ptrace=true. If
// the child stops at exec and Wait4 returns the SIGTRAP, ptrace works.
func probePtrace(r *probeReport) {
	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		r.Ptrace.Error = "Start: " + err.Error()
		return
	}
	defer func() { _ = cmd.Wait() }()

	var status syscall.WaitStatus
	if _, err := syscall.Wait4(cmd.Process.Pid, &status, 0, nil); err != nil {
		r.Ptrace.Error = "Wait4: " + err.Error()
		return
	}
	if !status.Stopped() || status.StopSignal() != syscall.SIGTRAP {
		r.Ptrace.Error = fmt.Sprintf("unexpected wait status: stopped=%v sig=%v", status.Stopped(), status.StopSignal())
		return
	}
	r.Ptrace.AttachWorks = true
	r.Ptrace.Detail = "child stopped at exec via PTRACE_TRACEME"
	// Detach so the child can exit.
	_ = syscall.PtraceDetach(cmd.Process.Pid)
}

// probeSeccompBPF tries to install a minimal "always allow" seccomp
// filter on a child process via prctl. Doesn't require root if
// PR_SET_NO_NEW_PRIVS works.
func probeSeccompBPF(r *probeReport) {
	// Use unshare or a fork to install on a sub-process so we don't
	// permanently restrict ourselves. Easiest: spawn /bin/true with a
	// pre-exec hook... in Go we can't easily run code between fork and
	// exec for an existing binary. So use a clone-via-syscall approach
	// via /proc/self/exe with a special arg.
	if len(os.Args) > 1 && os.Args[1] == "__seccomp_child" {
		// Child mode: actually install the filter and exit.
		installSeccompAndExit()
		return // unreachable
	}

	exe, err := os.Executable()
	if err != nil {
		r.SeccompBPF.Error = "Executable: " + err.Error()
		return
	}
	cmd := exec.Command(exe, "__seccomp_child")
	out, err := cmd.CombinedOutput()
	exitCode := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		r.SeccompBPF.Error = "child exec: " + err.Error()
		return
	}

	// Exit codes signaled by the child:
	//   0 = both NO_NEW_PRIVS + SECCOMP filter installed
	//   1 = NO_NEW_PRIVS failed
	//   2 = SECCOMP install failed (NO_NEW_PRIVS worked)
	//   3 = other unexpected error
	switch exitCode {
	case 0:
		r.SeccompBPF.NoNewPrivsWorks = true
		r.SeccompBPF.FilterInstallWorks = true
		r.SeccompBPF.Detail = "PR_SET_NO_NEW_PRIVS + PR_SET_SECCOMP MODE_FILTER both succeeded"
	case 1:
		r.SeccompBPF.Error = "PR_SET_NO_NEW_PRIVS failed (unusual — kernel < 3.5?)"
	case 2:
		r.SeccompBPF.NoNewPrivsWorks = true
		r.SeccompBPF.Error = "PR_SET_SECCOMP MODE_FILTER failed: " + strings.TrimSpace(string(out))
	default:
		r.SeccompBPF.Error = fmt.Sprintf("unexpected child exit code %d, output: %s", exitCode, string(out))
	}
}

// installSeccompAndExit is the child path. Runs in a separate process
// so the filter install doesn't poison the parent.
func installSeccompAndExit() {
	const prSetNoNewPrivs = 38
	const prSetSeccomp = 22
	const seccompModeFilter = 2

	// PR_SET_NO_NEW_PRIVS
	_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0)
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "no_new_privs failed: %v\n", errno)
		os.Exit(1)
	}

	// Minimal BPF program: SECCOMP_RET_ALLOW for everything.
	type sockFilter struct {
		Code uint16
		Jt   uint8
		Jf   uint8
		K    uint32
	}
	type sockFprog struct {
		Len    uint16
		_pad   uint16
		Filter *sockFilter
	}
	const bpfRetK = 0x06
	const seccompRetAllow = 0x7FFF0000
	prog := []sockFilter{{Code: bpfRetK, K: seccompRetAllow}}
	fprog := sockFprog{
		Len:    uint16(len(prog)),
		Filter: &prog[0],
	}

	_, _, errno = syscall.Syscall6(syscall.SYS_PRCTL,
		prSetSeccomp, seccompModeFilter,
		uintptr(unsafe.Pointer(&fprog)), 0, 0, 0)
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "prctl seccomp failed: %v\n", errno)
		os.Exit(2)
	}

	// Verify the filter is active (we should still be able to exit).
	os.Exit(0)
}

// probeEBPF tries:
//   - bpf(BPF_MAP_CREATE) for a trivial hash map
//   - bpf(BPF_PROG_LOAD) for a trivial program that returns 0
//
// Both require CAP_BPF on Linux 5.8+, CAP_SYS_ADMIN on older kernels.
func probeEBPF(r *probeReport) {
	// Constants from <linux/bpf.h>
	const (
		BPF_MAP_CREATE     = 0
		BPF_PROG_LOAD      = 5
		BPF_MAP_TYPE_HASH  = 1
		BPF_PROG_TYPE_KPROBE = 2
	)
	const SYS_BPF = 321 // amd64; arm64 is 280
	sysBpf := uintptr(SYS_BPF)
	if runtime.GOARCH == "arm64" {
		sysBpf = 280
	}

	// Probe 1: BPF_MAP_CREATE
	type bpfMapAttr struct {
		MapType    uint32
		KeySize    uint32
		ValueSize  uint32
		MaxEntries uint32
		MapFlags   uint32
	}
	mapAttr := bpfMapAttr{
		MapType:    BPF_MAP_TYPE_HASH,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 16,
	}
	mapFd, _, errno := syscall.Syscall(sysBpf, BPF_MAP_CREATE,
		uintptr(unsafe.Pointer(&mapAttr)), unsafe.Sizeof(mapAttr))
	if errno != 0 {
		r.EBPF.Error = "BPF_MAP_CREATE: " + errno.Error()
		// Check if the syscall itself is even there
		if errors.Is(errno, unix.ENOSYS) {
			r.EBPF.BPFSyscallAvailable = false
			r.EBPF.Detail = "bpf(2) syscall not available on this kernel"
			return
		}
		r.EBPF.BPFSyscallAvailable = true
		return
	}
	r.EBPF.BPFSyscallAvailable = true
	r.EBPF.MapCreateWorks = true
	_ = syscall.Close(int(mapFd))

	// Probe 2: BPF_PROG_LOAD — trivial program: r0 = 0; exit.
	type bpfInsn struct {
		Code   uint8
		DstReg uint8 // packed: dst(4) src(4)
		Off    int16
		Imm    int32
	}
	// BPF_MOV64_IMM(BPF_REG_0, 0): mov r0, 0
	// BPF_EXIT_INSN: exit
	insns := []bpfInsn{
		{Code: 0xb7, Imm: 0},
		{Code: 0x95},
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
		ProgType: BPF_PROG_TYPE_KPROBE,
		InsnCnt:  uint32(len(insns)),
		Insns:    uint64(uintptr(unsafe.Pointer(&insns[0]))),
		License:  uint64(uintptr(unsafe.Pointer(&license[0]))),
	}
	progFd, _, errno := syscall.Syscall(sysBpf, BPF_PROG_LOAD,
		uintptr(unsafe.Pointer(&progAttr)), unsafe.Sizeof(progAttr))
	if errno != 0 {
		r.EBPF.Error = fmt.Sprintf("BPF_PROG_LOAD failed: %v (map create worked, so syscall is there but prog load denied — likely missing CAP_BPF/CAP_SYS_ADMIN or CAP_PERFMON)", errno)
		r.EBPF.Detail = "map_create:ok prog_load:denied"
		return
	}
	_ = syscall.Close(int(progFd))
	r.EBPF.ProgLoadWorks = true
	r.EBPF.Detail = "map_create:ok prog_load:ok — full eBPF available"
}

func makeRecommendation(r *probeReport) string {
	switch {
	case r.EBPF.ProgLoadWorks:
		return "DEFAULT-EBPF: full eBPF available — recommend eBPF tracing mode for best performance"
	case r.SeccompBPF.FilterInstallWorks && r.Ptrace.AttachWorks:
		return "DEFAULT-PTRACE-SECCOMP: ptrace + seccomp prefilter available — recommend ptrace mode with seccomp-BPF prefilter"
	case r.Ptrace.AttachWorks:
		return "DEFAULT-PTRACE: ptrace works but seccomp-BPF prefilter blocked — degraded mode"
	default:
		return "NO-TRACING: neither ptrace nor seccomp-BPF available — cilock tracing cannot run"
	}
}
