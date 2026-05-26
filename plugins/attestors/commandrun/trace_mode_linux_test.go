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

package commandrun

import (
	"os"
	"strings"
	"testing"
)

func TestSelectTraceMode_ExplicitPtrace(t *testing.T) {
	t.Setenv(EnvVarTraceMode, "ptrace")
	mode, err := selectTraceMode()
	if err != nil {
		t.Fatalf("expected ptrace mode to succeed, got: %v", err)
	}
	if mode != traceModePtrace {
		t.Fatalf("expected traceModePtrace, got %v", mode)
	}
}

func TestSelectTraceMode_DefaultFallsToError_WhenCapsAbsent(t *testing.T) {
	// In CI / test env without CAP_BPF, default should error with the
	// remediation message. We verify the message content, not the
	// exact errno (kernel-dependent).
	t.Setenv(EnvVarTraceMode, "")

	// Skip if running as root or with CAP_BPF (eBPF would succeed,
	// invalidating the test premise).
	if probeEBPFAvailable().available {
		t.Skip("eBPF available in this environment; default-mode error test requires unprivileged env")
	}

	_, err := selectTraceMode()
	if err == nil {
		t.Fatal("expected default mode to fail when CAP_BPF unavailable")
	}
	msg := err.Error()

	wantSubstrings := []string{
		"eBPF tracing is unavailable",
		"setcap cap_bpf,cap_perfmon+ep",
		"sudo cilock run",
		"--cap-add=BPF",
		"options: --cap-add=BPF --cap-add=PERFMON",
		"CILOCK_TRACE_MODE=ptrace",
		"slower",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q\n--- full message ---\n%s", want, msg)
		}
	}
}

func TestSelectTraceMode_ExplicitEbpf_FailsLoudly(t *testing.T) {
	t.Setenv(EnvVarTraceMode, "ebpf")
	if probeEBPFAvailable().available {
		t.Skip("eBPF available; can't test failure path")
	}
	_, err := selectTraceMode()
	if err == nil {
		t.Fatal("expected explicit ebpf request to fail without caps")
	}
	if !strings.Contains(err.Error(), "eBPF tracing is unavailable") {
		t.Errorf("error message doesn't match: %v", err)
	}
}

func TestSelectTraceMode_UnknownValue(t *testing.T) {
	t.Setenv(EnvVarTraceMode, "fanotify-xyz")
	_, err := selectTraceMode()
	if err == nil {
		t.Fatal("expected unknown mode to error")
	}
	if !strings.Contains(err.Error(), "not recognized") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestErrorMessageHumanReadable does a smoke check that the error
// message is actually formatted for humans — no raw structs, has
// numbered remediation steps, mentions the env-var fallback.
func TestErrorMessageHumanReadable(t *testing.T) {
	probe := ebpfProbeResult{
		bpfSyscallExists: true,
		mapCreateError:   "operation not permitted",
		capEffective:     "0000000000000000",
		euid:             1001,
	}
	err := ebpfUnavailableError(probe)
	msg := err.Error()
	if !strings.HasPrefix(msg, "eBPF tracing is unavailable") {
		t.Errorf("message should start with the headline; got: %.80s...", msg)
	}
	if !strings.Contains(msg, "  [1]") || !strings.Contains(msg, "  [5]") {
		t.Errorf("message should have numbered remediation steps")
	}
	if !strings.Contains(msg, "capEff=0000000000000000") {
		t.Errorf("message should surface the capEff value for diagnosis")
	}
	if !strings.Contains(msg, "euid=1001") {
		t.Errorf("message should surface the euid")
	}
}

func TestLogTraceModeStartup_DoesntPanic(t *testing.T) {
	// Just check the function runs without panicking. Output goes to
	// stderr which we can't easily intercept here without redirecting.
	logTraceModeStartup(traceModeEBPF, "")
	logTraceModeStartup(traceModePtrace, "ptrace")
	logTraceModeStartup(traceModePtrace, "")
	_ = os.Stderr
}
