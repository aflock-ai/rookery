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

//go:build !darwin

package commandrun

import "testing"

// TestDarwinSandboxTrace announces itself on non-darwin hosts rather than
// vanishing. The macOS backend's tests live in sandbox_trace_darwin_test.go and
// exercise the real sandbox and the real unified log, so they cannot run — but
// a silent absence in CI output reads the same as a suite that was deleted.
func TestDarwinSandboxTrace(t *testing.T) {
	t.Skip("macOS sandbox-report tracer: darwin-only (needs sandbox-exec and the unified log)")
}

// TestDarwinSandboxNetworkTrace does the same for the network half. It is a
// separate skip rather than a line in the one above so that a reader of CI
// output on Linux can see that macOS egress observation exists and was not run
// here — the egress tests need the real Seatbelt report channel and a real
// listener, and there is nothing on this platform to fake them against.
func TestDarwinSandboxNetworkTrace(t *testing.T) {
	t.Skip("macOS network egress observation: darwin-only (needs the Seatbelt network* report channel)")
}

// TestDarwinHermeticityVerdict announces the end-to-end verdict tests, which
// build and drive the real cilock binary on macOS. On Linux the eBPF/ptrace
// backends already supply the same evidence through their own tests, so this
// one has nothing to add here.
func TestDarwinHermeticityVerdict(t *testing.T) {
	t.Skip("macOS end-to-end hermeticity verdict: darwin-only (drives cilock over the sandbox tracer)")
}
