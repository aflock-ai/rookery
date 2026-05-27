// Copyright 2021 The Witness Contributors
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

//go:build !linux

package commandrun

import (
	"errors"
	"os/exec"

	"github.com/aflock-ai/rookery/attestation"
)

func enableTracing(c *exec.Cmd) {
}

// applyTraceePrivilegeDrop is a no-op on non-Linux platforms. The
// SUDO_UID-based downgrade logic is Linux-specific (capabilities,
// SysProcAttr.Credential semantics differ on darwin/windows).
func applyTraceePrivilegeDrop(c *exec.Cmd) {
}

// preStartTracingSetup is the no-op stub for non-Linux platforms.
// On Linux this opens the eBPF consumer before c.Start(); elsewhere
// tracing is unsupported and the trace() method returns an error
// after Start, so this helper has nothing to do.
func (r *CommandRun) preStartTracingSetup() error {
	return nil
}

func (rc *CommandRun) trace(c *exec.Cmd, actx *attestation.AttestationContext) ([]ProcessInfo, error) {
	return nil, errors.New("tracing not supported on this platform")
}
