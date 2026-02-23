// Copyright 2025 The Witness Contributors
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

package systempackages

import (
	"os/exec"

	"github.com/aflock-ai/rookery/attestation"
)

type UbuntuBackend struct {
	DebianBackend
}

func NewUbuntuBackend(osReleaseFile string) Backend {
	debBackend, ok := NewDebianBackend(osReleaseFile).(*DebianBackend)
	if !ok {
		return &UbuntuBackend{}
	}
	return &UbuntuBackend{
		DebianBackend: *debBackend,
	}
}

func (b *UbuntuBackend) RunType() attestation.RunType {
	return RunType
}

type RedHatBackend struct {
	RPMBackend
}

func NewRedHatBackend(osReleaseFile string) Backend {
	rpmBackend, ok := NewRPMBackend(osReleaseFile).(*RPMBackend)
	if !ok {
		return &RedHatBackend{}
	}
	return &RedHatBackend{
		RPMBackend: *rpmBackend,
	}
}

func (b *RedHatBackend) RunType() attestation.RunType {
	return RunType
}

func (b *RedHatBackend) SetExecCommand(cmd func(name string, arg ...string) *exec.Cmd) {
	b.RPMBackend.SetExecCommand(cmd)
}
