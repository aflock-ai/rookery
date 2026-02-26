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
	"bufio"
	"os"
	"os/exec"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
)

type RPMBackend struct {
	osReleaseFile string
	execCommand   func(name string, arg ...string) *exec.Cmd
}

func NewRPMBackend(osReleaseFile string) Backend {
	return &RPMBackend{
		osReleaseFile: osReleaseFile,
		execCommand:   exec.Command,
	}
}

func (r *RPMBackend) DetermineOSInfo() (string, string, string, error) {
	file, err := os.Open(r.osReleaseFile)
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = file.Close() }()

	var distribution, version string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"")

		switch key {
		case "ID":
			distribution = value
		case "VERSION_ID":
			version = value
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", "", err
	}

	return "linux", distribution, version, nil
}

func (r *RPMBackend) GatherPackages() ([]Package, error) {
	// Security: use absolute path to rpm binary to prevent PATH manipulation
	// attacks where a malicious "rpm" binary in the PATH could be executed
	// instead of the system package manager.
	cmd := r.execCommand("/usr/bin/rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var packages []Package
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) == 2 {
			packages = append(packages, Package{
				Name:    parts[0],
				Version: parts[1],
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}

// SetExecCommand allows setting a custom exec.Command function for testing
func (r *RPMBackend) SetExecCommand(cmd func(name string, arg ...string) *exec.Cmd) {
	r.execCommand = cmd
}

// RunType returns the run type for the RPM backend
func (r *RPMBackend) RunType() attestation.RunType {
	return RunType
}
