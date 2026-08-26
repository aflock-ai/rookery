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

//go:build !linux && !darwin

package alpsevidence

// osProcessSource refuses cleanly on platforms with no implementation.
//
// Windows needs NtQueryInformationProcess or a toolhelp snapshot to read the
// parent PID and the PEB for argv; neither is implemented here. Reporting
// ErrUnsupportedPlatform makes the attestor record status "unavailable", which
// is the honest result: nothing is claimed about the invoking agent either way.
type osProcessSource struct{}

// NewOSProcessSource returns the native process source for this platform.
func NewOSProcessSource() ProcessSource { return osProcessSource{} }

func (osProcessSource) ReadProcess(int) (ProcessInfo, error) {
	return ProcessInfo{}, ErrUnsupportedPlatform
}

func (osProcessSource) ReadEnvironment(processInstance, []string) (map[string]string, error) {
	return map[string]string{}, ErrUnsupportedPlatform
}
