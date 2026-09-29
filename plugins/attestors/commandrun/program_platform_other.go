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

//go:build !linux && !darwin

package commandrun

import (
	"errors"
	"os"
	"os/exec"
)

// platformFDRealPath: GetFinalPathNameByHandleW is lane P1b. Until then the
// real path comes from the name, confirmed against the descriptor's identity
// where the platform can compare them (realPathOfDescriptor).
func platformFDRealPath(*os.File) (string, string, error) {
	return "", "", errors.New("this CI/lock build cannot read a path back from a descriptor on this platform")
}

// programFileFacts: no portable identity to report here (lane P1b).
func programFileFacts(*os.File, os.FileInfo) *ProgramFile {
	return nil
}

func pathOnlyFacts(path string) (string, string, *ProgramFile) {
	rp, source, _ := nameOnlyFacts(path)
	return rp, source, nil
}

// cilockWrapperOf: cilock starts nothing in front of the program here.
func cilockWrapperOf(programSnapshot, *exec.Cmd) (string, string, bool) {
	return "", "", false
}
