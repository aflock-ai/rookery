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

package cli

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

const noBrowserFlag = "no-browser"

// jenkinsURLKey is Jenkins' CI marker; ciFromEnv does not know Jenkins.
const jenkinsURLKey = "JENKINS_URL"

// browserBlockedReason says why a browser ceremony (login, use) cannot finish
// here, or "" when it can. Two cases:
//
//   - --no-browser: the caller asked for no browser.
//   - CI with no terminal: nobody is there to click, and the ceremony would
//     wait five minutes for a callback that never comes.
//
// An agent's non-TTY shell on a laptop is not CI: a human and a browser are
// there, so the ceremony runs. A CI job with a terminal attached (a debug
// shell) runs too.
func browserBlockedReason(getenv func(string) string, stdinTTY, noBrowser bool) string {
	if noBrowser {
		return "--" + noBrowserFlag + " was passed"
	}
	if stdinTTY {
		return ""
	}
	ci := ciFromEnv(getenv)
	if ci == "" && getenv(jenkinsURLKey) != "" {
		ci = "jenkins"
	}
	if ci == "" && (getenv("CI") == envTrue || getenv("CI") == "1") {
		ci = "CI=" + getenv("CI")
	}
	if ci == "" {
		return ""
	}
	return fmt.Sprintf("running in CI (%s) with no terminal", ci)
}

// isTerminal reports whether r is a terminal. A reader that is not a file (a
// test buffer, a pipe cobra was handed) is not one.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) //nolint:gosec // G115: a file descriptor is a small int
}

// browserRefusal is the error for a refused ceremony: why, and the ways that
// work without a browser.
func browserRefusal(command, reason string, headless string) error {
	return fmt.Errorf("%s: %s, so a browser sign-in cannot complete here.\n%s", command, reason, headless)
}
