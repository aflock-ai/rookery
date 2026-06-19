// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package piv

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// DefaultTouchPrompt writes the standard touch reminder to stderr, but only
// when stderr is a TTY (so it doesn't pollute machine-consumed output). It is
// printed right before a blocking, touch-gated card operation.
func DefaultTouchPrompt() {
	if term.IsTerminal(int(os.Stderr.Fd())) { //nolint:gosec // G115: stderr fd is a small int, no overflow
		fmt.Fprintln(os.Stderr, "👆 Touch your security key...")
	}
}

// InteractivePINPrompt reads the PIV PIN from the controlling terminal with
// echo disabled. It is the ONLY supported way to supply the PIN: the PIN is
// never accepted as a command-line flag (threat model DELEG-5 — flags leak via
// shell history, /proc, and process listings).
func InteractivePINPrompt() PINPrompter {
	return func() (string, error) {
		fd := int(os.Stdin.Fd()) //nolint:gosec // G115: stdin fd is a small int, no overflow
		if !term.IsTerminal(fd) {
			return "", errors.New("cannot prompt for PIV PIN: stdin is not a terminal (the PIN must be entered interactively, not piped or passed as a flag)")
		}
		fmt.Fprint(os.Stderr, "Enter PIV PIN: ")
		pin, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading PIN: %w", err)
		}
		if len(pin) == 0 {
			return "", errors.New("empty PIN")
		}
		return string(pin), nil
	}
}
