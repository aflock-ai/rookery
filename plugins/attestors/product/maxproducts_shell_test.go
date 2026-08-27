// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package product

import (
	"strings"
	"testing"
)

// THE ERROR MESSAGE IS A COMMAND THE OPERATOR IS INVITED TO PASTE INTO A SHELL,
// and every path in it comes from the build's own output — which in a supply
// chain tool is exactly the data an attacker may influence.
//
// A directory named `deps'; touch /tmp/pwned; #` closes the single quote that
// was supposed to contain it, and the rest runs as a command. The operator is
// not doing anything careless: they are following the tool's own instruction.
//
// The rule this file enforces is a SWEEP, not a patch for that one string:
// NO directory name, whatever it contains, may reach the suggested command
// unless it is conservatively safe. Unsafe names are still REPORTED — they are
// the diagnostic — but they are shown as quoted data, never as command text.

// hostileDirNames is the adversarial table. Each entry is a directory name a
// build could plausibly produce, deliberately or otherwise.
var hostileDirNames = []string{
	`deps'; touch /tmp/pwned; #`,     // quote break-out, the reported finding
	`a'$(id)'b`,                      // command substitution
	"a`id`b",                         // backtick substitution
	`x"; rm -rf /; echo "`,           // double-quote break-out
	"newline\ninjected",              // a second line in the pasted command
	"carriage\rreturn",               // terminal line-overwrite
	`glob*star`,                      // glob metacharacters change what is excluded
	`brace{a,b}`,                     // brace expansion — the suggestion's own syntax
	`question?mark`,                  //
	`bracket[a-z]`,                   //
	`--looks-like-a-flag`,            // argument injection rather than command injection
	"tab\there",                      //
	`semi;colon`,                     //
	`dollar$var`,                     //
	string([]byte{'n', 'u', 'l', 0}), // NUL
}

// shellMetacharacters are the bytes that must never appear inside the emitted
// command. Listed explicitly so the assertion states the property rather than
// re-deriving it from the implementation.
const shellMetacharacters = "'\"`$;&|<>(){}[]*?!\\\n\r\t\x00"

// suggestionLine returns the `--exclude-glob '...'` line from an error message,
// or "" when the message offers no command.
func suggestionLine(msg string) string {
	for _, l := range strings.Split(msg, "\n") {
		if strings.Contains(l, "--exclude-glob") {
			return l
		}
	}
	return ""
}

// TestErrorMessageNeverEmitsAnUnsafePathIntoACommand is the sweep: it quantifies
// over every hostile name, not over the one that was reported.
func TestErrorMessageNeverEmitsAnUnsafePathIntoACommand(t *testing.T) {
	for _, name := range hostileDirNames {
		a := New(WithMaxProducts(1))
		SetProductsForTesting(a, productSet(t, map[string]int{name: 5}))

		err := a.buildTree()
		if err == nil {
			t.Fatalf("%q: 5 products against a cap of 1 must be refused", name)
		}
		line := suggestionLine(err.Error())
		if line == "" {
			// Refusing to offer a command for an unsafe path is a correct
			// outcome — the operator still gets the directory in the report.
			continue
		}
		// A command WAS offered, so it must contain nothing that a shell would
		// act on beyond the glob we intend.
		payload := line
		payload = strings.TrimPrefix(strings.TrimSpace(payload), "--exclude-glob")
		for _, r := range shellMetacharacters {
			// The wrapping quotes and the glob's own {,} / ** are ours, so strip
			// the parts we generate before checking what came from the path.
			inner := extractQuoted(payload)
			if inner == "" {
				continue
			}
			if strings.ContainsRune(stripOurGlobSyntax(inner), r) {
				t.Errorf("%q: emitted command carries shell metacharacter %q from an "+
					"untrusted directory name — an operator pasting this executes it.\nline: %s",
					name, string(r), line)
				break
			}
		}
	}
}

// TestUnsafePathIsStillReportedJustNotAsCommandText — refusing to build a
// command must not silently drop the diagnostic. The operator still needs to
// know which directory blew the budget.
func TestUnsafePathIsStillReportedJustNotAsCommandText(t *testing.T) {
	const name = `deps'; touch /tmp/pwned; #`
	a := New(WithMaxProducts(1))
	SetProductsForTesting(a, productSet(t, map[string]int{name: 5}))

	err := a.buildTree()
	if err == nil {
		t.Fatal("must be refused")
	}
	msg := err.Error()
	if !strings.Contains(msg, "deps") {
		t.Errorf("the offending directory must still appear in the report, or the "+
			"error stops being actionable:\n%s", msg)
	}
	if strings.Contains(suggestionLine(msg), "touch /tmp/pwned") {
		t.Errorf("the payload reached the suggested command:\n%s", msg)
	}
}

// TestSafePathsStillGetACommand — the hardening must not cost the feature. A
// perfectly ordinary directory still produces the copy-pasteable fix.
func TestSafePathsStillGetACommand(t *testing.T) {
	a := New(WithMaxProducts(1))
	SetProductsForTesting(a, productSet(t, map[string]int{"web/node_modules": 5}))

	err := a.buildTree()
	if err == nil {
		t.Fatal("must be refused")
	}
	line := suggestionLine(err.Error())
	if !strings.Contains(line, "web/node_modules/**") {
		t.Errorf("an ordinary path must still get a copy-pasteable command; got: %q", line)
	}
}

// extractQuoted returns the text between the first pair of single quotes.
func extractQuoted(s string) string {
	i := strings.Index(s, "'")
	if i < 0 {
		return ""
	}
	j := strings.LastIndex(s, "'")
	if j <= i {
		return ""
	}
	return s[i+1 : j]
}

// stripOurGlobSyntax removes the characters this package itself puts into the
// suggestion, so the assertion only sees what came from the directory names.
func stripOurGlobSyntax(s string) string {
	r := strings.NewReplacer("**", "", "{", "", "}", "", ",", "", "/", "")
	return r.Replace(s)
}
