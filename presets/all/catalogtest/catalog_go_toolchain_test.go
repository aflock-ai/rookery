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

package catalogtest

import (
	"regexp"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
	_ "github.com/aflock-ai/rookery/presets/all" // register every attestor + detector
)

// goTestUnknownFlag matches a documented `go test` invocation that names a
// flag the Go toolchain does not accept. `go test` has never had -junit
// (`go help testflag`); the working path is `gotestsum --junitfile` or
// `go-junit-report`. The test-results catalog entry told a cold-start user
// otherwise and they had to guess their way to gotestsum.
//
// Extend the alternation when another phantom flag shows up in the docs.
var goTestUnknownFlag = regexp.MustCompile(`go test\b[^\n"')]*\s-junit\b`)

// TestDocumentedGoToolInvocationsAreAcceptedByTheToolchain scans every
// detector description and every embedded catalog doc for `go test` lines
// carrying a flag the toolchain rejects. The catalog is what `cilock tools
// show` and the website render verbatim, so a wrong flag there is a wrong
// flag in every user's terminal.
func TestDocumentedGoToolInvocationsAreAcceptedByTheToolchain(t *testing.T) {
	reg := detection.Default()
	all, failures := reg.LookupAll()
	for name, err := range failures {
		t.Errorf("detector %q failed to parse: %v", name, err)
	}
	scanned := 0
	for name, d := range all {
		scanned++
		if m := goTestUnknownFlag.FindString(d.Description); m != "" {
			t.Errorf("detector %q description documents %q — `go test` has no -junit flag; say `gotestsum --junitfile` or `go-junit-report`", name, m)
		}
	}
	for _, name := range reg.DocNames() {
		doc, ok, err := reg.LookupDoc(name)
		if err != nil || !ok {
			t.Errorf("doc %q: ok=%v err=%v", name, ok, err)
			continue
		}
		scanned++
		if m := goTestUnknownFlag.FindString(doc.Body); m != "" {
			t.Errorf("catalog doc %q documents %q — `go test` has no -junit flag; say `gotestsum --junitfile` or `go-junit-report`", name, m)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned nothing — registry wiring is broken")
	}
}
