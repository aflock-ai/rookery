// jade:ring local
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

package detection

import (
	"sort"
	"testing"
)

func firedDetectors(t *testing.T, argv []string) []string {
	t.Helper()
	res := RunPrePlanWith(Default(), PrePlan{Argv: argv, Env: map[string]string{}, Cwd: t.TempDir()})
	names := make([]string, 0, len(res.Fire))
	for _, f := range res.Fire {
		names = append(names, f.Attestor)
	}
	sort.Strings(names)
	return names
}

func contains(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// A monorepo runs each package's tools from the repository root: `go -C
// <dir>` for Go, and gotestsum because `go test` writes no JUnit. The
// catalog is matched against the exact argv, so a form it does not spell is a
// tool cilock never names. These are the commands the onboarding simulator's
// polyglot fixture (jade/onboardingsim/fixtures/monorepo-tag-expressions)
// verified offline, plus the bare forms of the same tools.
func TestMonorepoToolFormsAreDetected(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"go", "test", "./..."}, "go-test"},
		{[]string{"go", "-C", "go", "test", "./..."}, "go-test"},
		{[]string{"/usr/local/go/bin/go", "-C=pkg/api", "test", "./..."}, "go-test"},
		{[]string{"go", "-C", "go", "build", "-o", "tagexpressions.a", "."}, "go-build"},
		{[]string{"go", "-C", "cmd", "install", "./..."}, "go-build"},
		{[]string{"go", "vet", "./..."}, "go-vet"},
		{[]string{"go", "-C", "go", "vet", "./..."}, "go-vet"},
		{[]string{"gotestsum", "--junitfile", "junit.xml"}, "gotestsum"},
		{[]string{"go", "run", "gotest.tools/gotestsum@v1.13.0", "--junitfile", "junit.xml"}, "gotestsum"},
		{[]string{"go", "-C", "go", "run", "gotest.tools/gotestsum@v1.13.0", "--junitfile", "junit.xml", "--", "./..."}, "gotestsum"},
		{[]string{"go", "tool", "gotestsum", "--junitfile", "junit.xml"}, "gotestsum"},
	}
	for _, c := range cases {
		if got := firedDetectors(t, c.argv); !contains(got, c.want) {
			t.Errorf("%q: want %s to fire, fired %v", c.argv, c.want, got)
		}
	}
}

// The -C forms name the directory, so a directory called like a subcommand
// must not be read as one, and gotestsum is matched by its module path, not
// by any `go run`.
func TestMonorepoToolFormsDoNotOverMatch(t *testing.T) {
	cases := []struct {
		argv   []string
		refuse string
	}{
		{[]string{"go", "-C", "test", "build", "."}, "go-test"},
		{[]string{"go", "-C", "build", "test", "./..."}, "go-build"},
		{[]string{"go", "-C", "vet", "test", "./..."}, "go-vet"},
		{[]string{"go", "-C", "go", "testx"}, "go-test"},
		{[]string{"go", "run", "example.com/notgotestsum@v1"}, "gotestsum"},
		{[]string{"go", "run", "gotest.tools/gotestsum.evil@v1"}, "gotestsum"},
		{[]string{"go", "run", "./cmd/x", "gotest.tools/gotestsum@v1.13.0"}, "gotestsum"},
		{[]string{"echo", "go", "-C", "go", "test"}, "go-test"},
	}
	for _, c := range cases {
		if got := firedDetectors(t, c.argv); contains(got, c.refuse) {
			t.Errorf("%q: %s must not fire, fired %v", c.argv, c.refuse, got)
		}
	}
}
