// jade:ring local
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

// Onboarding simulator, mx-python-click-l3: 16018 products against the 10000
// cap, 15953 of them under .venv/. The suggested fix excluded every listed
// contributor, tests/ (36 files) and a __pycache__ included, so following it
// would also have dropped the test report the step exists to record. And the
// run summary prints the error on one line with its newlines escaped, so the
// fix sat at the end of a wall of \x0a. The fix now excludes only what brings
// the count under the cap, and the first line carries it.

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func TestMaxProducts_SuggestsOnlyWhatBringsTheCountUnderTheCap(t *testing.T) {
	a := New(WithMaxProducts(100))
	SetProductsForTesting(a, productSet(t, map[string]int{
		".venv": 400,
		"tests": 30,
		"build": 20,
	}))
	err := a.buildTree()
	if err == nil {
		t.Fatal("450 products against a cap of 100 must be refused")
	}
	msg := err.Error()
	line := suggestionLine(msg)
	if !strings.Contains(line, "'.venv/**'") {
		t.Fatalf("excluding .venv alone brings 450 to 50; the suggestion must be exactly that, got line %q in:\n%s", line, msg)
	}
	if strings.Contains(line, "tests/**") || strings.Contains(line, "build/**") {
		t.Fatalf("the suggestion must not exclude directories it does not need to; got %q", line)
	}
	if !strings.Contains(msg, "tests/") {
		t.Fatalf("the smaller contributors are still listed as diagnostics:\n%s", msg)
	}
}

func TestMaxProducts_SuggestsSeveralWhenOneIsNotEnough(t *testing.T) {
	a := New(WithMaxProducts(100))
	SetProductsForTesting(a, productSet(t, map[string]int{
		"a": 90,
		"b": 80,
		"c": 40,
	}))
	err := a.buildTree()
	if err == nil {
		t.Fatal("210 products against a cap of 100 must be refused")
	}
	line := suggestionLine(err.Error())
	// Excluding a leaves 120 (> 100); a and b leave 40.
	if !strings.Contains(line, "'{a/**,b/**}'") {
		t.Fatalf("want a and b excluded, not c; got %q", line)
	}
}

func TestMaxProducts_FirstLineNamesTheFix(t *testing.T) {
	a := New(WithMaxProducts(100))
	SetProductsForTesting(a, productSet(t, map[string]int{".venv": 400, "tests": 3}))
	err := a.buildTree()
	if err == nil {
		t.Fatal("must be refused")
	}
	first := firstLine(err.Error())
	for _, want := range []string{"403", "100", excludeGlobFlag + " '.venv/**'"} {
		if !strings.Contains(first, want) {
			t.Errorf("the first line alone must carry %q, because the run summary shows only that line readably; got %q", want, first)
		}
	}
}
