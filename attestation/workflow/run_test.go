// Copyright 2024 The Witness Contributors
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

package workflow

import (
	"testing"
)

func TestValidateRunOpts_NoStepName(t *testing.T) {
	ro := runOptions{}
	err := validateRunOpts(ro)
	if err == nil {
		t.Fatal("expected error for empty step name")
	}
	if err.Error() != "step name is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateRunOpts_NoSignersNotInsecure(t *testing.T) {
	ro := runOptions{stepName: "build"}
	err := validateRunOpts(ro)
	if err == nil {
		t.Fatal("expected error when no signers and not insecure")
	}
}

func TestValidateRunOpts_InsecureNoSigners(t *testing.T) {
	ro := runOptions{stepName: "build", insecure: true}
	err := validateRunOpts(ro)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunWithInsecure(t *testing.T) {
	ro := runOptions{}
	RunWithInsecure(true)(&ro)
	if !ro.insecure {
		t.Error("insecure should be true")
	}
	RunWithInsecure(false)(&ro)
	if ro.insecure {
		t.Error("insecure should be false")
	}
}

func TestRunWithIgnoreErrors(t *testing.T) {
	ro := runOptions{}
	RunWithIgnoreErrors(true)(&ro)
	if !ro.ignoreErrors {
		t.Error("ignoreErrors should be true")
	}
}

func TestRun_EmptyStepName(t *testing.T) {
	_, err := Run("", RunWithInsecure(true))
	if err == nil {
		t.Fatal("expected error for empty step name")
	}
}

func TestRun_InsecureNoAttestors(t *testing.T) {
	result, err := Run("test-step", RunWithInsecure(true))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Collection.Name != "test-step" {
		t.Errorf("Collection.Name = %q, want %q", result.Collection.Name, "test-step")
	}
}

func TestRunWithExports_InsecureNoAttestors(t *testing.T) {
	results, err := RunWithExports("test-step", RunWithInsecure(true))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one result")
	}
	// The last result should be the collection
	last := results[len(results)-1]
	if last.Collection.Name != "test-step" {
		t.Errorf("Collection.Name = %q, want %q", last.Collection.Name, "test-step")
	}
}
