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

package policy

import (
	"reflect"
	"testing"
)

// EnforcedHardening is the one definition of "fully enforced" that every
// embedder (the cilock CLI, Judge's in-process verifier) installs. A new
// HardeningOptions field that is not turned on here would silently leave both
// of them warn-only, so check every field by reflection rather than by name.
func TestEnforcedHardeningEnablesEveryFlag(t *testing.T) {
	v := reflect.ValueOf(EnforcedHardening())
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if f.Type.Kind() != reflect.Bool {
			t.Fatalf("HardeningOptions.%s is %s; teach this test and EnforcedHardening what enforced means for it", f.Name, f.Type)
		}
		if !v.Field(i).Bool() {
			t.Errorf("EnforcedHardening leaves %s off", f.Name)
		}
	}
	if v.NumField() == 0 {
		t.Fatal("HardeningOptions has no fields")
	}
}
