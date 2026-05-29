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
	"testing"

	"github.com/stretchr/testify/assert"
)

// shouldAutoDetect: detection is the default ONLY when the operator didn't
// pass -a; an explicit --workload always overrides.
func TestShouldAutoDetect(t *testing.T) {
	tests := []struct {
		name            string
		attestationsSet bool
		workloadSet     bool
		workload        string
		want            bool
	}{
		{name: "no -a, no --workload → auto (the default)", want: true},
		{name: "-a set, no --workload → manual (respect operator's set)", attestationsSet: true, want: false},
		{name: "-a set + --workload=auto → forced detection", attestationsSet: true, workloadSet: true, workload: "auto", want: true},
		{name: "-a set + --workload=manual → no detection", attestationsSet: true, workloadSet: true, workload: "manual", want: false},
		{name: "no -a + --workload=manual → no detection", workloadSet: true, workload: "manual", want: false},
		{name: "no -a + --workload=auto → detection", workloadSet: true, workload: "auto", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, shouldAutoDetect(tt.attestationsSet, tt.workloadSet, tt.workload))
		})
	}
}
