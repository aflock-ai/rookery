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

// RecommendIgnoreExitCode reports whether the suggested `cilock run` command
// should include --ignore-command-exit-code. It returns true when any fired
// tool exits non-zero on findings (its DetectorYAML sets
// ExitsNonzeroOnFindings) — those scanners would otherwise abort the run even
// though their report was captured. Mirrors RecommendTrace: re-reads each fired
// detector from the registry. Returns false when nothing fires or no fired tool
// gates on findings.
func RecommendIgnoreExitCode(reg *Registry, plan PlanResult) bool {
	for _, f := range plan.Fire {
		d, _, err := reg.Lookup(f.Attestor)
		if err != nil || d == nil {
			continue
		}
		if d.ExitsNonzeroOnFindings {
			return true
		}
	}
	return false
}
