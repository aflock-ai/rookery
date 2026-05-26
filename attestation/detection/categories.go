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

// Category labels what role this detector's evidence serves in the
// software supply chain. Categories combine "what kind of evidence" with
// "where in the lifecycle the tool runs" into a single label.
//
// An LLM agent gathering supply-chain evidence uses categories to route
// uploads — categories are the closed enum the cilock + platform API
// contract is built on. Adding a new category is a versioned API change;
// renaming an existing one is a breaking change.
//
// A detector.yaml may declare multiple categories when the same detector
// legitimately serves more than one lifecycle context (e.g. trivy in CI
// vs against a production registry — same CLI, different lifecycle).
type Category string

const (
	// CategoryBuild — evidence about how an artifact was built: who
	// (CI runner identity), from what (source commit, dependency
	// lockfiles, materials snapshot), how (command-run, github-action),
	// and what came out (product, docker image, oci artifact).
	//
	// Lifecycle: build / CI.
	CategoryBuild Category = "build"

	// CategoryArtifactScan — scanner output produced as part of CI
	// against a built artifact: SBOMs, vulnerability scans, static
	// analysis findings, secret scans, test results.
	//
	// Lifecycle: build / CI.
	CategoryArtifactScan Category = "artifact-scan"

	// CategoryStatement — human or policy assertion attached to an
	// artifact: VEX statements (vuln impact), VSAs (verification
	// summaries), in-toto Links (declared CI steps), policy verifies.
	//
	// Lifecycle: release / between build and deploy.
	CategoryStatement Category = "statement"

	// CategoryPostureScan — continuous configuration scan of running
	// infrastructure: CIS benchmarks against live clusters, CSPM
	// findings, compliance profile outcomes, network mesh health.
	//
	// Lifecycle: production / continuous.
	CategoryPostureScan Category = "posture-scan"

	// CategoryRuntime — real-time observation of a deployed running
	// system: syscall events, network flows, process lifecycle.
	//
	// Lifecycle: production / continuous.
	CategoryRuntime Category = "runtime"
)

// AllCategories returns every valid category value, in canonical
// order. Used by validators and `cilock tools list`.
func AllCategories() []Category {
	return []Category{
		CategoryBuild,
		CategoryArtifactScan,
		CategoryStatement,
		CategoryPostureScan,
		CategoryRuntime,
	}
}

// IsValidCategory reports whether the given string is a recognized
// category. Closed set — adding a category requires a code change.
func IsValidCategory(s string) bool {
	switch Category(s) {
	case CategoryBuild, CategoryArtifactScan, CategoryStatement, CategoryPostureScan, CategoryRuntime:
		return true
	}
	return false
}
