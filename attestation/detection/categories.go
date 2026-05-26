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

import "slices"

// Category names the kind of supply-chain step a detector's evidence
// represents. Categories serve three purposes:
//
//  1. Auto-defaulting --step when the producer omits it (cilock run uses
//     the matched detector's primary category as the step name).
//  2. Routing uploads on the platform side: the agent reads category to
//     decide which bucket the evidence lands in.
//  3. Giving attestor authors and policy authors a shared vocabulary.
//
// The set is closed and tiered. Tier 1 (Core) categories are the
// lingua franca every policy template should reference. Tier 2
// (Specialized) categories cover domain-specific steps (containers,
// ML/AI, mobile, firmware, IaC, operations). Tier 3 (Extension) lives
// in repo-local .cilock/commands.yaml and is namespaced (x-*, org.*) —
// extensions never appear in this file.
//
// Adding a Tier 1 or Tier 2 category is a versioned API change.
// Renaming or removing one is a breaking change. See
// docs/lexicon-v1.md §"Adding a new category" for the acceptance
// criteria.
type Category string

// Tier 1 — Core. Required first-class vocabulary for pre-deploy steps.
const (
	CategorySourceCheckout    Category = "source-checkout"
	CategoryCIContext         Category = "ci-context"
	CategoryDependencyResolve Category = "dependency-resolve"
	CategoryDependencyVerify  Category = "dependency-verify"
	CategoryBuild             Category = "build"
	CategoryUnitTest          Category = "unit-test"
	CategoryIntegrationTest   Category = "integration-test"
	CategoryCodeReview        Category = "code-review"
	CategoryThreatModel       Category = "threat-model"
	CategoryVulnerabilityScan Category = "vulnerability-scan"
	CategorySecretScan        Category = "secret-scan"
	CategoryComplianceScan    Category = "compliance-scan"
	CategorySBOMGenerate      Category = "sbom-generate"
	CategorySBOMConsume       Category = "sbom-consume"
	CategoryProvenance        Category = "provenance"
	CategoryPolicyEval        Category = "policy-eval"
	CategorySign              Category = "sign"
	CategoryPublish           Category = "publish"
	CategoryDeploy            Category = "deploy"
)

// Tier 2 — Specialized. Domain-specific or operational categories.
const (
	CategoryLint                       Category = "lint"
	CategoryReleaseApprove             Category = "release-approve"
	CategoryArchive                    Category = "archive"
	CategoryIaCPlan                    Category = "iac-plan"
	CategoryIaCApply                   Category = "iac-apply"
	CategoryManifestValidate           Category = "manifest-validate"
	CategoryImageBuild                 Category = "image-build"
	CategoryImageScan                  Category = "image-scan"
	CategoryImageSign                  Category = "image-sign"
	CategoryPackagePublish             Category = "package-publish"
	CategoryRuntimeEvent               Category = "runtime-event"
	CategoryRuntimeVulnerabilityDetect Category = "runtime-vulnerability-detect"
	CategoryDriftDetect                Category = "drift-detect"
	CategoryAssetInventory             Category = "asset-inventory"
	CategoryVEXConsume                 Category = "vex-consume"
	CategoryVulnerabilityDisclosure    Category = "vulnerability-disclosure"
	CategoryIncidentResponse           Category = "incident-response"
	CategoryRollback                   Category = "rollback"
	CategoryKeyCeremony                Category = "key-ceremony"
	CategoryAPISurfaceCheck            Category = "api-surface-check"
	CategoryModelTrain                 Category = "model-train"
	CategoryModelEval                  Category = "model-eval"
	CategoryDatasetSnapshot            Category = "dataset-snapshot"
	CategoryFirmwareSign               Category = "firmware-sign"
	CategoryMobileSign                 Category = "mobile-sign"
	CategoryMobileSubmit               Category = "mobile-submit"
)

// tier1Categories is the Core lexicon in canonical order.
var tier1Categories = []Category{
	CategorySourceCheckout,
	CategoryCIContext,
	CategoryDependencyResolve,
	CategoryDependencyVerify,
	CategoryBuild,
	CategoryUnitTest,
	CategoryIntegrationTest,
	CategoryCodeReview,
	CategoryThreatModel,
	CategoryVulnerabilityScan,
	CategorySecretScan,
	CategoryComplianceScan,
	CategorySBOMGenerate,
	CategorySBOMConsume,
	CategoryProvenance,
	CategoryPolicyEval,
	CategorySign,
	CategoryPublish,
	CategoryDeploy,
}

// tier2Categories is the Specialized lexicon in canonical order.
var tier2Categories = []Category{
	CategoryLint,
	CategoryReleaseApprove,
	CategoryArchive,
	CategoryIaCPlan,
	CategoryIaCApply,
	CategoryManifestValidate,
	CategoryImageBuild,
	CategoryImageScan,
	CategoryImageSign,
	CategoryPackagePublish,
	CategoryRuntimeEvent,
	CategoryRuntimeVulnerabilityDetect,
	CategoryDriftDetect,
	CategoryAssetInventory,
	CategoryVEXConsume,
	CategoryVulnerabilityDisclosure,
	CategoryIncidentResponse,
	CategoryRollback,
	CategoryKeyCeremony,
	CategoryAPISurfaceCheck,
	CategoryModelTrain,
	CategoryModelEval,
	CategoryDatasetSnapshot,
	CategoryFirmwareSign,
	CategoryMobileSign,
	CategoryMobileSubmit,
}

// AllCategories returns every valid category value (Tier 1 + Tier 2)
// in canonical order. Used by validators and `cilock tools list`.
func AllCategories() []Category {
	out := make([]Category, 0, len(tier1Categories)+len(tier2Categories))
	out = append(out, tier1Categories...)
	out = append(out, tier2Categories...)
	return out
}

// Tier1Categories returns the Core lexicon.
func Tier1Categories() []Category {
	return slices.Clone(tier1Categories)
}

// Tier2Categories returns the Specialized lexicon.
func Tier2Categories() []Category {
	return slices.Clone(tier2Categories)
}

// validCategorySet is the membership lookup; built once at init.
var validCategorySet = func() map[Category]bool {
	m := make(map[Category]bool, len(tier1Categories)+len(tier2Categories))
	for _, c := range tier1Categories {
		m[c] = true
	}
	for _, c := range tier2Categories {
		m[c] = true
	}
	return m
}()

// IsValidCategory reports whether the given string is a Tier 1 or
// Tier 2 category. Tier 3 (extension) names are not validated here;
// they are accepted in .cilock/commands.yaml via separate rules.
func IsValidCategory(s string) bool {
	return validCategorySet[Category(s)]
}

// IsTier1 reports whether the given category is in the Core tier.
// Used by the inference engine to prefer Tier 2 (more specific) over
// Tier 1 (more general) when multiple categories match the same argv.
func IsTier1(c Category) bool {
	return slices.Contains(tier1Categories, c)
}
