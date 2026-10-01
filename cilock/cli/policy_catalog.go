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
	"fmt"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"
)

// The authoring catalog is what `cilock policy guide` prints, what
// `cilock policy template` scaffolds from, and what `cilock policy prove`
// resolves attestor names through. It is knowledge, not a decision: a goal
// lists the attestors that can evidence it and the rules cilock seeds, and the
// coding agent decides which of them this repository needs. One table, three
// readers, so the guide an agent reads cannot drift from the draft it writes.
//
// Goal ids are the product's own (jade/factory/edge/git/policypairing.js,
// PAIRING_GOALS), so a goal a human picked on /policy/new names a goal here.

// Predicate types the catalog names beyond the seeded rules' own
// (policy_rules.go). Each is cited to the attestor constant
// that defines it in the design doc (docs/design/cilock-policy-init.md).
const (
	typeMaterial     = materialTreeType
	typeTrivy        = "https://aflock.ai/attestations/trivy/v0.1"
	typeSLSA         = "https://slsa.dev/provenance/v1"
	typeCycloneDX    = "https://cyclonedx.org/bom"
	typeSPDX         = "https://spdx.dev/Document"
	typeVEX          = "https://openvex.dev/ns"
	typeGitHubReview = "https://aflock.ai/attestations/github-review/v0.1"
	typeGit          = "https://aflock.ai/attestations/git/v0.1"
	typeK8sManifest  = "https://aflock.ai/attestations/k8smanifest/v0.2"
	typeDocker       = "https://aflock.ai/attestations/docker/v0.1"
	typeGoBuild      = "https://aflock.ai/attestations/go-build/v0.1"
	typeLockfiles    = "https://aflock.ai/attestations/lockfiles/v0.1"
	typeBaseAncestry = "https://aflock.ai/attestations/base-ancestry/v0.1"
)

// goalIDVulns is the vulnerability goal, which template extends with --with-vex.
const goalIDVulns = "vulns"

// functionaryTypeRoot is a functionary checked against the policy's roots.
const functionaryTypeRoot = "root"

// Attestor names the catalog uses more than once.
const (
	attestorNameProduct  = "product"
	attestorNameMaterial = "material"
	attestorNameVEX      = "vex"
	attestorNameSBOM     = "sbom"
	attestorNameGit      = "git"
)

// catalogAttestor is one attestor as a policy author meets it: the `-a` name
// that records it, the predicate type a step requires, what the wrapped
// command has to leave behind for it, and the predicate paths a rule reads.
type catalogAttestor struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Always   bool     `json:"always_recorded,omitempty"`
	Produce  string   `json:"wrapped_command_must_produce,omitempty"`
	Reads    []string `json:"predicate_paths"`
	Rules    []string `json:"seeded_rules,omitempty"`
	Source   string   `json:"source"`
	RunFlags []string `json:"run_flags,omitempty"`
}

// catalogAttestors is keyed by predicate type. Always-recorded attestors carry
// no `-a` name in run flags; the rest are what `cilock run -a` takes.
var catalogAttestors = map[string]catalogAttestor{
	typeCommandRun: {
		Name: attestorCommandRun, Type: typeCommandRun, Always: true,
		Reads: []string{"exitcode (number, always present)", "cmd (argv array)", "stdout", "stderr",
			"processes[] (only with --trace)", "paths[] / digests[] / comms[] (interned tables processes[] index into)"},
		Rules:  []string{ruleCommandSucceeded, ruleCommandPin},
		Source: "plugins/attestors/commandrun/v2_marshal.go:217-255",
	},
	typeProduct: {
		Name: attestorNameProduct, Type: typeProduct, Always: true,
		Produce: "files the wrapped command creates or changes under the working directory",
		Reads:   []string{"merkleRoot", "treeSize", "leaves[].path", "leaves[].fileDigest (inline only under the compact budget; otherwise inventory)"},
		Rules:   []string{ruleProductRecorded},
		Source:  "plugins/attestors/product/product.go:1008-1031",
	},
	typeMaterial: {
		Name: attestorNameMaterial, Type: typeMaterial, Always: true,
		Reads:  []string{"merkleRoot", "treeSize", "inventory (leaves are omitted or detached in the compact profile; artifactsFrom reads them, rego should not)"},
		Source: "plugins/attestors/material/material.go:109,268-277",
	},
	typeTestResults: {
		Name: "test-results", Type: typeTestResults,
		Produce: "a JUnit XML or CTRF JSON report file (first byte '<' or '{'; a bare <testsuite> root needs a name attribute); `go test -json` and TAP are not read, so use e.g. `gotestsum --junitfile junit.xml`",
		Reads:   []string{"predicate.summary.total", "predicate.summary.passed", "predicate.summary.failed", "predicate.summary.skipped", "predicate.summary.errors (omitted when 0)", "predicate.failedTests[] (capped at 50)"},
		Rules:   []string{ruleTestsPass},
		Source:  "plugins/attestors/test-results/test_results.go:48,81-118",
	},
	typeSARIF: {
		Name: "sarif", Type: typeSARIF,
		Produce: "ONE SARIF 2.1.0 file (e.g. `golangci-lint run --output.sarif.path lint.sarif`, `semgrep --sarif -o semgrep.sarif`, `hadolint -f sarif`, `checkov -o sarif`); a second SARIF file in the same step is dropped",
		Reads:   []string{"report.runs[].results[].level", "report.runs[].results[].ruleId", "report.runs[].tool.driver.rules[].defaultConfiguration.level", "reportFileName"},
		Rules:   []string{ruleSARIFNoErrors},
		Source:  "plugins/attestors/sarif/sarif.go:40,70-74,165-250",
	},
	typeLeakScan: {
		Name: "secretscan", Type: typeLeakScan,
		Produce:  "nothing: with a diff scope the scan reads the change itself",
		Reads:    []string{"findings[] (ruleId, location; the secret is a digest, never the value)", "scope.files (products|diff|tree)", "scope.productDigestMismatches[]"},
		Rules:    []string{ruleSecretscanClean},
		Source:   "plugins/attestors/secretscan/types.go:31,100-115; scope.go:97-127",
		RunFlags: []string{"--attestor-secretscan-scope", "diff:origin/<default branch>"},
	},
	typeGovulncheck: {
		Name: "govulncheck", Type: typeGovulncheck,
		Produce: "the `govulncheck -json ./...` stream written to a file, e.g. `sh -c 'govulncheck -json ./... > govulncheck.json'`",
		Reads:   []string{"summary.scanLevel", "summary.reachableCount", "summary.unreachableCount", "summary.findings[].osvId", "summary.findings[].reachable", "report[].osv.id / report[].osv.aliases (CVE/GHSA aliases of each GO id)"},
		Rules:   []string{ruleGovulncheckReachable, ruleGovulncheckVEX},
		Source:  "plugins/attestors/govulncheck/govulncheck.go:66,226-280",
	},
	typeVEX: {
		Name: attestorNameVEX, Type: typeVEX,
		Produce:  "an OpenVEX document: author it with `cilock attest vex --vuln <CVE|GHSA> --product <purl|digest> --status ...`, or record an existing file with --attestor-vex-file",
		Reads:    []string{"vexDocument.statements[].vulnerability.name", "vexDocument.statements[].vulnerability.aliases[]", "vexDocument.statements[].products[].@id", "vexDocument.statements[].status", "vexDocument.statements[].justification"},
		Source:   "plugins/attestors/vex/vex.go:39,115-117; openvex/validate.go:220-223",
		RunFlags: []string{"--attestor-vex-file", "<path to the OpenVEX document>"},
	},
	typeTrivy: {
		Name: "trivy", Type: typeTrivy,
		Produce: "Trivy's native JSON report (`trivy image --format json -o trivy.json <image@digest>`), schema version 2",
		Reads:   []string{"summary.bySeverity.<critical|high|medium|low|unknown>.fail", "summary.failedFindings[].id", "summary.artifactName", "summary.metadata.repoDigests[]"},
		Rules:   []string{ruleTrivySeverity},
		Source:  "plugins/attestors/trivy/trivy.go:73,222-285",
	},
	typeSLSA: {
		Name: "slsa", Type: typeSLSA,
		Produce: "a build whose outputs land in the working directory; slsa assembles from the git, material, command-run and product attestors of the same run",
		Reads:   []string{"buildDefinition.resolvedDependencies[] (name, uri, digest)", "buildDefinition.externalParameters.command", "runDetails.builder.id"},
		Rules:   []string{ruleSLSAProvenance},
		Source:  "plugins/attestors/slsa/slsa.go:44,131-307",
	},
	typeCycloneDX: {
		Name: attestorNameSBOM, Type: typeCycloneDX,
		Produce: "a CycloneDX JSON SBOM file (e.g. `syft dir:. -o cyclonedx-json=sbom.cdx.json`)",
		Reads:   []string{"_sbomFormat (\"cyclonedx\")", "components[]", "metadata.component"},
		Rules:   []string{ruleSBOMInventory},
		Source:  "plugins/attestors/sbom/sbom.go:65-71,398-423",
	},
	typeSPDX: {
		Name: attestorNameSBOM, Type: typeSPDX,
		Produce: "an SPDX JSON SBOM file (e.g. `syft dir:. -o spdx-json=sbom.spdx.json`)",
		Reads:   []string{"_sbomFormat (\"spdx\")", "packages[]"},
		Rules:   []string{ruleSBOMInventory},
		Source:  "plugins/attestors/sbom/sbom.go:65-71,398-423",
	},
	typeGitHubReview: {
		Name: "github-review", Type: typeGitHubReview,
		Produce: "nothing: it asks GitHub for the pull requests of HEAD (token from GH_TOKEN, GITHUB_TOKEN or `gh auth token`)",
		Reads:   []string{"commit_sha", "prs[].reviews[].state (APPROVED|CHANGES_REQUESTED|...)", "prs[].reviews[].commit_id", "prs[].reviews[].user_login"},
		Rules:   []string{ruleReviewApproved},
		Source:  "plugins/attestors/github-review/github-review.go:69,99-138",
	},
	typeGit: {
		Name: attestorNameGit, Type: typeGit,
		Reads:  []string{"commithash", "treehash", "status (dirty paths)", "refs"},
		Source: "plugins/attestors/git/git.go",
	},
	typeK8sManifest: {
		Name: "k8smanifest", Type: typeK8sManifest,
		Produce:  "rendered .yaml/.yml/.json manifests (e.g. `sh -c 'kubectl kustomize deploy > rendered.yaml'`)",
		Reads:    []string{"recordeddocs[].kind", "recordeddocs[].name", "recordeddocs[].recordedimages[].digest"},
		Source:   "plugins/attestors/k8smanifest/k8s.go:40,66-105",
		RunFlags: []string{"--attestor-k8smanifest-record-cluster-information=false"},
	},
	typeDocker: {
		Name: "docker", Type: typeDocker,
		Produce: "a `docker buildx build --metadata-file meta.json` metadata file",
		Reads:   []string{"products.<digest>.imagedigest", "products.<digest>.imagereferences[]", "products.<digest>.materials"},
		Source:  "plugins/attestors/docker/docker.go:38,59-73",
	},
	typeGoBuild: {
		Name: "go-build", Type: typeGoBuild,
		Produce: "Go binaries (read with debug/buildinfo)",
		Reads:   []string{"binaries[].path", "binaries[].go_version", "binaries[].main_module", "binaries[].deps[]", "binaries[].settings"},
		Source:  "plugins/attestors/go-build/go-build.go:76,101-163",
	},
	typeLockfiles: {
		Name: "lockfiles", Type: typeLockfiles,
		Reads:  []string{"lockfiles[].filename", "lockfiles[].digest"},
		Source: "plugins/attestors/lockfiles/lockfiles.go:37,76-109",
	},
	typeBaseAncestry: {
		Name: "base-ancestry", Type: typeBaseAncestry,
		Reads:  []string{"relationship (current|behind|diverged|unknown)", "merge_base", "base"},
		Source: "plugins/attestors/base-ancestry/base_ancestry.go:74,160-195",
	},
}

// catalogGoal is one pairing goal as an author meets it. The goal fixes only
// the evidence FORMAT (attestation types and the rules seeded for them); the
// tools that can produce that evidence are derived from the detection
// catalog at run time (goalTools), so a detector added for a new language
// shows up under its goal without an edit here. Categories and Keywords are
// the join: a detector serves a goal when one of its categories is listed,
// or when its description names a keyword.
type catalogGoal struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Attestors  []string             `json:"attestation_types"`
	Rules      []string             `json:"seeded_rules"`
	Command    string               `json:"wrapped_command"`
	Gap        string               `json:"gap"`
	Categories []detection.Category `json:"detector_categories,omitempty"`
	Keywords   []string             `json:"detector_keywords,omitempty"`
	// SARIFScanners also admits vulnerability-scan detectors whose output the
	// sarif attestor captures: the category enum has no SAST/SCA split, so a
	// SARIF static analyser is listed under quality as well as vulns.
	SARIFScanners bool `json:"-"`
}

// catalogGoals is ordered for reading: the goals an agent most often needs
// first, vulnerability scanning last. The template writes one step per goal,
// named by the goal id.
var catalogGoals = []catalogGoal{
	{ID: "tests", Name: "Changes pass tests",
		Attestors:  []string{typeCommandRun, typeTestResults},
		Rules:      []string{ruleCommandSucceeded, ruleCommandPin, ruleTestsPass},
		Command:    "runs the suite and writes a JUnit XML or CTRF report into the working directory",
		Categories: []detection.Category{detection.CategoryUnitTest, detection.CategoryIntegrationTest},
		Gap:        "A green suite proves only what it covers; zero tests is refused, not passed."},
	{ID: "quality", Name: "Catch common code mistakes",
		Attestors:     []string{typeCommandRun, typeSARIF},
		Rules:         []string{ruleCommandSucceeded, ruleCommandPin, ruleSARIFNoErrors},
		Command:       "runs a static analyser that writes ONE SARIF file",
		Categories:    []detection.Category{detection.CategoryLint},
		SARIFScanners: true,
		Gap:           "Static checks do not prove runtime behavior; warning-level results pass unless a rule says otherwise."},
	{ID: "app-build", Name: "Build the changed code",
		Attestors:  []string{typeCommandRun, typeProduct},
		Rules:      []string{ruleCommandSucceeded, ruleCommandPin, ruleProductRecorded},
		Command:    "builds and writes its outputs under the working directory, so each is recorded by digest",
		Categories: []detection.Category{detection.CategoryBuild},
		Gap:        "A build is not a behavioral test. Chain later steps to it with artifactsFrom so they use these bytes."},
	{ID: "secrets", Name: "Keep secrets out of code",
		Attestors:  []string{typeCommandRun, typeLeakScan},
		Rules:      []string{ruleCommandSucceeded, ruleSecretscanClean},
		Command:    "anything that exits 0 (`true` is fine): --attestor-secretscan-scope diff:origin/<default branch> scans the change",
		Categories: []detection.Category{detection.CategorySecretScan},
		Gap:        "Pattern matching can miss secrets; a tree scope re-reports every old finding on every push."},
	{ID: "provenance", Name: "Record build inputs and outputs",
		Attestors:  []string{typeCommandRun, typeProduct, typeSLSA},
		Rules:      []string{ruleCommandSucceeded, ruleCommandPin, ruleProductRecorded, ruleSLSAProvenance},
		Command:    "the build itself, recorded with -a git -a slsa so provenance binds its outputs to its inputs",
		Categories: []detection.Category{detection.CategoryProvenance, detection.CategoryImageBuild},
		Gap:        "Provenance records what this run consumed and produced; it is not reproducibility or a SLSA level."},
	{ID: attestorNameSBOM, Name: "Record software dependencies",
		Attestors:  []string{typeCommandRun, typeCycloneDX},
		Rules:      []string{ruleCommandSucceeded, ruleCommandPin, ruleSBOMInventory},
		Command:    "writes ONE CycloneDX or SPDX JSON SBOM (pass --sbom-format to template: the step's type must match)",
		Categories: []detection.Category{detection.CategorySBOMGenerate},
		Gap:        "An SBOM is an inventory, not a vulnerability or license verdict. Chain it to the build with artifactsFrom to bind it to those bytes."},
	{ID: "config", Name: "Validate configuration and schemas",
		Attestors:  []string{typeCommandRun},
		Rules:      []string{ruleCommandSucceeded, ruleCommandPin},
		Command:    "the repository's own validator for each changed format",
		Categories: []detection.Category{detection.CategoryPolicyEval, detection.CategoryIaCPlan},
		Gap:        "Valid configuration is not safe configuration."},
	{ID: "config-security", Name: "Check configuration security",
		Attestors:  []string{typeCommandRun, typeSARIF},
		Rules:      []string{ruleCommandSucceeded, ruleCommandPin, ruleSARIFNoErrors},
		Command:    "a configuration scanner that writes ONE SARIF file",
		Categories: []detection.Category{detection.CategoryComplianceScan},
		Gap:        "One scanner rarely covers every infrastructure and CI language."},
	{ID: "kubernetes", Name: "Validate Kubernetes manifests",
		Attestors:  []string{typeCommandRun},
		Rules:      []string{ruleCommandSucceeded, ruleCommandPin},
		Command:    "renders the manifests and validates the rendered output",
		Categories: []detection.Category{detection.CategoryManifestValidate},
		Gap:        "Rendered-output validation is not live-cluster admission. Add k8smanifest (with --attestor-k8smanifest-record-cluster-information=false) to record image digests."},
	{ID: "dockerfile", Name: "Check Dockerfile best practices",
		Attestors: []string{typeCommandRun, typeSARIF},
		Rules:     []string{ruleCommandSucceeded, ruleCommandPin, ruleSARIFNoErrors},
		Command:   "a Dockerfile linter that writes ONE SARIF file",
		Keywords:  []string{"dockerfile"},
		Gap:       "Dockerfile lint only; no image scan."},
	{ID: "docs", Name: "Check documentation changes",
		Attestors: []string{typeCommandRun},
		Rules:     []string{ruleCommandSucceeded, ruleCommandPin},
		Command:   "the repository's docs build or link check",
		Gap:       "Link and build checks do not establish factual accuracy."},
	{ID: "migrations", Name: "Test database migrations",
		Attestors: []string{typeCommandRun},
		Rules:     []string{ruleCommandSucceeded, ruleCommandPin},
		Command:   "applies the migrations to a disposable database and checks them",
		Gap:       "Needs a disposable database; never run against production."},
	{ID: "image-vulns", Name: "Scan the built container image",
		Attestors:  []string{typeCommandRun, typeTrivy},
		Rules:      []string{ruleCommandSucceeded, ruleCommandPin, ruleTrivySeverity},
		Command:    "scans the exact built image digest and writes the scanner's report",
		Categories: []detection.Category{detection.CategoryImageScan},
		Keywords:   []string{"container image"},
		Gap:        "Needs the exact image digest and a reviewed severity threshold."},
	{ID: goalIDVulns, Name: "Catch known vulnerable dependencies",
		Attestors:  []string{typeCommandRun, typeGovulncheck},
		Rules:      []string{ruleCommandSucceeded, ruleCommandPin, ruleGovulncheckReachable},
		Command:    "writes the scanner's report (for Go: the `govulncheck -json` stream) to a file; with --with-vex, a separate vex step's OpenVEX statements must cover every finding",
		Categories: []detection.Category{detection.CategoryVulnerabilityScan, detection.CategoryVEXConsume},
		Gap:        "Source dependencies are not the contents of a built image. A VEX statement is a signed judgment, not a fix."},
}

// catalogTool is one detector from the detection catalog, as a candidate for
// a goal. It is a suggestion: the agent decides whether this repository uses
// it. Argv is the command prefix the detector matches; Captures names the
// attestors that sign its output (a detection-only tool's emits_formats, or
// the plugin itself), and Types their predicate types.
type catalogTool struct {
	Name                   string   `json:"name"`
	Description            string   `json:"description,omitempty"`
	Argv                   []string `json:"argv,omitempty"`
	Captures               []string `json:"captured_by,omitempty"`
	Types                  []string `json:"predicate_types,omitempty"`
	ExitsNonzeroOnFindings bool     `json:"exits_nonzero_on_findings,omitempty"`
	OnPath                 bool     `json:"on_path,omitempty"`
}

// guideRegistry is the detection catalog guide and template read. A package
// variable so a test can hand them a temporary catalog.
var guideRegistry = detection.Default

// goalTools derives the candidate tools for a goal from the detection
// catalog: every detector whose categories or description join the goal.
func goalTools(reg *detection.Registry, g catalogGoal, onPath func(string) bool) []catalogTool {
	all, _ := reg.LookupAll()
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []catalogTool
	for _, n := range names {
		d := all[n]
		if d == nil || d.AlwaysOn || !detectorServesGoal(d, g) {
			continue
		}
		t := catalogTool{Name: d.Name, Description: detectorDescription(reg, d), ExitsNonzeroOnFindings: d.ExitsNonzeroOnFindings}
		t.Argv = detectorArgv(d)
		t.Captures = detectorCaptures(d)
		for _, a := range t.Captures {
			t.Types = append(t.Types, typesForAttestorName(a)...)
		}
		for _, argv := range t.Argv {
			head := strings.Fields(argv)
			if len(head) > 0 && onPath != nil && onPath(head[0]) {
				t.OnPath = true
			}
		}
		out = append(out, t)
	}
	return out
}

func detectorServesGoal(d *detection.DetectorYAML, g catalogGoal) bool {
	for _, c := range d.Category {
		for _, want := range g.Categories {
			if c == want {
				return true
			}
		}
		if g.SARIFScanners && c == detection.CategoryVulnerabilityScan {
			for _, f := range d.EmitsFormats {
				if f == "sarif" {
					return true
				}
			}
		}
	}
	desc := strings.ToLower(d.Description)
	for _, k := range g.Keywords {
		if strings.Contains(desc, k) {
			return true
		}
	}
	return false
}

func detectorDescription(reg *detection.Registry, d *detection.DetectorYAML) string {
	if doc, ok, err := reg.LookupDoc(d.Name); err == nil && ok && doc != nil && doc.Description != "" {
		return doc.Description
	}
	return strings.TrimSpace(d.Description)
}

// detectorArgv lists the argv prefixes a detector matches, joined by spaces.
func detectorArgv(d *detection.DetectorYAML) []string {
	seen := map[string]bool{}
	var out []string
	var visit func(p *detection.Predicate)
	visit = func(p *detection.Predicate) {
		if p == nil {
			return
		}
		if len(p.ArgvPrefix) > 0 {
			s := strings.Join(p.ArgvPrefix, " ")
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		for i := range p.AnyOf {
			visit(&p.AnyOf[i])
		}
		for i := range p.AllOf {
			visit(&p.AllOf[i])
		}
		visit(p.Not)
		visit(p.ExecObserved)
	}
	for _, gate := range []*detection.GateBlock{d.Pre, d.Post} {
		if gate != nil {
			visit(gate.Match)
		}
	}
	return out
}

// detectorCaptures names the attestors that sign a detector's output: a
// detection-only entry's emits_formats, else the plugin the detector belongs
// to. A detection-only entry with no format is captured by command-run alone.
func detectorCaptures(d *detection.DetectorYAML) []string {
	if len(d.EmitsFormats) > 0 {
		return append([]string(nil), d.EmitsFormats...)
	}
	if d.DetectionOnly {
		return []string{attestorCommandRun}
	}
	return []string{d.Name}
}

// typesForAttestorName resolves the predicate types an attestor emits: the
// registry first (every attestor compiled into this binary), then the
// catalog table. sbom is special: its registered type only selects it, and it
// signs under the SBOM's own format type.
func typesForAttestorName(name string) []string {
	if name == attestorNameSBOM {
		return []string{typeCycloneDX, typeSPDX}
	}
	if f, ok := attestation.FactoryByName(name); ok {
		if a := f(); a != nil && a.Type() != "" {
			return []string{a.Type()}
		}
	}
	if a, ok := attestorByName(name); ok {
		return []string{a.Type}
	}
	return nil
}

// goalByID returns the catalog goal for a pairing goal id.
func goalByID(id string) (catalogGoal, bool) {
	for _, g := range catalogGoals {
		if g.ID == id {
			return g, true
		}
	}
	return catalogGoal{}, false
}

func goalIDs() []string {
	ids := make([]string, 0, len(catalogGoals))
	for _, g := range catalogGoals {
		ids = append(ids, g.ID)
	}
	return ids
}

// attestorByName resolves `--attestor <name-or-type>` for template.
func attestorByName(nameOrType string) (catalogAttestor, bool) {
	if a, ok := catalogAttestors[nameOrType]; ok {
		return a, true
	}
	names := make([]string, 0, len(catalogAttestors))
	for t := range catalogAttestors {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		if a := catalogAttestors[t]; a.Name == nameOrType {
			return a, true
		}
	}
	return catalogAttestor{}, false
}

// fillSlot renders a slot value: the marker, what to supply, and how.
func fillSlot(what, how string) string {
	return fmt.Sprintf("%s %s: %s", fillMarker, what, how)
}

// findFillSlots walks a decoded draft and returns every unfilled slot as
// "<json path>: <slot text>", sorted. A slot is any string that starts with
// the marker, wherever it sits.
func findFillSlots(doc any) []string {
	var out []string
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(joinJSONPath(path, k), x[k])
			}
		case []any:
			for i, e := range x {
				walk(fmt.Sprintf("%s[%d]", path, i), e)
			}
		case string:
			if strings.HasPrefix(x, fillMarker) {
				out = append(out, path+": "+x)
			}
		}
	}
	walk("", doc)
	return out
}

func joinJSONPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// agentFunctionary is the functionary for evidence the enrolled agent signs,
// copied exactly from the brief (jade/factory/edge/git/agentpolicyprompt.js,
// "The functionary for agent-signed evidence"). Every field is load-bearing:
// an empty commonname or list fails closed, and a URI without the tenant
// segment admits every tenant.
func agentFunctionary(trustDomain, tenantID string) map[string]any {
	return map[string]any{
		draftKeyType: functionaryTypeRoot,
		"certConstraint": map[string]any{
			"commonname":    "*",
			"dnsnames":      []any{"*"},
			"emails":        []any{"*"},
			"organizations": []any{"*"},
			"uris":          []any{fmt.Sprintf("spiffe://%s/tenant/%s/agent/*", trustDomain, tenantID)},
			"roots":         []any{platformFulcioRoot},
		},
	}
}

const (
	platformFulcioRoot = "fulcio-root"
	platformTSA        = "platform-tsa"
	// expectedPlatformRootError is the one error `cilock policy validate`
	// reports on a correct Pushgate draft, because the platform fills the
	// root when the human prepares the policy for signing
	// (cilock/internal/policy/validate.go validateRoots).
	expectedPlatformRootError = "Root 'fulcio-root': missing certificate data"
)

// platformTrustPlaceholders are the empty trust entries the platform fills.
func platformTrustPlaceholders() (roots, tsas map[string]any) {
	return map[string]any{platformFulcioRoot: map[string]any{"certificate": ""}},
		map[string]any{platformTSA: map[string]any{"certificate": ""}}
}
