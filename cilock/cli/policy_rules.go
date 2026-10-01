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
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	internalpolicy "github.com/aflock-ai/rookery/cilock/internal/policy"
)

// Seeded rule templates. Every module is RegoV0, as the verifier parses it,
// and every one is written to the same three disciplines:
//
//  1. It reads the predicate through `pred := field(input, "attestation",
//     input)`. A step with attestationsFrom or externalFrom hands every one of
//     its attestations the wrapped input {attestation, steps, external}
//     (attestation/policy/rego.go buildRegoInput), so a rule that reads
//     input.exitcode directly stops matching the moment a step gains an edge.
//  2. It fails closed: a missing, null or mistyped decision field is a deny
//     with an "unreadable evidence" message, never an undefined comparison.
//  3. Every message is total: the fields it interpolates go through
//     object.get with a default, so a deny can never go undefined because the
//     text it wanted to print was missing.
//
// A rule that needs a repository-specific value takes it as a JSON parameter.
// Until the model supplies it the module field holds a fill slot instead.

const (
	ruleCommandSucceeded     = "command-succeeded"
	ruleCommandPin           = "command-pin"
	ruleProductRecorded      = "product-recorded"
	ruleTestsPass            = "tests-pass"
	ruleSARIFNoErrors        = "sarif-no-errors"
	ruleSecretscanClean      = "secretscan-no-findings"
	ruleGovulncheckReachable = "govulncheck-no-reachable"
	ruleGovulncheckVEX       = "govulncheck-vex-covered"
	ruleSARIFVEX             = "sarif-vex-covered"
	ruleTrivySeverity        = "trivy-no-blocked-severity"
	ruleSLSAProvenance       = "slsa-provenance"
	ruleSBOMInventory        = "sbom-inventory"
	ruleReviewApproved       = "review-approved"
	ruleProductsFrom         = "products-from"
)

// Predicate types the seeded rules attach to: each is the type its attestor
// registers (plugins/attestors/<name>).
const (
	typeCommandRun  = "https://aflock.ai/attestations/command-run/v0.2"
	typeProduct     = productTreeType
	typeTestResults = "https://aflock.ai/attestations/test-results/v0.1"
	typeSARIF       = "https://aflock.ai/attestations/sarif/v0.1"
	typeLeakScan    = "https://aflock.ai/attestations/secretscan/v0.1"
	typeGovulncheck = "https://aflock.ai/attestations/govulncheck/v0.1"
)

// fillMarker opens every slot the model must fill. A slot is a JSON string
// value, so a slot in a rego module field is also invalid base64 and
// `cilock policy validate` refuses it on its own. No other metadata marks a
// slot: a hand-written draft that uses the marker is treated exactly like a
// templated one.
const fillMarker = internalpolicy.FillSlotMarker

// regoLiteral renders a value as a Rego literal. JSON strings, numbers,
// arrays and objects are valid Rego terms with the same meaning.
func regoLiteral(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ruleTemplate is one seeded rule. Param is empty for a rule with nothing to
// fill; otherwise it says what JSON value the model supplies.
type ruleTemplate struct {
	ID      string `json:"id"`
	Type    string `json:"attestation_type"`
	Summary string `json:"enforces"`
	Param   string `json:"fill,omitempty"`
	Example string `json:"fill_example,omitempty"`
	build   func(param json.RawMessage) (string, error)
}

// ruleTemplates is keyed by rule id; the id is also the regopolicies name the
// template writes.
var ruleTemplates = map[string]ruleTemplate{
	ruleCommandSucceeded: {ID: ruleCommandSucceeded, Type: typeCommandRun,
		Summary: "the wrapped command exited 0",
		build:   fixedModule(commandSucceededModule)},
	ruleCommandPin: {ID: ruleCommandPin, Type: typeCommandRun,
		Summary: "the wrapped command is exactly the pinned argv, so wrapping `true` cannot satisfy the step",
		Param:   "JSON array of the exact argv the step runs (what `cilock run --step <step> -- <argv>` records as cmd)",
		Example: `["go","test","./..."]`,
		build:   buildCommandPin},
	ruleProductRecorded: {ID: ruleProductRecorded, Type: typeProduct,
		Summary: "the step recorded at least one product by digest",
		build:   fixedModule(productRecordedModule)},
	ruleTestsPass: {ID: ruleTestsPass, Type: typeTestResults,
		Summary: "the report ran at least one test, and none failed or errored",
		build:   fixedModule(testsPassModule)},
	ruleSARIFNoErrors: {ID: ruleSARIFNoErrors, Type: typeSARIF,
		Summary: "no SARIF result at level error (a result's level falls back to its rule's defaultConfiguration, then to warning, as SARIF 2.1.0 specifies; every rule reference is resolved, and a run with configuration overrides or policies is refused as unreadable)",
		build:   fixedModule(sarifNoErrorsModule)},
	ruleSecretscanClean: {ID: ruleSecretscanClean, Type: typeLeakScan,
		Summary: "no secret finding, and no product changed between recording and scanning",
		build:   fixedModule(secretscanCleanModule)},
	ruleGovulncheckReachable: {ID: ruleGovulncheckReachable, Type: typeGovulncheck,
		Summary: "no vulnerability reachable from this code (symbol-level scan; unreachable findings are advisory)",
		build:   fixedModule(govulncheckReachableModule)},
	ruleGovulncheckVEX: {ID: ruleGovulncheckVEX, Type: typeGovulncheck,
		Summary: "every govulncheck finding (by GO id or any CVE/GHSA alias) is covered by a VEX statement from the named vex step, for one of the named products, with status fixed, or not_affected with a justification",
		Param:   `JSON object {"vexStep": "<step whose vex attestation this reads>", "products": ["<purl, @id or sha256 the VEX statements must name>"] ([] accepts any product)}`,
		Example: `{"vexStep":"vex","products":["pkg:golang/example.com/app"]}`,
		build:   buildVEXCovered(vexScanGovulncheck)},
	ruleSARIFVEX: {ID: ruleSARIFVEX, Type: typeSARIF,
		Summary: "every SARIF result from a vulnerability scanner (osv-scanner, grype, trivy SARIF) is covered, by ruleId, by a VEX statement with status fixed, or not_affected with a justification",
		Param:   `JSON object {"vexStep": "<step whose vex attestation this reads>", "products": ["<purl, @id or sha256>"]}`,
		Example: `{"vexStep":"vex","products":["pkg:oci/app@sha256:<digest>"]}`,
		build:   buildVEXCovered(vexScanSARIF)},
	ruleTrivySeverity: {ID: ruleTrivySeverity, Type: typeTrivy,
		Summary: "no failed Trivy finding at a blocked severity",
		Param:   "JSON array of blocked severities, lowercase",
		Example: `["critical","high"]`,
		build:   buildTrivySeverity},
	ruleSLSAProvenance: {ID: ruleSLSAProvenance, Type: typeSLSA,
		Summary: "provenance names at least one build input, and every input carries a digest",
		build:   fixedModule(slsaProvenanceModule)},
	ruleSBOMInventory: {ID: ruleSBOMInventory, Type: typeCycloneDX,
		Summary: "the SBOM is CycloneDX with components[] or SPDX with packages[], and lists at least one",
		build:   fixedModule(sbomInventoryModule)},
	ruleReviewApproved: {ID: ruleReviewApproved, Type: typeGitHubReview,
		Summary: "a pull request of this commit has an APPROVED review on this exact commit",
		build:   fixedModule(reviewApprovedModule)},
	ruleProductsFrom: {ID: ruleProductsFrom, Type: typeProduct,
		Summary: "every product this step ships is, by digest, a product of the named upstream step (read through attestationsFrom)",
		Param:   "JSON string: the upstream step name (template fills it from --attestations-from)",
		Example: `"build"`,
		build:   buildProductsFrom},
}

func fixedModule(src string) func(json.RawMessage) (string, error) {
	return func(param json.RawMessage) (string, error) {
		if len(param) > 0 {
			return "", fmt.Errorf("this rule takes no fill value")
		}
		return src, nil
	}
}

// ruleRequiresParam reports whether a rule has a slot to fill.
func (r ruleTemplate) requiresParam() bool { return r.Param != "" }

// renderRule builds the module source for a rule, or returns an error that
// names what the value must look like.
func renderRule(id string, param json.RawMessage) (string, error) {
	r, ok := ruleTemplates[id]
	if !ok {
		return "", fmt.Errorf("no seeded rule named %q (known: %s)", id, strings.Join(sortedRuleIDs(), ", "))
	}
	if r.requiresParam() && len(param) == 0 {
		return "", fmt.Errorf("rule %s needs a value: %s, e.g. %s", id, r.Param, r.Example)
	}
	src, err := r.build(param)
	if err != nil {
		return "", fmt.Errorf("rule %s: %w (want %s, e.g. %s)", id, err, r.Param, r.Example)
	}
	return src, nil
}

func sortedRuleIDs() []string {
	ids := make([]string, 0, len(ruleTemplates))
	for id := range ruleTemplates {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func decodeStringList(param json.RawMessage, allowEmpty bool) ([]string, error) {
	var list []string
	if err := json.Unmarshal(param, &list); err != nil {
		return nil, fmt.Errorf("not a JSON array of strings: %v", err)
	}
	if !allowEmpty && len(list) == 0 {
		return nil, fmt.Errorf("the list is empty")
	}
	for _, s := range list {
		if strings.TrimSpace(s) == "" {
			return nil, fmt.Errorf("the list contains an empty string")
		}
		if strings.HasPrefix(s, fillMarker) {
			return nil, fmt.Errorf("the list still contains a fill slot")
		}
	}
	return list, nil
}

func buildCommandPin(param json.RawMessage) (string, error) {
	argv, err := decodeStringList(param, false)
	if err != nil {
		return "", err
	}
	lit, err := regoLiteral(argv)
	if err != nil {
		return "", err
	}
	return strings.Replace(commandPinModule, "__ARGV__", lit, 1), nil
}

// trivySeverityUnknown is trivy's severity for a finding it could not rate.
const trivySeverityUnknown = "unknown"

// regoPackageSafe turns a step name into the tail of a Rego package name.
var regoPackageUnsafe = regexp.MustCompile(`[^a-z0-9_]`)

func regoPackageSafe(s string) string {
	return regoPackageUnsafe.ReplaceAllString(strings.ToLower(s), "_")
}

func buildTrivySeverity(param json.RawMessage) (string, error) {
	sev, err := decodeStringList(param, false)
	if err != nil {
		return "", err
	}
	known := map[string]bool{"critical": true, "high": true, "medium": true, "low": true, trivySeverityUnknown: true}
	for _, s := range sev {
		if !known[s] {
			return "", fmt.Errorf("unknown severity %q (Trivy's summary keys are critical, high, medium, low, unknown)", s)
		}
	}
	lit, err := regoLiteral(sev)
	if err != nil {
		return "", err
	}
	return strings.Replace(trivySeverityModule, "__SEVERITIES__", lit, 1), nil
}

func buildProductsFrom(param json.RawMessage) (string, error) {
	var upstream string
	if err := json.Unmarshal(param, &upstream); err != nil || strings.TrimSpace(upstream) == "" {
		return "", fmt.Errorf("want the upstream step name as a JSON string")
	}
	lit, err := regoLiteral(upstream)
	if err != nil {
		return "", err
	}
	src := strings.Replace(productsFromModule, "__UPSTREAM__", lit, 1)
	return strings.Replace(src, "__PKG__", regoPackageSafe(upstream), 1), nil
}

type vexScanKind int

const (
	vexScanGovulncheck vexScanKind = iota
	vexScanSARIF
)

type vexParam struct {
	VEXStep  string   `json:"vexStep"`
	Products []string `json:"products"`
}

func buildVEXCovered(kind vexScanKind) func(json.RawMessage) (string, error) {
	return func(param json.RawMessage) (string, error) {
		var p vexParam
		dec := json.NewDecoder(strings.NewReader(string(param)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return "", fmt.Errorf("not the expected JSON object: %v", err)
		}
		if strings.TrimSpace(p.VEXStep) == "" {
			return "", fmt.Errorf("vexStep is empty")
		}
		if p.Products == nil {
			return "", fmt.Errorf("products is missing: list the products the VEX statements must name, or [] to accept a statement for any product")
		}
		products, err := decodeStringList(mustMarshal(p.Products), true)
		if err != nil {
			return "", fmt.Errorf("products: %w", err)
		}
		stepLit, err := regoLiteral(p.VEXStep)
		if err != nil {
			return "", err
		}
		prodLit, err := regoLiteral(products)
		if err != nil {
			return "", err
		}
		scan := govulncheckVEXFindings
		if kind == vexScanSARIF {
			scan = sarifVEXFindings
		}
		src := strings.Replace(vexCoveredModule, "__SCAN__", scan, 1)
		src = strings.Replace(src, "__VEXSTEP__", stepLit, 1)
		return strings.Replace(src, "__PRODUCTS__", prodLit, 1), nil
	}
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// predRead is the shape-agnostic read every module opens with, plus field,
// the total accessor every module reads nested evidence through: a field of
// something that is not an object is the default, never an error or
// undefined, so a message built from it cannot drop the deny it belongs to.
const predRead = `pred := object.get(input, "attestation", input)

field(x, k, d) = v { is_object(x); v := object.get(x, k, d) } else = d
`

const commandSucceededModule = `package commandrun_succeeded

` + predRead + `
readable_exit { is_number(field(pred, "exitcode", null)) }

deny[msg] {
	not readable_exit
	msg := "unreadable evidence: command-run has no numeric exitcode"
}

deny[msg] {
	readable_exit
	pred.exitcode != 0
	msg := sprintf("wrapped command exited %v, not 0", [pred.exitcode])
}
`

const commandPinModule = `package commandrun_pinned

` + predRead + `
expected := __ARGV__

readable_cmd { is_array(field(pred, "cmd", null)) }

deny[msg] {
	not readable_cmd
	msg := "unreadable evidence: command-run has no cmd argv"
}

deny[msg] {
	readable_cmd
	pred.cmd != expected
	msg := sprintf("command must be %v; got %v", [expected, pred.cmd])
}
`

const productRecordedModule = `package product_recorded

` + predRead + `
readable {
	is_number(field(pred, "treeSize", null))
	is_string(field(pred, "merkleRoot", null))
}

deny[msg] {
	not readable
	msg := "unreadable evidence: product needs a numeric treeSize and a merkleRoot"
}

deny[msg] {
	readable
	pred.treeSize < 1
	msg := "product: the step recorded no products; write the outputs under the working directory so they are recorded by digest"
}
`

const testsPassModule = `package tests_pass

` + predRead + `
summary := field(field(pred, "predicate", {}), "summary", null)

# A count is a nonnegative integer: a negative failed or errors count is not
# "> 0", so it would read as a pass.
count_value(x) { is_number(x); x >= 0; floor(x) == x }

readable {
	is_object(summary)
	count_value(field(summary, "total", null))
	count_value(field(summary, "passed", null))
	count_value(field(summary, "failed", null))
	count_value(field(summary, "errors", 0))
	count_value(field(summary, "skipped", 0))
}

deny[msg] {
	not readable
	msg := "unreadable evidence: test-results needs predicate.summary with total, passed and failed (and any errors or skipped) as nonnegative integers"
}

deny[msg] {
	readable
	summary.total < 1
	msg := "test-results: the report recorded 0 tests; zero tests passing is not tests passing"
}

# A report whose every test was skipped ran nothing: it is not tests passing
# either.
deny[msg] {
	readable
	summary.total >= 1
	summary.passed < 1
	msg := sprintf("test-results: none of %v tests passed (%v skipped)", [summary.total, field(summary, "skipped", 0)])
}

deny[msg] {
	readable
	summary.failed > 0
	msg := sprintf("test-results: %v of %v tests failed", [summary.failed, summary.total])
}

deny[msg] {
	readable
	field(summary, "errors", 0) > 0
	msg := sprintf("test-results: %v tests errored", [field(summary, "errors", 0)])
}
`

const sarifNoErrorsModule = `package sarif_no_errors

` + predRead + `
runs := field(field(pred, "report", {}), "runs", null)

# SARIF 2.1.0 §3.58.6: the only levels there are.
sarif_levels := {"none", "note", "warning", "error"}

rules_of(run) = rs { rs := field(field(field(run, "tool", {}), "driver", {}), "rules", null); rs != null } else = []

unreadable_run { r := runs[_]; not is_array(field(r, "results", null)) }

unreadable_run { r := runs[_]; not is_array(rules_of(r)) }

# Configuration overrides and policies can raise a rule's level for this run
# (SARIF 2.1.0 §3.27.10, §3.20.5, §3.14.27). This rule does not resolve them,
# so a run that carries any is unreadable rather than read at the rule's
# default.
unreadable_run {
	r := runs[_]
	inv := field(r, "invocations", [])
	not is_array(inv)
}

unreadable_run {
	r := runs[_]
	inv := field(r, "invocations", [])[_]
	o := field(inv, "ruleConfigurationOverrides", [])
	o != []
}

# SARIF 2.1.0 §3.20.14: an invocation says whether the tool finished. A run
# whose invocation did not, or does not say, has no complete result list, so
# its empty results are not "no errors".
unreadable_run { r := runs[_]; inv := field(r, "invocations", [])[_]; not is_object(inv) }

unreadable_run { r := runs[_]; inv := field(r, "invocations", [])[_]; field(inv, "executionSuccessful", null) != true }

unreadable_run {
	r := runs[_]
	p := field(r, "policies", [])
	p != []
}

results[[run, r]] { run := runs[_]; r := field(run, "results", [])[_] }

# Every way a result names its rule (SARIF 2.1.0 §3.27.5-§3.27.7, §3.52): by
# position through ruleIndex or rule.index, by id through ruleId or rule.id.
# All of them are read, so a result cannot hide its rule behind the one
# spelling a check does not look at.
ref(r) = field(r, "rule", null)

index_refs(r) = {i | i := field(r, "ruleIndex", null); i != null} | {i | i := field(ref(r), "index", null); i != null}

id_refs(r) = {x | x := field(r, "ruleId", null); x != null} | {x | x := field(ref(r), "id", null); x != null}

# A result that is not an object, a level outside SARIF's enum (explicit or a
# rule's default), or a rule reference that cannot be resolved against the
# driver's rules cannot be read as any level, so it is unreadable evidence,
# never a warning.
unreadable_result { results[[_, r]]; not is_object(r) }

unreadable_result { results[[_, r]]; is_object(r); not sarif_levels[field(r, "level", "warning")] }

listed_rule(run, i) {
	is_number(i)
	i >= 0
	i < count(rules_of(run))
	is_object(rules_of(run)[i])
}

unreadable_result { results[[_, r]]; ref(r) != null; not is_object(ref(r)) }

# A rule in a tool extension is out of this rule's reach.
unreadable_result { results[[_, r]]; field(ref(r), "toolComponent", null) != null }

unreadable_result { results[[run, r]]; i := index_refs(r)[_]; not listed_rule(run, i) }

unreadable_result { results[[_, r]]; x := id_refs(r)[_]; not is_string(x) }

unreadable_result { results[[run, r]]; l := default_levels(run, r)[_]; not sarif_levels[l] }

readable {
	is_array(runs)
	count(runs) > 0
	not unreadable_run
	not unreadable_result
}

# A rule id names a rule exactly, or as a hierarchical prefix: "E/sub" is a
# sub-rule of rule "E" (§3.27.5).
names(rule, x) { is_string(x); field(rule, "id", null) == x }

names(rule, x) {
	is_string(x)
	id := field(rule, "id", null)
	is_string(id)
	id != ""
	startswith(x, concat("", [id, "/"]))
}

rule_level(rule) = field(field(rule, "defaultConfiguration", {}), "level", "warning")

# Every rule the result names supplies a default level. A set, so two rules
# sharing an id, or references that disagree, can only add levels: any of
# them at error makes the result an error.
default_levels(run, r) = {l | i := index_refs(r)[_]; l := rule_level(rules_of(run)[i])} | {l |
	x := id_refs(r)[_]
	rule := rules_of(run)[_]
	names(rule, x)
	l := rule_level(rule)
}

# A result's own level wins; with none, its rule's default decides, and with
# neither it is a warning (SARIF 2.1.0 §3.27.10).
error_level(run, r) { field(r, "level", null) == "error" }

error_level(run, r) { field(r, "level", null) == null; default_levels(run, r)["error"] }

where(r) = uri { uri := r.locations[0].physicalLocation.artifactLocation.uri } else = "an unknown location"

tool(run) = field(field(field(run, "tool", {}), "driver", {}), "name", "a tool")

deny[msg] {
	not readable
	msg := "unreadable evidence: sarif needs report.runs as a non-empty array of runs with no configuration overrides or policies, each with a results array of objects whose level is none, note, warning or error and whose rule references name listed driver rules"
}

deny[msg] {
	readable
	results[[run, r]]
	error_level(run, r)
	msg := sprintf("sarif: %v reported an error-level result: rule %v at %v", [tool(run), field(r, "ruleId", "unnamed"), where(r)])
}
`

const secretscanCleanModule = `package secretscan_no_findings

` + predRead + `
# Absent is unreadable; the attestor always writes the key (secretscan
# config.go), and only an explicit null reads as no findings.
findings = [] { pred.findings == null }

findings = fs {
	is_array(field(pred, "findings", null))
	fs := pred.findings
}

mismatches = [] { field(pred, "scope", null) == null }

mismatches = [] {
	is_object(field(pred, "scope", null))
	field(pred.scope, "productDigestMismatches", null) == null
}

mismatches = ms {
	is_array(field(field(pred, "scope", {}), "productDigestMismatches", null))
	ms := pred.scope.productDigestMismatches
}

# A finding that is not an object is still a finding, but one that cannot be
# read: unreadable, so it can neither pass nor lose its deny to its message.
unreadable_finding { f := findings[_]; not is_object(f) }

readable {
	is_array(findings)
	is_array(mismatches)
	not unreadable_finding
}

deny[msg] {
	not readable
	msg := "unreadable evidence: secretscan needs a findings list of objects and a readable scope"
}

deny[msg] {
	readable
	f := findings[_]
	msg := sprintf("secretscan: %v finding(s), e.g. rule %v at %v", [count(findings),
		field(f, "ruleId", "unnamed"), field(f, "location", "an unknown location")])
}

deny[msg] {
	readable
	count(mismatches) > 0
	msg := sprintf("secretscan: %v product(s) changed between recording and scanning", [count(mismatches)])
}
`

const govulncheckReachableModule = `package govulncheck_no_reachable

` + predRead + `
summary := field(pred, "summary", {})

findings = [] { summary.findings == null }

findings = fs {
	is_array(field(summary, "findings", null))
	fs := summary.findings
}

count_value(x) { is_number(x); x >= 0; floor(x) == x }

readable {
	count_value(field(summary, "reachableCount", null))
	count_value(field(summary, "unreachableCount", null))
	field(summary, "scanLevel", "") == "symbol"
	is_array(findings)
}

flagged(f) { is_boolean(field(f, "reachable", null)) }

deny[msg] {
	not readable
	msg := "unreadable evidence: govulncheck needs a symbol-level scan with nonnegative integer counts and a findings list"
}

deny[msg] {
	readable
	summary.reachableCount > 0
	msg := sprintf("govulncheck: %v vulnerabilities reachable from this code", [summary.reachableCount])
}

deny[msg] {
	readable
	f := findings[_]
	not flagged(f)
	msg := "unreadable evidence: a govulncheck finding has no reachable flag"
}

deny[msg] {
	readable
	f := findings[_]
	f.reachable == true
	msg := sprintf("govulncheck: %v is reachable from this code", [field(f, "osvId", "an unnamed vulnerability")])
}

deny[msg] {
	readable
	count(findings) != summary.reachableCount + summary.unreachableCount
	msg := "inconsistent evidence: govulncheck counts disagree with its findings list"
}
`

const vexCoveredModule = `package vex_covered

` + predRead + `
vex_step := __VEXSTEP__
products := {p | p := __PRODUCTS__[_]}

__SCAN__
vex_docs[d] {
	c := input.steps[vex_step].collections[_]
	d := field(field(c, "attestations", {}), "https://openvex.dev/ns", {})["vexDocument"]
}

vex_readable {
	count(vex_docs) > 0
	not unreadable_vex
}

unreadable_vex { d := vex_docs[_]; not is_array(field(d, "statements", null)) }

statement_names(s) = names {
	v := field(s, "vulnerability", {})
	names := {n | n := field(v, "name", ""); n != ""} | {n | n := field(v, "@id", ""); n != ""} | {a | a := field(v, "aliases", [])[_]; a != ""}
}

statement_products(s) = ids {
	ids := {i | p := field(s, "products", [])[_]; i := field(p, "@id", "")} |
		{i | p := field(s, "products", [])[_]; i := field(field(p, "identifiers", {}), "purl", "")} |
		{i | p := field(s, "products", [])[_]; i := field(field(p, "hashes", {}), "sha-256", "")}
}

# An empty products list accepts a statement for any product.
product_matches(s) { count(products) == 0 }

product_matches(s) { count(products & statement_products(s)) > 0 }

settled(s) { field(s, "status", "") == "fixed" }

settled(s) {
	field(s, "status", "") == "not_affected"
	j := field(s, "justification", "")
	is_string(j)
	j != ""
}

covered(id) {
	d := vex_docs[_]
	s := d.statements[_]
	count(finding_ids[id] & statement_names(s)) > 0
	product_matches(s)
	settled(s)
}

deny[msg] {
	not scan_readable
	msg := "unreadable evidence: the scan report this rule reads is missing or malformed"
}

# No findings needs no VEX; a finding with no readable VEX fails closed.
deny[msg] {
	scan_readable
	count(finding_ids) > 0
	not vex_readable
	msg := sprintf("unreadable evidence: no readable OpenVEX document from step %v (add it to attestationsFrom and record it with -a vex)", [vex_step])
}

deny[msg] {
	scan_readable
	vex_readable
	finding_ids[id]
	not covered(id)
	msg := sprintf("vex: %v is not covered by a VEX statement for %v with status fixed, or not_affected with a justification", [id, concat(", ", sort([p | products[p]]))])
}
`

const govulncheckVEXFindings = `summary := field(pred, "summary", {})

scan_findings = [] { summary.findings == null }

scan_findings = fs {
	is_array(field(summary, "findings", null))
	fs := summary.findings
}

# A scan with no roots scanned nothing (govulncheck.go ScanRoots); its empty
# findings list is not a clean result.
scanned {
	roots := field(summary, "scanRoots", null)
	is_array(roots)
	count(roots) > 0
}

scan_readable {
	is_array(scan_findings)
	is_array(field(pred, "report", []))
	not unnamed_finding
	counts_agree
	scanned
}

# The attestor writes one finding per OSV id and counts each as reachable or
# not, and totalFindings counts every trace tier, so it is at least that and
# zero only when there are none. A list that disagrees with its own counts
# (findings null while reachableCount says 3) is not a clean scan.
count_fields_numeric {
	is_number(field(summary, "reachableCount", null))
	is_number(field(summary, "unreachableCount", null))
	is_number(field(summary, "totalFindings", null))
}

counts_agree {
	count_fields_numeric
	n := count(scan_findings)
	n == summary.reachableCount + summary.unreachableCount
	count([f | f := scan_findings[_]; field(f, "reachable", false) == true]) == summary.reachableCount
	summary.totalFindings >= n
	n > 0
}

counts_agree {
	count_fields_numeric
	count(scan_findings) == 0
	summary.reachableCount == 0
	summary.unreachableCount == 0
	summary.totalFindings == 0
}

valid_id(id) { is_string(id); id != "" }

unnamed_finding { f := scan_findings[_]; not valid_id(field(f, "osvId", null)) }

finding_ids[id] = names {
	f := scan_findings[_]
	id := f.osvId
	names := {id} | {a | m := field(pred, "report", [])[_]; o := field(m, "osv", {}); field(o, "id", "") == id; a := field(o, "aliases", [])[_]; is_string(a); a != ""}
}
`

const sarifVEXFindings = `runs := field(field(pred, "report", {}), "runs", null)

unreadable_run { r := runs[_]; not is_array(field(r, "results", null)) }

# SARIF 2.1.0 §3.20.14: a run whose invocation did not finish, or does not
# say, has no complete result list, so its empty results need no VEX only
# in appearance.
unreadable_run { r := runs[_]; not is_array(field(r, "invocations", [])) }

unreadable_run { r := runs[_]; inv := field(r, "invocations", [])[_]; not is_object(inv) }

unreadable_run { r := runs[_]; inv := field(r, "invocations", [])[_]; field(inv, "executionSuccessful", null) != true }

valid_id(id) { is_string(id); id != "" }

unnamed_result { r := runs[_].results[_]; not valid_id(field(r, "ruleId", null)) }

scan_readable {
	is_array(runs)
	count(runs) > 0
	not unreadable_run
	not unnamed_result
}

finding_ids[id] = names {
	r := runs[_].results[_]
	id := r.ruleId
	names := {id}
}
`

const trivySeverityModule = `package trivy_blocked_severity

` + predRead + `
blocked := __SEVERITIES__

by := object.get(object.get(pred, "summary", {}), "bySeverity", null)

readable { is_object(by) }

deny[msg] {
	not readable
	msg := "unreadable evidence: trivy needs summary.bySeverity"
}

deny[msg] {
	readable
	s := blocked[_]
	n := object.get(object.get(by, s, {}), "fail", 0)
	not is_number(n)
	msg := sprintf("unreadable evidence: trivy bySeverity.%v.fail is not a number", [s])
}

deny[msg] {
	readable
	s := blocked[_]
	n := object.get(object.get(by, s, {}), "fail", 0)
	is_number(n)
	n < 0
	msg := sprintf("unreadable evidence: trivy bySeverity.%v.fail is %v, not a count", [s, n])
}

deny[msg] {
	readable
	s := blocked[_]
	n := object.get(object.get(by, s, {}), "fail", 0)
	is_number(n)
	n > 0
	msg := sprintf("trivy: %v failed %v finding(s)", [n, s])
}
`

const slsaProvenanceModule = `package slsa_provenance

` + predRead + `
deps := object.get(object.get(pred, "buildDefinition", {}), "resolvedDependencies", null)

readable { is_array(deps) }

deny[msg] {
	not readable
	msg := "unreadable evidence: slsa needs buildDefinition.resolvedDependencies"
}

deny[msg] {
	readable
	count(deps) < 1
	msg := "slsa: the provenance names no build inputs"
}

hex_digest(v) {
	is_string(v)
	regex.match("^[0-9a-f]{32,}$", v)
}

bad_digest_entry(dg) { v := dg[_]; not hex_digest(v) }

digest_ok(dg) {
	is_object(dg)
	count(dg) > 0
	not bad_digest_entry(dg)
}

deny[msg] {
	readable
	d := deps[_]
	not digest_ok(object.get(d, "digest", null))
	msg := sprintf("slsa: build input %v has no digest (want at least one algorithm with a lowercase hex value, every value valid)", [object.get(d, "uri", object.get(d, "name", "unnamed"))])
}
`

const sbomInventoryModule = `package sbom_inventory

` + predRead + `
sbom_format := object.get(pred, "_sbomFormat", "")

items = object.get(pred, "components", null) { sbom_format == "cyclonedx" }

items = object.get(pred, "packages", null) { sbom_format == "spdx" }

readable { is_array(items) }

deny[msg] {
	not readable
	msg := "unreadable evidence: sbom needs _sbomFormat cyclonedx with components[] or spdx with packages[]"
}

deny[msg] {
	readable
	count(items) < 1
	msg := "sbom: the SBOM lists no components"
}
`

const reviewApprovedModule = `package review_approved

` + predRead + `
prs := object.get(pred, "prs", null)

commit := object.get(pred, "commit_sha", null)

readable {
	is_array(prs)
	is_string(commit)
	commit != ""
}

approved {
	pr := prs[_]
	rv := field(pr, "reviews", [])[_]
	field(rv, "state", "") == "APPROVED"
	id := field(rv, "commit_id", null)
	is_string(id)
	id == commit
}

deny[msg] {
	not readable
	msg := "unreadable evidence: github-review needs prs[] and commit_sha"
}

deny[msg] {
	readable
	not approved
	msg := sprintf("github-review: no APPROVED review on commit %v", [commit])
}
`

// productsFromModule reads the upstream step's product predicate through
// attestationsFrom: input.steps.<step>.collections[].attestations[<type>]
// (attestation/policy/step.go buildStepContext).
const productsFromModule = `package products_from___PKG__

` + predRead + `
upstream := __UPSTREAM__

product_type := "https://aflock.ai/attestations/product/v0.3"

mine := object.get(pred, "leaves", null)

upstream_products[c] {
	col := input.steps[upstream].collections[_]
	c := field(field(col, "attestations", {}), product_type, null)
}

unreadable_upstream { c := upstream_products[_]; not is_array(field(c, "leaves", null)) }

valid_digest(d) {
	is_string(d)
	regex.match("^[0-9a-f]{64}$", d)
}

upstream_digests[d] {
	c := upstream_products[_]
	l := c.leaves[_]
	d := field(l, "fileDigest", null)
	valid_digest(d)
}

readable {
	is_array(mine)
	count(upstream_products) > 0
	not unreadable_upstream
}

deny[msg] {
	not readable
	msg := sprintf("unreadable evidence: products-from needs this step's inline product leaves and step %v's, through attestationsFrom", [upstream])
}

deny[msg] {
	readable
	count(mine) < 1
	msg := "products-from: this step shipped no products"
}

deny[msg] {
	readable
	l := mine[_]
	not valid_digest(field(l, "fileDigest", null))
	msg := sprintf("products-from: %v has no sha256 fileDigest, so nothing ties it to step %v", [field(l, "path", "an unnamed product"), upstream])
}

deny[msg] {
	readable
	l := mine[_]
	d := field(l, "fileDigest", null)
	valid_digest(d)
	not upstream_digests[d]
	msg := sprintf("products-from: %v is not, by digest, a product of step %v", [field(l, "path", "an unnamed product"), upstream])
}
`
