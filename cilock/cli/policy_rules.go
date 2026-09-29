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
