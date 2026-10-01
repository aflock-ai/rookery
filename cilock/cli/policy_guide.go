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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/spf13/cobra"
)

// Topic names used more than once.
const (
	guideTopicAttestorsName = "attestors"
	guideTopicVEXName       = "vex"
)

type guideOptions struct {
	goals  []string
	topics []string
	format string
	dir    string
}

// PolicyGuideCmd is `cilock policy guide`: the catalog made legible to the
// model that authors the policy. One command replaces the help and schema
// pages an agent otherwise reads one by one. It decides nothing.
func PolicyGuideCmd() *cobra.Command {
	o := guideOptions{}
	cmd := &cobra.Command{
		Use:   "guide",
		Short: "What each policy goal needs: attestors, what the command must produce, run flags, predicate fields, seeded rules",
		Long: `guide explains how to evidence each Pushgate goal with cilock, for the model
that writes the policy. You author the policy: which steps, which commands,
which attestors and what the rules say for THIS repository. cilock supplies
the knowledge (this command), the scaffolding ('cilock policy template') and
the draft check ('cilock policy validate').

Goal ids are the ones your human picks on the Pushgate policy page. For each
goal guide prints the attestation types, what the wrapped command must leave
behind, the exact 'cilock run' line, the predicate fields a rule reads, the
seeded fail-closed Rego, and the tools the detection catalog knows for it
(suggestions, marked when on PATH; never decisions).

Topics: flow, rego, chain, trace, vex, attestors, rules.`,
		Example: `  cilock policy guide
  cilock policy guide --goal tests --goal quality
  cilock policy guide --topic chain --topic trace
  cilock policy guide --format json`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyGuide(cmd.OutOrStdout(), o)
		},
	}
	cmd.Flags().StringArrayVar(&o.goals, "goal", nil, "Goal id to explain in full (repeat). Ids: "+strings.Join(goalIDs(), ", "))
	cmd.Flags().StringArrayVar(&o.topics, "topic", nil, "Topic to explain (repeat): "+strings.Join(guideTopicNames(), ", "))
	cmd.Flags().StringVar(&o.format, "format", "text", "Output format: text or json")
	cmd.Flags().StringVarP(&o.dir, "dir", "d", ".", "Repository to look at for suggestions")
	return cmd
}

// guideRule is a rule template as guide shows it, with its Rego source.
type guideRule struct {
	ruleTemplate
	Module string `json:"module,omitempty"`
}

type guideAttestation struct {
	catalogAttestor
	RulesDetail []guideRule `json:"rules,omitempty"`
}

type guideGoal struct {
	catalogGoal
	Attestations []guideAttestation `json:"attestations"`
	Tools        []catalogTool      `json:"tools"`
	Run          string             `json:"run"`
	Template     string             `json:"template"`
}

type guideDoc struct {
	Flow     string            `json:"flow"`
	Goals    []guideGoal       `json:"goals"`
	Topics   map[string]string `json:"topics"`
	Detected []string          `json:"repository_markers,omitempty"`
}

func runPolicyGuide(out io.Writer, o guideOptions) error {
	if o.format != "text" && o.format != flagJSON {
		return fmt.Errorf("--format %q: want text or json", o.format)
	}
	for _, g := range o.goals {
		if _, ok := goalByID(g); !ok {
			return fmt.Errorf("unknown goal %q. Ids: %s", g, strings.Join(goalIDs(), ", "))
		}
	}
	for _, t := range o.topics {
		if _, ok := guideTopics[t]; !ok {
			return fmt.Errorf("unknown topic %q. Topics: %s", t, strings.Join(guideTopicNames(), ", "))
		}
	}
	doc := buildGuide(o)
	if o.format == flagJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(doc)
	}
	writeGuideText(out, doc, o)
	return nil
}

func buildGuide(o guideOptions) guideDoc {
	reg := guideRegistry()
	onPath := func(bin string) bool { _, err := exec.LookPath(bin); return err == nil }
	doc := guideDoc{Flow: guideFlow, Topics: map[string]string{}}
	wanted := map[string]bool{}
	for _, g := range o.goals {
		wanted[g] = true
	}
	for _, g := range catalogGoals {
		if len(wanted) > 0 && !wanted[g.ID] {
			continue
		}
		doc.Goals = append(doc.Goals, buildGuideGoal(reg, g, onPath))
	}
	topics := o.topics
	if o.format == flagJSON && len(topics) == 0 {
		topics = guideTopicNames()
	}
	for _, t := range topics {
		doc.Topics[t] = guideTopics[t]()
	}
	doc.Detected = repositoryMarkers(o.dir)
	return doc
}

// buildGuideGoal is one goal as the guide prints it: its attestations with
// their seeded rules, the run line that records them, and the candidate tools.
func buildGuideGoal(reg *detection.Registry, g catalogGoal, onPath func(string) bool) guideGoal {
	gg := guideGoal{catalogGoal: g, Tools: goalTools(reg, g, onPath)}
	var aFlags []string
	for _, t := range g.Attestors {
		a := catalogAttestors[t]
		gg.Attestations = append(gg.Attestations, guideAttestationFor(g, t))
		if !a.Always && a.Name != "" {
			aFlags = append(aFlags, "-a "+a.Name)
		}
		aFlags = append(aFlags, a.RunFlags...)
	}
	if g.ID == "provenance" {
		aFlags = append([]string{"-a git"}, aFlags...)
	}
	gg.Run = strings.TrimSpace(fmt.Sprintf("cilock run --step %s %s -- <argv>", g.ID, strings.Join(aFlags, " ")))
	gg.Template = "cilock policy template --goal " + g.ID
	return gg
}

// guideAttestationFor pairs the attestor for predicate type t with the rules
// the goal seeds for that type, rendering each module (with the example value
// when the rule takes one).
func guideAttestationFor(g catalogGoal, t string) guideAttestation {
	ga := guideAttestation{catalogAttestor: catalogAttestors[t]}
	for _, r := range g.Rules {
		rt := ruleTemplates[r]
		if rt.Type != t {
			continue
		}
		gr := guideRule{ruleTemplate: rt}
		if !rt.requiresParam() {
			gr.Module, _ = renderRule(r, nil)
		} else if src, err := renderRule(r, json.RawMessage(rt.Example)); err == nil {
			gr.Module = src
		}
		ga.RulesDetail = append(ga.RulesDetail, gr)
	}
	return ga
}

const guideFlow = `You author the policy; cilock supplies the knowledge, the scaffold and the draft check.
  1. cilock policy template --goal <id>...    scaffold .pushgate/policy.json (trust blocks, steps, seeded rules)
  2. fill every __FILL__ slot                  cilock policy template -p .pushgate/policy.json --fill <step>.<rule>=<json>, or edit by hand
     add or hand-write any step you need       cilock policy template -p .pushgate/policy.json --add-step <name> --attestor <name>
  3. cilock policy validate -p .pushgate/policy.json
     refuses an unfilled slot, a rule module that does not parse, and a root certificate that is not base64;
     then record each step for real with the cilock run line 'cilock policy guide --goal <id>' prints
  4. hand .pushgate/policy.json to your human; they import, validate, sign and activate it. You never sign, publish or activate.`

// guideWriter prints the guide's text form; write errors are not actionable
// for a help page, so they are dropped in one place.
type guideWriter struct{ out io.Writer }

func (w guideWriter) f(format string, args ...any) { _, _ = fmt.Fprintf(w.out, format, args...) }

func writeGuideText(out io.Writer, doc guideDoc, o guideOptions) {
	w := guideWriter{out}
	w.f("%s\n\n", doc.Flow)
	if len(doc.Detected) > 0 {
		w.f("Repository markers in %s (suggestions only): %s\n\n", o.dir, strings.Join(doc.Detected, ", "))
	}
	if len(o.goals) > 0 {
		for _, g := range doc.Goals {
			writeGuideGoal(w, g)
		}
	} else {
		writeGuideSummary(w, doc)
	}
	names := make([]string, 0, len(doc.Topics))
	for t := range doc.Topics {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		w.f("== topic: %s\n%s\n\n", t, doc.Topics[t])
	}
}

// writeGuideSummary is the no-goal form: one line per goal with its
// attestations, rules (* marks one with a slot) and catalog tools on PATH.
func writeGuideSummary(w guideWriter, doc guideDoc) {
	w.f("Goals (one step each, named by the id; * marks a rule with a slot you fill):\n")
	for _, g := range doc.Goals {
		var types, rules []string
		for _, a := range g.Attestations {
			types = append(types, a.Name)
			for _, r := range a.RulesDetail {
				mark := ""
				if r.requiresParam() {
					mark = "*"
				}
				rules = append(rules, r.ID+mark)
			}
		}
		var onPath []string
		for _, t := range g.Tools {
			if t.OnPath {
				onPath = append(onPath, t.Name)
			}
		}
		w.f("  %-16s %s\n", g.ID, g.Name)
		w.f("  %-16s attestations: %s; rules: %s\n", "", strings.Join(types, ", "), strings.Join(rules, ", "))
		if len(onPath) > 0 {
			w.f("  %-16s catalog tools on PATH: %s\n", "", strings.Join(onPath, ", "))
		}
	}
	w.f("\nNext: cilock policy guide --goal <id> for the run line, predicate fields, rule source and tools of a goal;\n")
	w.f("      cilock policy guide --topic <%s>.\n", strings.Join(guideTopicNames(), "|"))
}

// writeGuideGoal is the full form of one goal.
func writeGuideGoal(w guideWriter, g guideGoal) {
	w.f("== %s: %s\n", g.ID, g.Name)
	w.f("Scaffold:  %s\n", g.Template)
	w.f("Evidence:  %s\n", g.Run)
	w.f("Command:   %s\n", g.Command)
	w.f("Gap:       %s\n", g.Gap)
	for _, a := range g.Attestations {
		writeGuideAttestation(w, a)
	}
	writeGuideTools(w, g.Tools)
	w.f("\n")
}

func writeGuideAttestation(w guideWriter, a guideAttestation) {
	always := ""
	if a.Always {
		always = "  recorded on every run"
	}
	w.f("\n  %s  (%s)%s\n", a.Name, a.Type, always)
	if a.Produce != "" {
		w.f("    the command must produce: %s\n", a.Produce)
	}
	w.f("    predicate fields: %s\n", strings.Join(a.Reads, "; "))
	w.f("    source: %s\n", a.Source)
	for _, r := range a.RulesDetail {
		w.f("    rule %s: %s\n", r.ID, r.Summary)
		if r.requiresParam() {
			w.f("      fill: %s, e.g. %s\n", r.Param, r.Example)
		}
		if r.Module == "" {
			continue
		}
		form := "seeded"
		if r.requiresParam() {
			form = "with the example value"
		}
		w.f("      rego (%s):\n", form)
		for _, line := range strings.Split(strings.TrimRight(r.Module, "\n"), "\n") {
			w.f("        %s\n", line)
		}
	}
}

func writeGuideTools(w guideWriter, tools []catalogTool) {
	if len(tools) == 0 {
		return
	}
	w.f("\n  Tools the detection catalog knows for this goal (suggestions; you choose):\n")
	for _, t := range tools {
		mark := ""
		if t.OnPath {
			mark = " [on PATH]"
		}
		argv := strings.Join(t.Argv, " | ")
		w.f("    %s%s: %s\n      argv: %s; captured by: %s", t.Name, mark, t.Description, argv, strings.Join(t.Captures, ", "))
		if t.ExitsNonzeroOnFindings {
			w.f("; exits non-zero on findings (pass --ignore-command-exit-code or a no-fail flag so the report is recorded)")
		}
		w.f("\n")
	}
}

// repositoryMarkers names the build files present at the top of the
// repository, so the model starts from what is there. It never chooses.
func repositoryMarkers(dir string) []string {
	markers := []string{"go.mod", "package.json", "pyproject.toml", "requirements.txt", "Cargo.toml", "pom.xml",
		"build.gradle", "build.gradle.kts", "CMakeLists.txt", "Makefile", "Dockerfile", ".golangci.yml", ".golangci.yaml",
		"tsconfig.json", "setup.py", "Gemfile", "composer.json", "global.json", "kustomization.yaml", "Chart.yaml", ".gitleaks.toml"}
	var found []string
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			found = append(found, m)
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.sln")); len(matches) > 0 {
		found = append(found, "*.sln")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.csproj")); len(matches) > 0 {
		found = append(found, "*.csproj")
	}
	return found
}

var guideTopics = map[string]func() string{
	"flow":                  func() string { return guideFlow },
	"rego":                  func() string { return guideTopicRego },
	"chain":                 func() string { return guideTopicChain },
	"trace":                 guideTopicTrace,
	guideTopicVEXName:       func() string { return guideTopicVEX },
	guideTopicAttestorsName: guideTopicAttestors,
	"rules":                 guideTopicRules,
}

func guideTopicNames() []string {
	names := make([]string, 0, len(guideTopics))
	for n := range guideTopics {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

const guideTopicRego = `Rules are RegoV0 modules with deny[msg] rules, base64 in regopolicies[].module.
Input is the attestor's predicate JSON (attestation/policy/rego.go EvaluateRegoPolicy). When a step has
attestationsFrom or externalFrom, EVERY attestation of that step instead sees {attestation, steps, external}
(rego.go buildRegoInput), so read the predicate as pred := object.get(input, "attestation", input); every
seeded rule does. Fail closed: a missing field is undefined, and an undefined comparison denies nothing, so
guard reads (is_number, is_array) and deny when they fail. Keep messages total: object.get(x, "field", "default")
for anything you interpolate. Builtin type errors abort evaluation (StrictBuiltinErrors), which refuses.
cilock policy validate lints fail-open negations and probes each attestation's rules against {}.`

const guideTopicChain = `Chain steps when a later step must use the bytes an earlier one made: build -> test -> package -> provenance.
The SDLC reason: the artifact you tested and ship is provably the one you built, not a rebuild.
  artifactsFrom: [<step>]   the verifier checks this step's MATERIALS against that step's products and materials,
                            path by path (attestation/policy/policy.go compareArtifacts): a digest that differs is
                            "mismatched digests for <path>", and no shared path at all is refused too. Record every
                            chained step with --material-manifest so the material inventory is retained.
  attestationsFrom: [<step>] this step's rules also read that step's predicates, as
                            input.steps.<step>.collections[].attestations["<predicate type>"]
                            (attestation/policy/step.go buildStepContext). Seeded cross-step rule: products-from
                            (--rule products-from=<step>): every product this step ships is, by digest, a product of
                            <step>, for a copy/sign/publish step.
Add a chained step: cilock policy template -p <draft> --add-step test-built --goal tests --artifacts-from app-build
Record producers first: a step's artifactsFrom and attestationsFrom read evidence its upstream already recorded.`

func guideTopicTrace() string {
	var b strings.Builder
	b.WriteString(`cilock run --trace records the process tree in command-run: processes[] with interned tables. Paths and digests
are indices: a process's executable is paths[p.execPathId], its image digest digests[p.exeDigestId].digests.sha256
(plugins/attestors/commandrun/v2_marshal.go:164-255). Per process: network.connections[] {syscall, family, address,
port, hostname (TLS SNI)}, network.dnsLookups[] {serverAddress, serverPort}, fileOps {writes[].path,
renames[].oldPath/newPath, deletes[].path, permChanges[].path}, openedFiles[]/writtenFiles[] {pathId, digestId}.
Require tracing where the build itself is the risk: a hermetic build (no network), supply-chain hygiene (only
known compilers ran, nothing read ~/.ssh or ~/.aws, nothing wrote into .git). Linux records exe digests; the macOS
sandbox backend records paths but not image digests, so allowlist by path there, and it can record a connect
whose host is not observable ("(host-not-observable)", port 0), which no allowlist entry admits.
--trace-file-content is macOS-only and adds bounded workspace text snapshots; no seeded rule needs it.
Rules that read these fields (trace-present, trace-network, trace-exec, trace-writes, trace-credential-reads) arrive
in a follow-up; a step they will read must already be recorded with cilock run --trace.`)
	return b.String()
}

const guideTopicVEX = `VEX is the right answer when a finding does not apply to what you ship: the vulnerable code is not
reachable (govulncheck: reachable=false, justification vulnerable_code_not_in_execute_path), the component is
not present, or a fix already landed (status fixed). It is a SIGNED JUDGMENT, not a fix: draft it with
  cilock attest vex --step vex --vuln <CVE-...|GHSA-...> --product <purl|sha256> --status not_affected \
    --justification vulnerable_code_not_in_execute_path --impact-statement "<why>"
and whoever the policy's vex step names signs it (the agent functionary, or a human approver's email).
cilock attest vex accepts CVE and GHSA ids only (plugins/attestors/vex/openvex/builder.go:59-60), while govulncheck
names findings by GO id; the seeded rule matches a finding by its GO id or by any alias in the scan's osv
records, so a CVE/GHSA statement covers it. not_affected without a justification is refused at authoring and at
ingestion (openvex/validate.go:220), and by the rule.
Rego input holds one attestation, so a rule cannot read a VEX document from the same step: put VEX in its own
step and read it through attestationsFrom (cilock policy template --goal vulns --with-vex does this):
  govulncheck-vex-covered: every govulncheck finding covered by a fixed, or not_affected+justification, statement
  sarif-vex-covered: the same for SARIF scanner results (osv-scanner, grype, trivy SARIF), by ruleId
Findings that are uncovered, affected or under_investigation are refused.`

func guideTopicAttestors() string {
	var b strings.Builder
	b.WriteString("Attestors with guidance (predicate fields a rule reads; seeded rules where cilock has one).\nFor any other attestor, `cilock attestors schema <name>` prints its predicate shape.\n")
	types := make([]string, 0, len(catalogAttestors))
	for t := range catalogAttestors {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		a := catalogAttestors[t]
		fmt.Fprintf(&b, "  %s (%s)\n    fields: %s\n", a.Name, t, strings.Join(a.Reads, "; "))
		if len(a.Rules) > 0 {
			fmt.Fprintf(&b, "    seeded rules: %s\n", strings.Join(a.Rules, ", "))
		} else {
			b.WriteString("    no seeded rule: write one against the fields above\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func guideTopicRules() string {
	var b strings.Builder
	b.WriteString("Seeded rules (regopolicies name = rule id). Add one with --rule <id>[=<json>], fill a slot with --fill <step>.<id>=<json>:\n")
	for _, id := range sortedRuleIDs() {
		r := ruleTemplates[id]
		fmt.Fprintf(&b, "  %s on %s: %s", id, r.Type, r.Summary)
		if r.requiresParam() {
			fmt.Fprintf(&b, "\n    fill: %s, e.g. %s", r.Param, r.Example)
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
