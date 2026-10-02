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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const defaultDraftPath = ".pushgate/policy.json"

type templateOptions struct {
	goals            []string
	attestors        []string
	rules            []string
	fills            []string
	artifactsFrom    []string
	attestationsFrom []string
	addStep          string
	policyPath       string
	output           string
	sbomFormat       string
	platformURL      string
	traced           bool
	withVEX          bool
	force            bool
	now              func() time.Time
}

// PolicyTemplateCmd is `cilock policy template`: it writes the parts of a
// Pushgate draft agents get wrong, and marks the parts that are the model's
// judgment as fill slots. It never signs, publishes or activates anything.
func PolicyTemplateCmd() *cobra.Command {
	o := templateOptions{}
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Scaffold a Pushgate policy draft: trust blocks, steps and seeded rules, with slots for your judgment",
		Long: `template writes a Pushgate policy draft skeleton you then fill and prove.

cilock writes what agents get wrong: the agent functionary copied from your
enrolled identity (tenant-pinned SPIFFE URI, roots ["fulcio-root"], explicit
"*" for the other constraints), the empty platform trust placeholders, an
expiry one year out, one step per goal named by the goal id, each goal's
attestation types, and each attestation's seeded fail-closed Rego.

You write what only you can judge for THIS repository. Every such place is a
string starting with __FILL__ (a pinned command, an allowlist, a threshold).
Fill a rule slot with --fill <step>.<rule>=<json>; edit any other slot, and
any rule, by hand. Steps you add or write by hand are proved exactly like
templated ones.

Three forms:
  create    --goal <id>... [-o .pushgate/policy.json] [--force]
  add step  -p <draft> --add-step <name> (--goal <id> | --attestor <name|type>...)
            [--artifacts-from <step>]... [--attestations-from <step>]...
  fill      -p <draft> --fill <step>.<rule>=<json>...

The template never overwrites an existing file without --force, never touches
a step it did not add, and never replaces a rule that is not an unfilled slot.
Run 'cilock policy guide' for what each goal, attestor and rule means, and
'cilock policy validate -p <draft>' to check the filled draft.`,
		Example: `  # Start from the goals your human picked
  cilock policy template --goal tests --goal secrets --goal quality

  # Pin the test command: the argv 'cilock run --step tests -- <argv>' records, as JSON:
  #   cilock policy template -p .pushgate/policy.json --fill tests.command-pin='["gotestsum","--junitfile","junit.xml","./..."]'

  # Add a custom check the goals do not name
  cilock policy template -p .pushgate/policy.json --add-step docs-build --attestor command-run

  # Chain: a test step whose materials must be the build step's products
  cilock policy template -p .pushgate/policy.json --add-step test-built --goal tests --artifacts-from app-build

  # Traced build with network, exec, write and credential-read rules to fill
  cilock policy template --goal app-build --traced`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPolicyTemplate(cmd.OutOrStdout(), o)
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&o.goals, "goal", nil, "Goal id to scaffold (repeat); one step per goal, named by the id. Ids: "+strings.Join(goalIDs(), ", "))
	f.StringArrayVar(&o.attestors, "attestor", nil, "With --add-step: an attestor name or predicate type the step requires (repeat); its seeded rules come with it")
	f.StringArrayVar(&o.rules, "rule", nil, "Add a seeded rule to each new step: <rule>[=<json value>] (repeat); see 'cilock policy guide --topic rules'")
	f.StringArrayVar(&o.fills, "fill", nil, "Fill a rule slot: <step>.<rule>=<json value> (repeat)")
	f.StringArrayVar(&o.artifactsFrom, "artifacts-from", nil, "With --add-step: a step whose products this step's materials must match (repeat)")
	f.StringArrayVar(&o.attestationsFrom, "attestations-from", nil, "With --add-step: a step whose predicates this step's rules read as input.steps.<step> (repeat)")
	f.StringVar(&o.addStep, "add-step", "", "Append a step with this name to the draft named by -p")
	f.StringVarP(&o.policyPath, "policy", "p", "", "Existing draft to add a step to or fill (rewritten in place)")
	f.StringVarP(&o.output, "output", "o", defaultDraftPath, "Write a new draft to this file")
	f.StringVar(&o.sbomFormat, "sbom-format", "", "For the sbom goal: cyclonedx or spdx (the step's type must match the SBOM the command writes)")
	f.StringVar(&o.platformURL, "platform-url", "", "Platform whose enrolled agent the functionary names (default: the cilock default platform)")
	f.BoolVar(&o.traced, "traced", false, "Add the tracing rules (trace-present, trace-network, trace-exec, trace-writes, trace-credential-reads) to each new step")
	f.BoolVar(&o.withVEX, "with-vex", false, "For the vulns goal: add a vex step and require its OpenVEX statements to cover every finding")
	f.BoolVar(&o.force, "force", false, "Overwrite an existing file when creating a draft")
	return cmd
}

var stepNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func runPolicyTemplate(out io.Writer, o templateOptions) error {
	if o.now == nil {
		o.now = time.Now
	}
	switch {
	case o.addStep != "":
		return templateAddStep(out, o)
	case len(o.goals) == 0 && len(o.fills) > 0:
		return templateFillOnly(out, o)
	case len(o.goals) > 0:
		return templateCreate(out, o)
	default:
		return errors.New("nothing to template. Next: `cilock policy template --goal <id>` (ids: " + strings.Join(goalIDs(), ", ") + "), or `cilock policy guide` to choose")
	}
}

func templateCreate(out io.Writer, o templateOptions) error {
	if o.policyPath != "" {
		return fmt.Errorf("-p names an existing draft; to add a goal to it use `cilock policy template -p %s --add-step <name> --goal <id>`", o.policyPath)
	}
	if len(o.attestors) > 0 || len(o.artifactsFrom) > 0 || len(o.attestationsFrom) > 0 {
		return errors.New("--attestor, --artifacts-from and --attestations-from shape one added step. Next: create the draft with --goal, then `cilock policy template -p <draft> --add-step <name> ...`")
	}
	if _, err := os.Stat(o.output); err == nil && !o.force {
		return fmt.Errorf("%s already exists and template never overwrites a draft. Next: add to it with `cilock policy template -p %s --add-step <name> --goal <id>`, or pass --force to replace it", o.output, o.output)
	}
	id, err := lookupEnrolledIdentity(o.platformURL)
	if err != nil {
		return err
	}
	roots, tsas := platformTrustPlaceholders()
	doc := draftDoc{
		"expires":              oneYearFromToday(o.now()),
		"roots":                roots,
		"timestampauthorities": tsas,
		"steps":                map[string]any{},
	}
	var added []string
	for _, g := range o.goals {
		names, err := addGoalSteps(doc, id, g, g, o)
		if err != nil {
			return err
		}
		added = append(added, names...)
	}
	if err := applyFills(doc, o.fills); err != nil {
		return err
	}
	// Exclusive unless --force: the existence check above gives the message,
	// the filesystem gives the guarantee.
	if err := saveDraft(o.output, doc, !o.force); err != nil {
		return err
	}
	return reportTemplate(out, o.output, doc, id, added, "Wrote")
}

func templateAddStep(out io.Writer, o templateOptions) error {
	if o.policyPath == "" {
		return addStepWithoutDraftError(o)
	}
	if len(o.goals) > 1 {
		return errors.New("--add-step adds one step: pass at most one --goal (and any number of --attestor)")
	}
	if len(o.goals) == 0 && len(o.attestors) == 0 && len(o.rules) == 0 && !o.traced {
		return fmt.Errorf("say what step %s requires. Next: add --goal <id> or --attestor <name> (e.g. --attestor command-run for a custom script)", o.addStep)
	}
	doc, err := loadDraft(o.policyPath)
	if err != nil {
		return fmt.Errorf("%w. Next: create a draft first with `cilock policy template --goal <id> -o %s`", err, o.policyPath)
	}
	if draftSteps(doc) == nil {
		doc["steps"] = map[string]any{}
	}
	id, err := lookupEnrolledIdentity(o.platformURL)
	if err != nil {
		return err
	}
	goal := ""
	if len(o.goals) == 1 {
		goal = o.goals[0]
	}
	added, err := addGoalSteps(doc, id, o.addStep, goal, o)
	if err != nil {
		return err
	}
	if err := applyFills(doc, o.fills); err != nil {
		return err
	}
	if err := saveDraft(o.policyPath, doc, false); err != nil {
		return err
	}
	return reportTemplate(out, o.policyPath, doc, id, added, "Added to")
}

// addStepWithoutDraftError answers `--add-step` with no -p. The usual cause
// is an author starting a new draft with -o and one custom step; a new draft
// starts from --goal, so the fix is two commands, spelled with the author's
// own path and flags (shell-quoted: they are meant to be pasted).
func addStepWithoutDraftError(o templateOptions) error {
	draft := o.output
	if draft == "" {
		draft = defaultDraftPath
	}
	add := []string{"cilock policy template -p", shellQuote(draft), "--add-step", shellWord(o.addStep)}
	for _, g := range o.goals {
		add = append(add, "--goal", shellWord(g))
	}
	for _, a := range o.attestors {
		add = append(add, "--attestor", shellWord(a))
	}
	for _, r := range o.rules {
		add = append(add, "--rule", shellWord(r))
	}
	for _, s := range o.artifactsFrom {
		add = append(add, "--artifacts-from", shellWord(s))
	}
	for _, s := range o.attestationsFrom {
		add = append(add, "--attestations-from", shellWord(s))
	}
	if o.traced {
		add = append(add, "--traced")
	}
	for _, f := range o.fills {
		add = append(add, "--fill", shellWord(f))
	}
	addCmd := "`" + strings.Join(add, " ") + "`"
	if _, err := os.Stat(draft); err == nil {
		return fmt.Errorf("--add-step appends a step to an existing draft named by -p; -o only names a new draft. Next: %s", addCmd)
	}
	return fmt.Errorf("--add-step appends a step to an existing draft named by -p; -o only names a new draft, and a new draft starts from --goal. "+
		"Next: `cilock policy template --goal <id> -o %s` (ids: %s), then %s",
		shellQuote(draft), strings.Join(goalIDs(), ", "), addCmd)
}

// shellWord leaves a word a shell would not act on bare and quotes the rest.
func shellWord(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@,+", r))
	}) < 0 {
		return s
	}
	return shellQuote(s)
}

func templateFillOnly(out io.Writer, o templateOptions) error {
	if o.policyPath == "" {
		return fmt.Errorf("--fill edits an existing draft. Next: pass it with -p, e.g. `cilock policy template -p %s --fill <step>.<rule>=<json>`", defaultDraftPath)
	}
	doc, err := loadDraft(o.policyPath)
	if err != nil {
		return err
	}
	if err := applyFills(doc, o.fills); err != nil {
		return err
	}
	if err := saveDraft(o.policyPath, doc, false); err != nil {
		return err
	}
	return reportTemplate(out, o.policyPath, doc, enrolledIdentity{}, nil, "Filled")
}

// addGoalSteps adds the step(s) for one goal (or, with goal "", a step built
// from --attestor/--rule) under stepName, and returns the names it added.
func addGoalSteps(doc draftDoc, id enrolledIdentity, stepName, goalID string, o templateOptions) ([]string, error) {
	steps := draftSteps(doc)
	if err := checkNewStep(doc, steps, stepName, o); err != nil {
		return nil, err
	}
	if goalID == goalIDVulns && o.withVEX && stepName == attestorNameVEX {
		return nil, fmt.Errorf("--with-vex adds a step named %s for the VEX document, so the scan step cannot use that name. Next: --add-step vulns (or another name)", attestorNameVEX)
	}
	p := &stepPlan{
		attestationsFrom: append([]string{}, o.attestationsFrom...),
		rulesByType:      map[string][]string{},
		ruleValues:       map[string]json.RawMessage{},
	}
	if goalID != "" {
		if err := p.addGoal(steps, id, goalID, o); err != nil {
			return nil, err
		}
	} else if o.withVEX {
		return nil, errors.New("--with-vex belongs to the vulns goal: pass --goal vulns")
	}
	if err := p.addAttestors(o.attestors); err != nil {
		return nil, err
	}
	if o.traced {
		for _, r := range traceRuleIDs {
			p.addRule(typeCommandRun, r)
		}
	}
	if err := p.addRuleSpecs(steps, o.rules); err != nil {
		return nil, err
	}
	atts, err := p.attestations(stepName, goalID, o.sbomFormat)
	if err != nil {
		return nil, err
	}
	step := map[string]any{
		draftKeyName:    stepName,
		"functionaries": []any{agentFunctionary(id.trustDomain, id.tenantID)},
		"attestations":  atts,
	}
	if len(o.artifactsFrom) > 0 {
		step["artifactsFrom"] = toAnyList(o.artifactsFrom)
	}
	if len(p.attestationsFrom) > 0 {
		step["attestationsFrom"] = toAnyList(p.attestationsFrom)
	}
	steps[stepName] = step
	return append(p.added, stepName), nil
}

// checkNewStep refuses a step name the draft cannot take, and edges to steps
// it does not have.
func checkNewStep(doc draftDoc, steps map[string]any, stepName string, o templateOptions) error {
	if !stepNameRE.MatchString(stepName) {
		return fmt.Errorf("step name %q: use letters, digits, '.', '_' and '-' (it is the --step you pass to cilock run)", stepName)
	}
	if _, dup := steps[stepName]; dup {
		return fmt.Errorf("the draft already has a step named %s; step names are unique and equal the --step cilock run records. Next: choose another name with --add-step <name>", stepName)
	}
	for _, e := range append(append([]string{}, o.artifactsFrom...), o.attestationsFrom...) {
		if e == stepName {
			return fmt.Errorf("step %s cannot read itself through artifactsFrom/attestationsFrom", stepName)
		}
		if _, ok := steps[e]; !ok {
			return fmt.Errorf("step %s would read step %s, which the draft does not have (steps: %s). Next: add %s first, or fix the name", stepName, e, strings.Join(sortedStepNames(doc), ", "), e)
		}
	}
	return nil
}

// stepPlan collects what one new step requires: its attestation types in
// order, the rules per type, the values given for rules, the attestationsFrom
// edges, and any helper step (the vex step) added alongside it.
type stepPlan struct {
	types            []string
	rulesByType      map[string][]string
	ruleValues       map[string]json.RawMessage
	attestationsFrom []string
	added            []string
}

func (p *stepPlan) addType(t string) {
	for _, x := range p.types {
		if x == t {
			return
		}
	}
	p.types = append(p.types, t)
}

func (p *stepPlan) addRule(t, rule string) {
	p.addType(t)
	for _, r := range p.rulesByType[t] {
		if r == rule {
			return
		}
	}
	p.rulesByType[t] = append(p.rulesByType[t], rule)
}

// addGoal adds a goal's attestors and seeded rules. For vulns with --with-vex
// it also adds the vex step the govulncheck VEX rule reads.
func (p *stepPlan) addGoal(steps map[string]any, id enrolledIdentity, goalID string, o templateOptions) error {
	g, ok := goalByID(goalID)
	if !ok {
		return fmt.Errorf("unknown goal %q. Next: pick one of %s (`cilock policy guide` explains each)", goalID, strings.Join(goalIDs(), ", "))
	}
	withVEX := goalID == goalIDVulns && o.withVEX
	for _, t := range g.Attestors {
		p.addType(t)
	}
	for _, r := range g.Rules {
		if withVEX && r == ruleGovulncheckReachable {
			continue
		}
		p.addRule(ruleTemplates[r].Type, r)
	}
	if goalID == attestorNameSBOM {
		switch o.sbomFormat {
		case "", "cyclonedx", "spdx":
		default:
			return fmt.Errorf("--sbom-format %q: want cyclonedx or spdx", o.sbomFormat)
		}
	}
	if !withVEX {
		return nil
	}
	vexStep := attestorNameVEX
	if _, exists := steps[vexStep]; !exists {
		steps[vexStep] = map[string]any{
			draftKeyName:    vexStep,
			"functionaries": []any{agentFunctionary(id.trustDomain, id.tenantID)},
			"attestations":  []any{map[string]any{draftKeyType: typeVEX}},
		}
		p.added = append(p.added, vexStep)
	}
	p.attestationsFrom = appendUnique(p.attestationsFrom, vexStep)
	p.addRule(typeGovulncheck, ruleGovulncheckVEX)
	return nil
}

func (p *stepPlan) addAttestors(names []string) error {
	for _, a := range names {
		att, ok := attestorByName(a)
		if !ok {
			return templateUnknownAttestorError(a)
		}
		p.addType(att.Type)
		for _, r := range att.Rules {
			if r == ruleGovulncheckVEX {
				continue
			}
			p.addRule(att.Type, r)
		}
	}
	return nil
}

// addRuleSpecs adds each --rule <id>[=<value>]. products-from also reads the
// named upstream step through attestationsFrom.
func (p *stepPlan) addRuleSpecs(steps map[string]any, specs []string) error {
	given := map[string]bool{}
	for _, spec := range specs {
		ruleID, value, _ := strings.Cut(spec, "=")
		r, ok := ruleTemplates[ruleID]
		if !ok {
			return fmt.Errorf("unknown rule %q (known: %s)", ruleID, strings.Join(sortedRuleIDs(), ", "))
		}
		// A step carries one instance of each rule, so a second value would
		// silently replace the first.
		if given[ruleID] {
			return fmt.Errorf("--rule %s is given twice; a step carries each rule once, and a second value would replace the first. Next: pass it once", ruleID)
		}
		given[ruleID] = true
		if value != "" {
			p.ruleValues[ruleID] = jsonValue(value)
		}
		if ruleID == ruleProductsFrom {
			if err := p.readProductsFrom(steps); err != nil {
				return err
			}
		}
		p.addRule(p.ruleTarget(r), ruleID)
	}
	return nil
}

// readProductsFrom reads the upstream step products-from names and reads it
// through attestationsFrom.
func (p *stepPlan) readProductsFrom(steps map[string]any) error {
	var up string
	if err := json.Unmarshal(p.ruleValues[ruleProductsFrom], &up); err != nil || up == "" {
		return errors.New("--rule products-from=<upstream step> names the step whose products this one ships")
	}
	if _, ok := steps[up]; !ok {
		return fmt.Errorf("--rule products-from=%s: the draft has no step %s", up, up)
	}
	p.attestationsFrom = appendUnique(p.attestationsFrom, up)
	return nil
}

// ruleTarget is the attestation type a --rule attaches to: one already
// selected that carries the rule (SPDX for sbom-inventory), else the rule's
// canonical type, so a step that selected one format is not made to require
// a second.
func (p *stepPlan) ruleTarget(r ruleTemplate) string {
	for _, t := range p.types {
		if att, ok := attestorByName(t); ok && containsString(att.Rules, r.ID) {
			return t
		}
	}
	return r.Type
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// attestations renders the step's attestations list: one entry per type with
// its regopolicies. The sbom goal's type is the chosen SBOM format, or a slot.
func (p *stepPlan) attestations(stepName, goalID, sbomFormat string) ([]any, error) {
	var atts []any
	for _, t := range p.types {
		stepType := t
		if t == typeCycloneDX && goalID == attestorNameSBOM {
			switch sbomFormat {
			case "spdx":
				stepType = typeSPDX
			case "":
				stepType = fillSlot("sbom-format", fmt.Sprintf("%s for CycloneDX JSON or %s for SPDX JSON; it must match the SBOM your command writes (or re-create the step with --sbom-format)", typeCycloneDX, typeSPDX))
			}
		}
		att := map[string]any{draftKeyType: stepType}
		var regos []any
		for _, ruleID := range p.rulesByType[t] {
			entry, err := ruleEntry(stepName, ruleID, p.ruleValues[ruleID])
			if err != nil {
				return nil, err
			}
			regos = append(regos, entry)
		}
		if len(regos) > 0 {
			att["regopolicies"] = regos
		}
		atts = append(atts, att)
	}
	if len(atts) == 0 {
		return nil, fmt.Errorf("step %s would require no attestation. Next: add --attestor <name>", stepName)
	}
	return atts, nil
}

// ruleEntry renders one regopolicies entry: the module when the rule needs
// nothing (or its value was given), otherwise a fill slot naming the rule.
func ruleEntry(stepName, ruleID string, value json.RawMessage) (map[string]any, error) {
	r := ruleTemplates[ruleID]
	name := ruleID
	if ruleID == ruleProductsFrom && len(value) > 0 {
		var up string
		_ = json.Unmarshal(value, &up)
		name = ruleProductsFrom + "-" + up
	}
	if r.requiresParam() && len(value) == 0 {
		return map[string]any{
			draftKeyName: name,
			"module": fillSlot(ruleID, fmt.Sprintf("%s; e.g. cilock policy template -p <draft> --fill %s.%s=%s",
				r.Param, stepName, name, shellQuote(r.Example))),
		}, nil
	}
	src, err := renderRule(ruleID, value)
	if err != nil {
		return nil, err
	}
	return map[string]any{draftKeyName: name, "module": base64.StdEncoding.EncodeToString([]byte(src))}, nil
}

// slotRuleRE reads the rule id a rule slot names: "__FILL__ <rule-id>: ...".
var slotRuleRE = regexp.MustCompile(`^` + fillMarker + ` ([a-z0-9-]+):`)

// applyFills renders each --fill into the slot it names. It refuses to
// replace anything that is not an unfilled rule slot.
func applyFills(doc draftDoc, fills []string) error {
	steps := draftSteps(doc)
	for _, spec := range fills {
		target, value, ok := strings.Cut(spec, "=")
		if !ok || !strings.Contains(target, ".") || value == "" {
			return fmt.Errorf("--fill %q: want <step>.<rule>=<json value>, e.g. tests.command-pin='[\"go\",\"test\",\"./...\"]'", spec)
		}
		stepName, ruleName, entry, err := resolveFillTarget(doc, steps, target)
		if err != nil {
			return err
		}
		mod, _ := entry["module"].(string)
		m := slotRuleRE.FindStringSubmatch(mod)
		if m == nil {
			return filledRuleError(target, stepName, ruleName, asMap(steps[stepName]))
		}
		src, err := renderRule(m[1], jsonValue(value))
		if err != nil {
			return fmt.Errorf("--fill %s: %w", target, err)
		}
		entry["module"] = base64.StdEncoding.EncodeToString([]byte(src))
	}
	return nil
}

// resolveFillTarget splits "<step>.<rule>" against the draft itself. Step
// names may contain dots (tests.unit) and so may rule names
// (products-from-tests.unit), so no fixed split point is right: every step
// whose name prefixes the target is tried, and the target must name exactly
// one existing rule.
func resolveFillTarget(doc draftDoc, steps map[string]any, target string) (string, string, map[string]any, error) {
	type match struct {
		step, rule string
		entry      map[string]any
	}
	var matches []match
	var stepsOnly []string
	for _, name := range sortedStepNames(doc) {
		rule, ok := strings.CutPrefix(target, name+".")
		if !ok || rule == "" {
			continue
		}
		stepsOnly = append(stepsOnly, name)
		if e := findRegoEntry(asMap(steps[name]), rule); e != nil {
			matches = append(matches, match{name, rule, e})
		}
	}
	switch {
	case len(matches) == 1:
		return matches[0].step, matches[0].rule, matches[0].entry, nil
	case len(matches) > 1:
		alts := make([]string, 0, len(matches))
		for _, m := range matches {
			alts = append(alts, fmt.Sprintf("step %s rule %s", m.step, m.rule))
		}
		return "", "", nil, fmt.Errorf("--fill %s is ambiguous: it names %s. Rename one step with --add-step so the target is unique", target, strings.Join(alts, " and "))
	case len(stepsOnly) > 0:
		step := stepsOnly[len(stepsOnly)-1]
		return "", "", nil, fmt.Errorf("--fill %s: step %s has no rule named %s (its rules: %s). Next: add it with --rule",
			target, step, strings.TrimPrefix(target, step+"."), strings.Join(regoEntryNames(asMap(steps[step])), ", "))
	default:
		return "", "", nil, fmt.Errorf("--fill %s: no step of the draft prefixes it (steps: %s)", target, strings.Join(sortedStepNames(doc), ", "))
	}
}

func regoEntryNames(step map[string]any) []string {
	var names []string
	for _, a := range asList(step["attestations"]) {
		for _, r := range asList(asMap(a)["regopolicies"]) {
			if n, ok := asMap(r)[draftKeyName].(string); ok {
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	return names
}

// filledRuleError refuses a --fill on a rule that already holds a value. It
// names the module's JSON path so the author can edit it, and for a pinned
// command shows what it pins, which is usually why the author wanted it.
func filledRuleError(target, stepName, ruleName string, step map[string]any) error {
	msg := fmt.Sprintf("--fill %s: rule %s is not an unfilled slot: it already holds a value, and template never overwrites a rule", target, ruleName)
	if ruleName == ruleCommandPin {
		if argv, ok := pinnedArgv(step); ok {
			if b, err := json.Marshal(argv); err == nil {
				msg += "; it pins " + string(b)
			}
		}
	}
	if path := regoEntryPath(stepName, step, ruleName); path != "" {
		msg += fmt.Sprintf(". Next: if it must change, edit %s.module by hand (base64 of the rego module), then run `cilock policy validate -p <draft>`", path)
	} else {
		msg += ". Next: if it must change, edit that rule's module by hand, then run `cilock policy validate -p <draft>`"
	}
	return errors.New(msg)
}

// regoEntryPath is the JSON path of the named rule in a step, in the form the
// validator prints (steps.<step>.attestations[i].regopolicies[j]).
func regoEntryPath(stepName string, step map[string]any, name string) string {
	for i, a := range asList(step["attestations"]) {
		for j, r := range asList(asMap(a)["regopolicies"]) {
			if e := asMap(r); e != nil && e["name"] == name {
				return fmt.Sprintf("steps.%s.attestations[%d].regopolicies[%d]", stepName, i, j)
			}
		}
	}
	return ""
}

func findRegoEntry(step map[string]any, name string) map[string]any {
	for _, a := range asList(step["attestations"]) {
		for _, r := range asList(asMap(a)["regopolicies"]) {
			if e := asMap(r); e != nil && e[draftKeyName] == name {
				return e
			}
		}
	}
	return nil
}

// jsonValue accepts a JSON value, or a bare word that is taken as a string.
func jsonValue(s string) json.RawMessage {
	if json.Valid([]byte(s)) {
		return json.RawMessage(s)
	}
	b, _ := json.Marshal(s)
	return b
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func toAnyList(list []string) []any {
	out := make([]any, 0, len(list))
	for _, s := range list {
		out = append(out, s)
	}
	return out
}

func reportTemplate(out io.Writer, path string, doc draftDoc, id enrolledIdentity, added []string, verb string) error {
	if len(added) > 0 {
		sort.Strings(added)
		_, _ = fmt.Fprintf(out, "%s %s: step(s) %s\n", verb, path, strings.Join(added, ", "))
	} else {
		_, _ = fmt.Fprintf(out, "%s %s\n", verb, path)
	}
	if id.trustDomain != "" {
		_, _ = fmt.Fprintf(out, "  functionary: spiffe://%s/tenant/%s/agent/* (roots: fulcio-root); platform trust placeholders: fulcio-root, platform-tsa; expires %v\n",
			id.trustDomain, id.tenantID, doc["expires"])
		if id.expired {
			_, _ = fmt.Fprintln(out, "  note: the enrolled agent has expired; `cilock enroll agent` again before you record evidence")
		}
	}
	slots := findFillSlots(doc)
	if len(slots) > 0 {
		_, _ = fmt.Fprintf(out, "%d slot(s) to fill before proving (your judgment for this repository):\n", len(slots))
		for _, s := range slots {
			_, _ = fmt.Fprintf(out, "  %s\n", s)
		}
	} else {
		_, _ = fmt.Fprintln(out, "No slots left to fill.")
	}
	_, _ = fmt.Fprintf(out, "Next: cilock policy validate -p %s, then record each step with the cilock run line cilock policy guide --goal <id> prints\n", path)
	return nil
}
