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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/config"
	internalpolicy "github.com/aflock-ai/rookery/cilock/internal/policy"
	"github.com/spf13/cobra"
)

type proveOptions struct {
	policyPath  string
	output      string
	workdir     string
	platformURL string
	runs        []string
	runArgs     []string
	step        string
	stepArgv    []string
	trace       bool
	noNormalize bool
}

// proveSelfExecutable is the cilock binary prove runs `cilock run` with. A
// separate process per run, as the agent would type it: the run's output and
// its process-wide state stay out of prove's report. A package variable so a
// test binary can stand in for cilock.
var proveSelfExecutable = os.Executable

// PolicyProveCmd is `cilock policy prove`: the local verify loop an agent used
// to run by hand, run mechanically against the agent's own draft.
func PolicyProveCmd() *cobra.Command {
	o := proveOptions{}
	cmd := &cobra.Command{
		Use:   "prove -p <draft.json> [--run <step>=<argv>]... [--step <name> -- <argv>]",
		Short: "Prove a policy draft locally: real evidence must pass, a failing run must be refused",
		Long: `prove runs the local verify loop against YOUR draft, offline, and never
rewrites your steps or rules.

  1. Refuses a draft that still holds a __FILL__ slot, and names each one.
  2. Normalizes the Pushgate blocks (unless --no-normalize): a step with no
     functionary, or only publickey ones, gets the enrolled agent functionary;
     roots and timestampauthorities become the empty platform placeholders;
     a missing expires becomes one year out. It says what it changed.
  3. Makes a throwaway ed25519 key in a temp dir outside the checkout, and
     records every step for real, producers before the steps that read them
     (artifactsFrom, attestationsFrom), with --material-manifest; a step
     whose command-run rules read processes[] is recorded with --trace.
  4. Records each step that requires command-run again wrapping 'false'.
  5. Signs a scratch copy whose functionaries name the throwaway key, and
     verifies: the real evidence must pass; each failing run must be refused
     by its own step, or the step "admits a failing run: add a rule".
  6. Validates the draft as 'cilock policy validate' does: the empty platform
     placeholders pass as an unsigned draft, because the platform fills them.
  7. Deletes the key, the evidence and the scratch policy.

The first line of the report is exactly 'Local verify: passed' or
'Local verify: REFUSED by <step>: <rule message>'. prove exits non-zero on
any refusal or problem and still writes the normalized draft, so your human
can choose. A step's command is --run <step>=<argv>, or --step <name> -- <argv>,
or the argv its command-pin rule pins. prove never signs the real policy,
uploads anything, or activates.`,
		Example: `  # Every step pins its command, so prove reads them from the draft
  cilock policy prove -p .pushgate/policy.json

  # Name a command explicitly (JSON array or plain words; no shell parsing), and pass an attestor flag:
  #   cilock policy prove -p .pushgate/policy.json --run tests='["gotestsum","--junitfile","junit.xml","./..."]'
  cilock policy prove -p .pushgate/policy.json --run-arg=--attestor-secretscan-scope=diff:origin/main

  # One step, argv after --
  cilock policy prove -p .pushgate/policy.json --step app-build -- go build -o bin/app ./cmd/app`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dash := cmd.ArgsLenAtDash(); dash >= 0 {
				if dash > 0 {
					return fmt.Errorf("unexpected argument %q before --", args[0])
				}
				o.stepArgv = args
			} else if len(args) > 0 {
				return fmt.Errorf("unexpected argument %q: put a step's command after --step <name> --, or use --run <step>=<argv>", args[0])
			}
			if len(o.stepArgv) > 0 && o.step == "" {
				return errors.New("a command after -- needs --step <name>")
			}
			if o.step != "" && len(o.stepArgv) == 0 {
				return fmt.Errorf("--step %s needs its command after --, e.g. cilock policy prove -p %s --step %s -- <argv>", o.step, o.policyPath, o.step)
			}
			return runPolicyProve(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), o)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.policyPath, "policy", "p", defaultDraftPath, "The policy draft to prove")
	f.StringVarP(&o.output, "output", "o", "", "Write the normalized draft here (default: back to -p)")
	f.StringVarP(&o.workdir, "workingdir", "d", "", "Directory each step's command runs in (default: the current directory)")
	f.StringVar(&o.platformURL, "platform-url", "", "Platform whose enrolled agent the functionary names (default: the cilock default platform)")
	f.StringArrayVar(&o.runs, "run", nil, "A step's command: <step>=<argv> (repeat); argv is a JSON array or plain words")
	f.StringArrayVar(&o.runArgs, "run-arg", nil, "Extra flag for every 'cilock run' prove makes, e.g. --run-arg=--attestor-secretscan-scope=diff:origin/main (repeat)")
	f.StringVar(&o.step, "step", "", "Name the step whose command follows --")
	f.BoolVar(&o.trace, "trace", false, "Record every step with --trace")
	f.BoolVar(&o.noNormalize, "no-normalize", false, "Do not fill the functionary or trust placeholders; prove and validate the draft as written")
	return cmd
}

// proveReport accumulates what prove found, in the order it is printed.
type proveReport struct {
	firstLine string
	steps     []string
	problems  []string
	notes     []string
}

func (r *proveReport) problem(format string, args ...any) {
	r.problems = append(r.problems, fmt.Sprintf(format, args...))
}

func (r *proveReport) note(format string, args ...any) {
	r.notes = append(r.notes, fmt.Sprintf(format, args...))
}

// proveFlagOffline keeps every run, sign and verify prove makes off the
// platform: nothing is uploaded, signed for real or activated.

func runPolicyProve(ctx context.Context, stdout, stderr io.Writer, o proveOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	doc, err := loadProveDraft(o)
	if err != nil {
		return err
	}
	report := &proveReport{}
	plan, err := planProve(doc, o, report)
	if err != nil {
		return err
	}
	p, keyID, pubPEM, err := newProver(ctx, stderr, o)
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(p.scratch) }()
	for _, name := range plan.order {
		p.edges[name] = stringList(asMap(draftSteps(doc)[name])["artifactsFrom"])
	}
	p.recordRealRuns(doc, plan, o.trace, report)

	if p.signed, err = p.signScratch(doc, keyID, pubPEM); err != nil {
		return err
	}

	refusal, goodRefused := p.verifyRealRuns(plan)
	if refusal == "" {
		report.firstLine = "Local verify: passed"
	} else {
		report.firstLine = "Local verify: REFUSED by " + refusal
	}
	for _, name := range plan.order {
		p.checkFailingRun(doc, plan, name, goodRefused[name], report)
	}

	validateDraft(ctx, doc, report)

	target, err := writeProvedDraft(doc, o, plan.changed, report)
	if err != nil {
		return err
	}
	report.note("the throwaway key, evidence and scratch-signed policy were deleted; nothing was uploaded, signed for real, or activated")

	writeProveReport(stdout, report, target, o.platformURL)
	if refusal != "" || len(report.problems) > 0 {
		return fmt.Errorf("the draft is not proved: %s. The draft was still written, so your human can choose", proveFailureSummary(refusal, report))
	}
	return nil
}

// newProver resolves the checkout and this cilock binary, and makes the
// scratch directory with a throwaway key. The caller removes p.scratch.
func newProver(ctx context.Context, stderr io.Writer, o proveOptions) (*prover, string, []byte, error) {
	workdir, err := proveWorkdir(o)
	if err != nil {
		return nil, "", nil, err
	}
	self, err := proveSelfExecutable()
	if err != nil {
		return nil, "", nil, fmt.Errorf("locate the cilock binary to record evidence with: %w", err)
	}
	scratch, err := os.MkdirTemp("", "cilock-prove-")
	if err != nil {
		return nil, "", nil, err
	}
	if inside(workdir, scratch) {
		_ = os.RemoveAll(scratch)
		return nil, "", nil, fmt.Errorf("the temp dir %s is inside the checkout %s; scratch keys and evidence must stay outside it. Next: set TMPDIR to a directory outside the repository", scratch, workdir)
	}
	keyPath, pubPath, keyID, pubPEM, err := writeScratchKey(scratch)
	if err != nil {
		_ = os.RemoveAll(scratch)
		return nil, "", nil, err
	}
	p := &prover{ctx: ctx, self: self, workdir: workdir, scratch: scratch, keyPath: keyPath, pubPath: pubPath,
		stderr: stderr, runArgs: o.runArgs, edges: map[string][]string{}}
	return p, keyID, pubPEM, nil
}

// loadProveDraft reads the draft and refuses one prove cannot run yet: an
// unfilled slot anywhere, or no steps at all.
func loadProveDraft(o proveOptions) (draftDoc, error) {
	doc, err := loadDraft(o.policyPath)
	if err != nil {
		return nil, fmt.Errorf("%w. Next: scaffold one with `cilock policy template --goal <id>`", err)
	}
	if slots := findFillSlots(doc); len(slots) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%s still has %d unfilled slot(s); prove runs nothing until each is filled:", o.policyPath, len(slots))
		for _, s := range slots {
			fmt.Fprintf(&b, "\n  %s", s)
		}
		fmt.Fprintf(&b, "\nNext: fill each with `cilock policy template -p %s --fill <step>.<rule>=<json>` or edit it by hand, then re-run prove", o.policyPath)
		return nil, errors.New(b.String())
	}
	if len(draftSteps(doc)) == 0 {
		return nil, fmt.Errorf("%s has no steps. Next: `cilock policy template -p %s --add-step <name> --goal <id>`", o.policyPath, o.policyPath)
	}
	return doc, nil
}

// provePlan is what prove runs: each step's command and attestors, in an
// order where a producer runs before every step that reads it.
type provePlan struct {
	changed   bool
	commands  map[string][]string
	order     []string
	attestors map[string][]string
	good      map[string]string
	traced    map[string]bool
}

func planProve(doc draftDoc, o proveOptions, report *proveReport) (*provePlan, error) {
	plan := &provePlan{attestors: map[string][]string{}, good: map[string]string{}, traced: map[string]bool{}}
	if !o.noNormalize {
		changes, err := normalizeDraft(doc, o.platformURL)
		if err != nil {
			return nil, err
		}
		for _, c := range changes {
			report.note("normalized: %s", c)
		}
		plan.changed = len(changes) > 0
	}
	checkFunctionaryTenants(doc, o.platformURL, report)

	var err error
	if plan.commands, err = proveCommands(doc, o); err != nil {
		return nil, err
	}
	if plan.order, err = stepOrder(doc); err != nil {
		return nil, fmt.Errorf("%w. Next: fix the step's artifactsFrom/attestationsFrom", err)
	}
	for _, name := range plan.order {
		names, err := stepRunAttestors(asMap(draftSteps(doc)[name]))
		if err != nil {
			return nil, fmt.Errorf("step %s: %w", name, err)
		}
		plan.attestors[name] = names
	}
	return plan, nil
}

func proveWorkdir(o proveOptions) (string, error) {
	workdir := o.workdir
	if workdir == "" {
		var err error
		if workdir, err = os.Getwd(); err != nil {
			return "", err
		}
	}
	return filepath.Abs(workdir)
}

// recordRealRuns records every step's own command, in order, and notes a step
// that recorded nothing or whose required trace is missing.
func (p *prover) recordRealRuns(doc draftDoc, plan *provePlan, trace bool, report *proveReport) {
	for _, name := range plan.order {
		step := asMap(draftSteps(doc)[name])
		plan.traced[name] = trace || stepReadsTrace(step)
		out, tail := p.record(name, "good", plan.attestors[name], plan.traced[name], plan.commands[name])
		if out == "" {
			if plan.traced[name] {
				report.problem("tracing unavailable for step %s: cilock run --trace recorded no evidence (%s); a tracing policy cannot be proved here", name, tail)
			} else {
				report.problem("step %s: cilock run recorded no evidence (%s)", name, tail)
			}
			continue
		}
		plan.good[name] = out
		if !plan.traced[name] {
			continue
		}
		if reason, ok := traceMissing(out); ok {
			report.problem("tracing unavailable for step %s: %s; a tracing policy cannot be proved here", name, reason)
		}
	}
}

// verifyRealRuns verifies the real evidence of every step together. It
// returns the first refusal in step order ("" when the evidence passed) and
// each refused step's reasons.
func (p *prover) verifyRealRuns(plan *provePlan) (string, map[string][]string) {
	if len(plan.good) != len(plan.order) {
		var missing []string
		for _, name := range plan.order {
			if _, ok := plan.good[name]; !ok {
				missing = append(missing, name)
			}
		}
		return missing[0] + ": no evidence was recorded for step " + strings.Join(missing, ", "), nil
	}
	refused, verr := p.verify(envelopeList(plan.good, plan.order, "", ""))
	if verr != nil {
		return "policy: " + verr.Error(), refused
	}
	for _, name := range plan.order {
		if reasons, ok := refused[name]; ok {
			return name + ": " + strings.Join(reasons, "; "), refused
		}
	}
	// A refused step outside the draft's order: report the first by name so
	// the line is stable.
	names := make([]string, 0, len(refused))
	for name := range refused {
		names = append(names, name)
	}
	if len(names) == 0 {
		return "", refused
	}
	sort.Strings(names)
	return names[0] + ": " + strings.Join(refused[names[0]], "; "), refused
}

// checkFailingRun puts one step's real evidence with its exit status set to
// 1 beside every other step's real evidence and requires the policy to
// refuse it.
func (p *prover) checkFailingRun(doc draftDoc, plan *provePlan, name string, goodRefused []string, report *proveReport) {
	step := asMap(draftSteps(doc)[name])
	if !requiresType(step, typeCommandRun) {
		report.steps = append(report.steps, fmt.Sprintf("%s: requires no command-run, so a failing command cannot be refused; only its %s rules judge it",
			name, strings.Join(stepAttestationTypes(step), ", ")))
		return
	}
	if len(plan.good) != len(plan.order) {
		report.steps = append(report.steps, fmt.Sprintf("%s: failing-run check skipped, because not every step has real evidence", name))
		return
	}
	bad, err := p.failingEvidence(name, plan.good[name])
	if err != nil {
		report.problem("step %s: the failing run could not be derived from the real one: %v", name, err)
		return
	}
	refused, verr := p.verify(envelopeList(plan.good, plan.order, name, bad))
	switch {
	case verr != nil:
		report.problem("step %s: the failing run could not be checked: %v", name, verr)
	case len(refused[name]) > 0:
		real := "real run admitted"
		if len(goodRefused) > 0 {
			real = "real run REFUSED (" + strings.Join(goodRefused, "; ") + ")"
		}
		report.steps = append(report.steps, fmt.Sprintf("%s: %s; failing run refused (%s)", name, real, strings.Join(refused[name], "; ")))
	default:
		report.problem("step %s admits a failing run: add a rule (e.g. command-succeeded on command-run) that refuses it", name)
	}
}

// writeProvedDraft writes the draft back when prove normalized it or an
// output was named, and returns where the draft is.
func writeProvedDraft(doc draftDoc, o proveOptions, changed bool, report *proveReport) (string, error) {
	target := o.output
	if target == "" {
		target = o.policyPath
	}
	if changed || o.output != "" {
		if err := saveDraft(target, doc, false); err != nil {
			return "", err
		}
		report.note("wrote %s", target)
	}
	return target, nil
}

func proveFailureSummary(refusal string, r *proveReport) string {
	var parts []string
	if refusal != "" {
		parts = append(parts, "the real evidence was refused")
	}
	if n := len(r.problems); n > 0 {
		parts = append(parts, fmt.Sprintf("%d problem(s) listed above", n))
	}
	return strings.Join(parts, " and ")
}

func writeProveReport(out io.Writer, r *proveReport, draftPath, platformURL string) {
	w := func(format string, args ...any) { _, _ = fmt.Fprintf(out, format, args...) }
	w("%s\n", r.firstLine)
	for _, s := range r.steps {
		w("  step %s\n", s)
	}
	for _, p := range r.problems {
		w("PROBLEM: %s\n", p)
	}
	for _, n := range r.notes {
		w("  %s\n", n)
	}
	gate := "<your Pushgate site>"
	if origin, err := discoverPushgateOrigin(platformURLOrDefault(platformURL)); err == nil && origin != "" {
		gate = strings.TrimRight(origin, "/")
	}
	w("Next: hand %s to your human: open %s/policy/new?mode=manual, choose Import or paste, press Import a file and pick it, then Save and Validate.\n", draftPath, gate)
	w("      Lead your handoff with the first line above. Never sign, publish or activate the policy yourself.\n")
}

func platformURLOrDefault(u string) string {
	if u == "" {
		return config.DefaultPlatformURL
	}
	return u
}

// proveCommands resolves each step's argv: --step/--run first, then the argv
// the step's command-pin rule pins. A step with neither is an error naming
// exactly what to pass.
func proveCommands(doc draftDoc, o proveOptions) (map[string][]string, error) {
	steps := draftSteps(doc)
	commands := map[string][]string{}
	given := map[string][]string{}
	for _, spec := range o.runs {
		name, argvText, ok := strings.Cut(spec, "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("--run %q: want <step>=<argv>", spec)
		}
		argv, err := parseArgv(argvText)
		if err != nil {
			return nil, fmt.Errorf("--run %s: %w", name, err)
		}
		given[name] = argv
	}
	if o.step != "" {
		given[o.step] = o.stepArgv
	}
	for name := range given {
		if _, ok := steps[name]; !ok {
			return nil, fmt.Errorf("a command was given for step %s, which %s does not have (steps: %s)", name, o.policyPath, strings.Join(sortedStepNames(doc), ", "))
		}
	}
	var missing []string
	for _, name := range sortedStepNames(doc) {
		if argv, ok := given[name]; ok {
			commands[name] = argv
			continue
		}
		if argv, ok := pinnedArgv(asMap(steps[name])); ok {
			commands[name] = argv
			continue
		}
		missing = append(missing, name)
	}
	if len(missing) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "prove needs a command for step(s) %s: none was given and none is pinned by a command-pin rule. Next: pass", strings.Join(missing, ", "))
		for _, name := range missing {
			fmt.Fprintf(&b, " --run %s='<argv>'", name)
		}
		fmt.Fprintf(&b, " (or --step %s -- <argv> for one of them)", missing[0])
		return nil, errors.New(b.String())
	}
	return commands, nil
}

// normalizeDraft fills the Pushgate blocks prove owns and returns what it
// changed. It never touches a step's attestations, rules or edges.
func normalizeDraft(doc draftDoc, platformURL string) ([]string, error) {
	var changes []string
	steps := draftSteps(doc)
	var needAgent []string
	for _, name := range sortedStepNames(doc) {
		funcs := asList(asMap(steps[name])["functionaries"])
		keyOnly := len(funcs) > 0
		for _, f := range funcs {
			if asMap(f)[draftKeyType] != flagPublicKey {
				keyOnly = false
			}
		}
		if len(funcs) == 0 || keyOnly {
			needAgent = append(needAgent, name)
		}
	}
	if len(needAgent) > 0 {
		id, err := lookupEnrolledIdentity(platformURL)
		if err != nil {
			return nil, fmt.Errorf("step(s) %s need the agent functionary: %w (or pass --no-normalize to prove the rules without it)", strings.Join(needAgent, ", "), err)
		}
		for _, name := range needAgent {
			asMap(steps[name])["functionaries"] = []any{agentFunctionary(id.trustDomain, id.tenantID)}
		}
		changes = append(changes, fmt.Sprintf("step(s) %s now name the enrolled agent spiffe://%s/tenant/%s/agent/*", strings.Join(needAgent, ", "), id.trustDomain, id.tenantID))
		if _, ok := doc["publickeys"]; ok && !anyPublicKeyFunctionary(doc) {
			delete(doc, "publickeys")
			changes = append(changes, "removed publickeys no functionary references")
		}
	}
	roots, tsas := platformTrustPlaceholders()
	if !trustIsPlaceholder(doc["roots"], platformFulcioRoot) {
		changes = append(changes, "roots set to the platform placeholder {\"fulcio-root\": {\"certificate\": \"\"}} (trust comes from the platform, never from evidence)")
		doc["roots"] = roots
	}
	if !trustIsPlaceholder(doc["timestampauthorities"], platformTSA) {
		changes = append(changes, "timestampauthorities set to the platform placeholder {\"platform-tsa\": {\"certificate\": \"\"}}")
		doc["timestampauthorities"] = tsas
	}
	if e, _ := doc["expires"].(string); e == "" {
		doc["expires"] = oneYearFromToday(nowFunc())
		changes = append(changes, fmt.Sprintf("expires set to %v", doc["expires"]))
	}
	return changes, nil
}

var nowFunc = time.Now

func anyPublicKeyFunctionary(doc draftDoc) bool {
	for _, s := range draftSteps(doc) {
		for _, f := range asList(asMap(s)["functionaries"]) {
			if asMap(f)[draftKeyType] == flagPublicKey {
				return true
			}
		}
	}
	return false
}

func trustIsPlaceholder(v any, name string) bool {
	m := asMap(v)
	if len(m) != 1 {
		return false
	}
	entry := asMap(m[name])
	cert, ok := entry["certificate"].(string)
	return entry != nil && ok && cert == ""
}

// checkFunctionaryTenants reports a root functionary whose SPIFFE URI names a
// tenant other than the enrolled agent's, or no tenant at all. Without an
// enrollment there is nothing to compare, and it stays silent.
func checkFunctionaryTenants(doc draftDoc, platformURL string, r *proveReport) {
	id, err := lookupEnrolledIdentity(platformURL)
	if err != nil {
		return
	}
	want := fmt.Sprintf("spiffe://%s/tenant/%s/", id.trustDomain, id.tenantID)
	for _, name := range sortedStepNames(doc) {
		for _, f := range asList(asMap(draftSteps(doc)[name])["functionaries"]) {
			cc := asMap(asMap(f)["certConstraint"])
			for _, u := range stringList(cc["uris"]) {
				if strings.HasPrefix(strings.ToLower(u), "spiffe://") && !strings.HasPrefix(u, want) {
					r.problem("step %s: functionary URI %s does not name the enrolled agent's tenant (%s*)", name, u, want)
				}
			}
		}
	}
}

// validateDraft runs `cilock policy validate` on the draft as it will be
// handed over. The empty platform trust placeholders are not errors in an
// unsigned draft (the validator reports them in Placeholders), so every
// error it returns is a problem.
func validateDraft(ctx context.Context, doc draftDoc, r *proveReport) {
	raw, err := encodeDraft(doc)
	if err != nil {
		r.problem("validate: %v", err)
		return
	}
	result := internalpolicy.ValidateRawPolicy(ctx, raw)
	for _, e := range result.Errors {
		r.problem("validate: %s", e)
	}
	if len(result.Errors) == 0 {
		if len(result.Placeholders) > 0 {
			r.note("validate: passed as an unsigned draft; %s are empty platform placeholders the platform fills when your human signs", strings.Join(result.Placeholders, ", "))
		} else {
			r.note("validate: passed")
		}
	}
	for _, w := range result.Warnings {
		r.note("validate warning: %s", w)
	}
}

func inside(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func envelopeList(good map[string]string, order []string, replace, with string) []string {
	var out []string
	for _, name := range order {
		if name == replace {
			out = append(out, with)
			continue
		}
		if g, ok := good[name]; ok {
			out = append(out, g)
		}
	}
	return out
}

// traceMissing reports why a traced run carries no process tree.
func traceMissing(envelope string) (string, bool) {
	stmt, err := readStatement(envelope)
	if err != nil {
		return "its evidence could not be read: " + err.Error(), true
	}
	for _, a := range stmt.Predicate.Attestations {
		if a.Type != typeCommandRun {
			continue
		}
		var cr struct {
			Meta struct {
				CaptureMode  string `json:"captureMode"`
				TraceBackend string `json:"traceBackend"`
			} `json:"_meta"`
			Processes []json.RawMessage `json:"processes"`
		}
		if err := json.Unmarshal(a.Attestation, &cr); err != nil {
			return "its command-run record could not be read: " + err.Error(), true
		}
		if len(cr.Processes) > 0 {
			return "", false
		}
		return fmt.Sprintf("cilock run --trace recorded no processes (capture mode %q, trace backend %q)", cr.Meta.CaptureMode, cr.Meta.TraceBackend), true
	}
	return "the run carries no command-run record", true
}
