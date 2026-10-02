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
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/registry"
)

// Refusals a coding agent meets while wiring cilock into a repository, each
// rewritten to name the cause and the flag to pass instead. None of them
// changes what is accepted or refused, and none auto-corrects: the agent sees
// the correction and reruns. (Rewriting the agent's own argv was cut at
// round 3 of #10201; it needs an option-aware tokenizer.)

// attestorAlias is a name an agent was taught for evidence that is not an
// attestor name: a pairing-goal id ("provenance") or a detector category a
// goal joins on ("lint"). It resolves to the attestors that goal needs
// beyond the always-recorded ones.
type attestorAlias struct {
	Goal      string
	Category  string   // the detector category the alias is, or "" for the goal id itself
	Attestors []string // the -a names the goal needs; empty when every one is always recorded
	Always    []string // the goal's always-recorded attestors
}

// attestorAliases derives the alias table from the goal catalog, so a goal or
// a category added there is understood here with no edit. Goal ids win over
// categories, and no alias shadows a real attestor name.
func attestorAliases() map[string]attestorAlias {
	out := map[string]attestorAlias{}
	add := func(key string, a attestorAlias) {
		if _, taken := out[key]; taken || isRegisteredAttestor(key) {
			return
		}
		out[key] = a
	}
	byGoal := make([]attestorAlias, len(catalogGoals))
	for i, g := range catalogGoals {
		a := attestorAlias{Goal: g.ID, Attestors: []string{}}
		for _, t := range g.Attestors {
			ca, ok := attestorByName(t)
			if !ok {
				continue
			}
			if ca.Always {
				a.Always = appendUnique(a.Always, ca.Name)
				continue
			}
			a.Attestors = appendUnique(a.Attestors, ca.Name)
		}
		byGoal[i] = a
		add(g.ID, a)
	}
	for i, g := range catalogGoals {
		for _, c := range g.Categories {
			a := byGoal[i]
			a.Category = string(c)
			add(string(c), a)
		}
	}
	return out
}

func isRegisteredAttestor(name string) bool {
	if _, ok := attestation.FactoryByName(name); ok {
		return true
	}
	_, ok := attestation.FactoryByType(name)
	return ok
}

// alwaysRecorded is true for the attestors every run records without -a.
func alwaysRecorded(name string) bool {
	if name == attestorCommandRun {
		return true
	}
	a, ok := attestorByName(name)
	return ok && a.Always
}

// attestorFix is what an unknown attestor name should have been: Replace
// holds the names to pass instead (empty means drop it), Why the sentence
// that says so, Goal the goal it resolved through, if any. Fixed is false
// when nothing close was found.
type attestorFix struct {
	Replace []string
	Why     string
	Goal    string
	Fixed   bool
}

func joinAnd(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// recordedBy says which attestor records an alias's goal, or that the goal
// needs none. flag is how the caller's command names attestors ("-a",
// "--attestor").
func (a attestorAlias) recordedBy(flag string) string {
	if len(a.Attestors) == 0 {
		return fmt.Sprintf("needs no %s: its evidence (%s) is recorded on every run, so drop it", flag, strings.Join(a.Always, ", "))
	}
	plural := ""
	if len(a.Attestors) > 1 {
		plural = "s"
	}
	return fmt.Sprintf("is recorded by the %s attestor%s", joinAnd(a.Attestors), plural)
}

func (a attestorAlias) fix(flag string) attestorFix {
	subject := "the " + a.Goal + " goal"
	if a.Category != "" {
		subject = fmt.Sprintf("%s is a check of the %s goal, which", a.Category, a.Goal)
	}
	return attestorFix{Replace: a.Attestors, Why: subject + " " + a.recordedBy(flag), Goal: a.Goal, Fixed: true}
}

// correctAttestor resolves a name that is not an attestor: its lowercase
// spelling, a goal id or category alias, or the one attestor or alias within
// a small edit distance. known lists the attestor names the caller accepts.
func correctAttestor(name string, isAttestor func(string) bool, known []string, flag string) attestorFix {
	lower := strings.ToLower(strings.TrimSpace(name))
	aliases := attestorAliases()
	if lower != name && isAttestor(lower) {
		return spelledAttestorFix(lower)
	}
	if a, ok := aliases[lower]; ok {
		return a.fix(flag)
	}
	aliasKeys := make([]string, 0, len(aliases))
	for k := range aliases {
		aliasKeys = append(aliasKeys, k)
	}
	sort.Strings(aliasKeys)
	bestNames := closestNames(lower, append(append([]string{}, known...), aliasKeys...))
	if len(bestNames) == 0 {
		return attestorFix{}
	}
	if len(bestNames) > 1 {
		return attestorFix{Why: "did you mean " + joinOr(bestNames) + "?"}
	}
	target := bestNames[0]
	if a, ok := aliases[target]; ok && !isAttestor(target) {
		f := a.fix(flag)
		what := "the " + a.Goal + " goal"
		if a.Category != "" {
			what = a.Category + ", a check of the " + a.Goal + " goal"
		}
		f.Why = fmt.Sprintf("did you mean %s? It %s", what, a.recordedBy(flag))
		return f
	}
	return spelledAttestorFix(target)
}

// closestNames returns the candidates nearest name by edit distance, within
// one edit for a name of up to four characters and two edits otherwise.
func closestNames(name string, candidates []string) []string {
	limit := 1
	if len([]rune(name)) > 4 {
		limit = 2
	}
	best, bestNames := limit+1, []string{}
	for _, c := range candidates {
		d := editDistance(name, c)
		switch {
		case d > limit:
			continue
		case d < best:
			best, bestNames = d, []string{c}
		case d == best:
			bestNames = appendUnique(bestNames, c)
		}
	}
	return bestNames
}

func spelledAttestorFix(target string) attestorFix {
	if alwaysRecorded(target) {
		return attestorFix{Replace: []string{}, Why: fmt.Sprintf("did you mean %s? It is recorded on every run, so drop it", target), Fixed: true}
	}
	return attestorFix{Replace: []string{target}, Why: fmt.Sprintf("did you mean %s?", target), Fixed: true}
}

func joinOr(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " or " + names[len(names)-1]
}

// editDistance is the optimal-string-alignment distance: insertions,
// deletions, substitutions and adjacent transpositions ("slas" is one from
// "slsa") each cost one.
func editDistance(a, b string) int {
	x, y := []rune(a), []rune(b)
	d := make([][]int, len(x)+1)
	for i := range d {
		d[i] = make([]int, len(y)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(x); i++ {
		for j := 1; j <= len(y); j++ {
			cost := 1
			if x[i-1] == y[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && x[i-1] == y[j-2] && x[i-2] == y[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(x)][len(y)]
}

// sentence ends s with a period unless it already ends a sentence.
func sentence(s string) string {
	if strings.HasSuffix(s, ".") || strings.HasSuffix(s, "?") {
		return s
	}
	return s + "."
}

// attestorNotFoundError is `cilock run` and `cilock attest`'s refusal for an
// -a name the registry does not have. It keeps the original error in the
// chain and its text as the prefix, explains every unknown name requested,
// and when all of them resolve, says what to pass instead.
func attestorNotFoundError(err error, requested []string) error {
	entries := attestation.RegistrationEntries()
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	sort.Strings(names)
	var why, instead []string
	allFixed := true
	seen := map[string]bool{}
	for _, r := range requested {
		if seen[r] || r == attestorCommandRun || isRegisteredAttestor(r) {
			continue
		}
		seen[r] = true
		f := correctAttestor(r, isRegisteredAttestor, names, "-a")
		if !f.Fixed {
			allFixed = false
			if f.Why == "" {
				f.Why = "no attestor or goal has a name close to it"
			}
		} else if len(f.Replace) == 0 {
			instead = append(instead, "no -a "+r)
		} else {
			instead = append(instead, "-a "+strings.Join(f.Replace, " -a ")+" instead of -a "+r)
		}
		why = append(why, fmt.Sprintf("%q: %s", r, f.Why))
	}
	if len(why) == 0 {
		return fmt.Errorf("failed to create attestor: %w", err)
	}
	next := " Next: `cilock attestors list` names every attestor this cilock records, and `cilock policy guide` maps each goal to the attestors that record it"
	if allFixed && len(instead) > 0 {
		next = " Next: rerun with " + joinAnd(instead)
	}
	// The explanation carries the user's own text; only the format string is
	// constant.
	return fmt.Errorf("failed to create attestor: %w. %s%s", err, sentence(strings.Join(why, "; ")), next)
}

// templateUnknownAttestorError is `cilock policy template --attestor`'s
// refusal for a name the authoring catalog does not describe.
func templateUnknownAttestorError(name string) error {
	known := make([]string, 0, len(catalogAttestors))
	for _, a := range catalogAttestors {
		known = appendUnique(known, a.Name)
	}
	sort.Strings(known)
	isCatalogAttestor := func(n string) bool { _, ok := attestorByName(n); return ok }
	f := correctAttestor(name, isCatalogAttestor, known, "--attestor")
	fallback := ". Next: `cilock policy guide --topic attestors` lists the ones with guidance, and `cilock attestors list` every one this cilock records"
	if f.Why == "" {
		return fmt.Errorf("unknown attestor %q%s", name, fallback)
	}
	msg := fmt.Sprintf("unknown attestor %q. %q: %s", name, name, sentence(f.Why))
	if !f.Fixed {
		return errors.New(msg + strings.TrimPrefix(fallback, "."))
	}
	goal := f.Goal
	if len(f.Replace) == 0 {
		if goal != "" {
			return fmt.Errorf("%s Next: pass --goal %s instead of --attestor %s", msg, goal, name)
		}
		return fmt.Errorf("%s Next: drop --attestor %s", msg, name)
	}
	next := fmt.Sprintf(" Next: --attestor %s", strings.Join(f.Replace, " --attestor "))
	if goal != "" {
		next += fmt.Sprintf(" (or --goal %s for the goal's whole step: its attestations and seeded rules)", goal)
	}
	return errors.New(msg + next)
}

// stepNameRule states the whole rule stepNameRE enforces.
const stepNameRule = "a step name must start with a letter or digit and then use only letters, digits, '.', '_' and '-'"

// suggestStepName derives a name that passes stepNameRE from one that does
// not: each character outside the rule becomes '-', leading punctuation is
// dropped, and a name taken in the draft gets the first free -<n>.
func suggestStepName(name string, taken map[string]bool) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	s := strings.TrimLeft(b.String(), "._-")
	if s == "" {
		s = "step"
	}
	if !taken[s] {
		return s
	}
	for n := 2; ; n++ {
		if c := fmt.Sprintf("%s-%d", s, n); !taken[c] {
			return c
		}
	}
}

// stepNameError is template's refusal of a step name, with the whole rule and
// a name that passes it. It does not rewrite the agent's command line.
func stepNameError(name string, steps map[string]any) error {
	taken := make(map[string]bool, len(steps))
	for s := range steps {
		taken[s] = true
	}
	fixed := suggestStepName(name, taken)
	return fmt.Errorf("step name %q: %s (it is the --step you pass to cilock run). Next: use --add-step %s", name, stepNameRule, shellQuoteArgv([]string{fixed}))
}

// stepNameWarning is what `cilock run --step` says about a name template
// would refuse. run still accepts it (a hand-written policy may name any
// step); the warning makes the two commands state one rule.
func stepNameWarning(name string) string {
	if name == "" || stepNameRE.MatchString(name) {
		return ""
	}
	return fmt.Sprintf("step name %q: %s, so `cilock policy template --add-step` refuses it, and a policy step must equal this --step. Next: use --step %s",
		name, stepNameRule, shellQuoteArgv([]string{suggestStepName(name, nil)}))
}

// exportNeedsOutfileError is the refusal for an exporting attestor with no
// --outfile. It names the flag that asked for the extra attestation and a free
// -o <step>.json to add. It does not rewrite the agent's command line.
func exportNeedsOutfileError(step string, exported []string) error {
	var names []string
	for _, e := range exported {
		name, _, _ := strings.Cut(e, "/")
		names = appendUnique(names, name)
	}
	var asked []string
	for _, n := range names {
		if flag := exportFlag(n); flag != "" {
			asked = append(asked, "--"+flag)
		} else {
			asked = append(asked, "the "+n+" attestor")
		}
	}
	companions := func(candidate string) []string {
		out := companionPaths(candidate)
		for _, e := range exported {
			out = append(out, candidate+"-"+strings.ReplaceAll(e, "/", "-")+".json")
		}
		return out
	}
	outfile := suggestStepName(step, nil) + ".json"
	if !pathsAbsent(append([]string{outfile}, companions(outfile)...)) {
		outfile = suggestFreshOutfileWith(outfile, companions)
	}
	msg := fmt.Sprintf("--outfile is required when attestors export multiple attestations: %s writes its own attestation beside the step's, as <outfile>-<attestor>.json, so the run needs an --outfile to name them. "+
		"The wrapped command already ran; rerun it with one", joinAnd(asked))
	if outfile == "" {
		return errors.New(msg + ". Next: add -o <file that does not exist yet>")
	}
	return errors.New(msg + ". Next: add -o " + shellQuoteArgv([]string{outfile}))
}

// exportFlag is the flag that turns on an attestor's export, or "" when the
// attestor has no export option (its extra attestations are companions).
func exportFlag(attestor string) string {
	for _, e := range attestation.RegistrationEntries() {
		if e.Name != attestor {
			continue
		}
		for _, o := range e.Options {
			if o.Name() == "export" {
				return registry.AttestorFlagName(attestor, "export")
			}
		}
	}
	return ""
}

func pathsAbsent(paths []string) bool {
	for _, p := range paths {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			return false
		}
	}
	return true
}
