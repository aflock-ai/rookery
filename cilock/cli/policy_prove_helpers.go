package cli

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Helpers `cilock policy prove` reads a draft with. They work on the
// decoded JSON a draft is handled as (policy_authoring.go), never on the
// typed policy struct.

func stringList(v any) []string {
	var out []string
	for _, e := range asList(v) {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// stepEdges names the steps a step reads through artifactsFrom and
// attestationsFrom, each once, sorted.
func stepEdges(step map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, key := range []string{"artifactsFrom", "attestationsFrom"} {
		for _, s := range stringList(step[key]) {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// stepOrder is the draft's steps in an order that records every producer
// before the step that reads it, or the edge that makes that impossible.
func stepOrder(doc draftDoc) ([]string, error) {
	steps := draftSteps(doc)
	names := sortedStepNames(doc)
	for _, n := range names {
		for _, dep := range stepEdges(asMap(steps[n])) {
			if _, ok := steps[dep]; !ok {
				return nil, fmt.Errorf("step %s reads step %s through artifactsFrom/attestationsFrom, and the draft has no step %s", n, dep, dep)
			}
		}
	}
	var order []string
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(n string, path []string) error
	visit = func(n string, path []string) error {
		switch state[n] {
		case 2:
			return nil
		case 1:
			return fmt.Errorf("steps form a cycle: %s", strings.Join(append(path, n), " -> "))
		}
		state[n] = 1
		for _, dep := range stepEdges(asMap(steps[n])) {
			if err := visit(dep, append(path, n)); err != nil {
				return err
			}
		}
		state[n] = 2
		order = append(order, n)
		return nil
	}
	for _, n := range names {
		if err := visit(n, nil); err != nil {
			return nil, err
		}
	}
	return order, nil
}

// stepReadsTrace reports whether any command-run rule of the step reads the
// process tree, so the step has to be recorded with cilock run --trace.
func stepReadsTrace(step map[string]any) bool {
	for _, src := range stepModules(step, typeCommandRun) {
		if strings.Contains(src, `"processes"`) || strings.Contains(src, ".processes") {
			return true
		}
	}
	return false
}

// parseArgv reads a --run command: a JSON array of strings, or plain words
// with no quoting.
func parseArgv(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty command")
	}
	if strings.HasPrefix(s, "[") {
		var argv []string
		if err := json.Unmarshal([]byte(s), &argv); err != nil {
			return nil, fmt.Errorf("command %q is not a JSON array of strings: %v", s, err)
		}
		if len(argv) == 0 {
			return nil, fmt.Errorf("empty command")
		}
		return argv, nil
	}
	if strings.ContainsAny(s, `"'`) {
		return nil, fmt.Errorf("command %q contains quotes, which are not parsed; write it as a JSON array, e.g. [\"sh\",\"-c\",\"...\"]", s)
	}
	return strings.Fields(s), nil
}

var plainShellWord = regexp.MustCompile(`^[A-Za-z0-9_./:=@%+,-]+$`)

// shellQuoteArgv renders argv the way a reader could paste it into a shell.
func shellQuoteArgv(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		if plainShellWord.MatchString(a) {
			parts = append(parts, a)
			continue
		}
		parts = append(parts, shellQuote(a))
	}
	return strings.Join(parts, " ")
}
