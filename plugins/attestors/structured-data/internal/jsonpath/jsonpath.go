// Package jsonpath is an inlined, conformant subset of RFC 9535 JSONPath used
// by the structured-data attestor to select subject paths from arbitrary JSON
// input. We intentionally support a small surface — child, index, wildcard,
// recursive descent — because attestor subject selection only needs to walk
// structure, not filter or compute. Keeping this inline (no external
// dependency) honors the rookery convention that each attestor adds zero
// third-party deps beyond the attestation framework.
//
// Supported syntax (conformant against RFC 9535 §2.3):
//
//	$                root identifier
//	.name            named child (shorthand)
//	['name']         named child (bracketed; required for non-identifier names)
//	["name"]         named child (double-quoted form)
//	[N]              array index (non-negative)
//	[*]              wildcard (every array element / every object value)
//	.*               wildcard (shorthand)
//	..name           recursive descent + named child
//	..[*]            recursive descent + wildcard
//
// Unsupported (silently rejected with an error):
//
//	slices ([start:end:step]), filters ([?(...)]), functions (length(),
//	count(), value()), unions ([a,b,c]), negative indices.
//
// Returned matches are pairs of (path, value) where path is the canonical
// normalized form per RFC 9535 §2.7 (every step is `['name']` or `[N]`).
// The structured-data attestor uses the value to digest and the path as the
// subject-key prefix.
package jsonpath

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Match is one selection result. Path is normalized to the canonical form
// `$['a'][2]['b']` so two equivalent queries produce identical subject keys.
type Match struct {
	Path  string
	Value any
}

// Select runs the JSONPath query against root and returns every match in
// document order. The input root should be the result of json.Unmarshal into
// an any (map[string]any / []any / string / float64 / bool / nil).
func Select(root any, query string) ([]Match, error) {
	steps, err := parse(query)
	if err != nil {
		return nil, err
	}
	out := []Match{}
	walk(root, "$", steps, &out)
	return out, nil
}

// step is one selector in the parsed query. Exactly one of the kind fields is
// populated (we keep them as separate fields rather than an enum so the
// matcher branches inline without a type switch).
type step struct {
	kind      stepKind
	name      string // for stepName
	index     int    // for stepIndex
	recursive bool   // true when prefixed with `..`
}

type stepKind int

const (
	stepName stepKind = iota + 1
	stepIndex
	stepWildcard
)

// parse converts a JSONPath query into an ordered sequence of steps. We
// hand-roll the parser — gojq / generic JSONPath libraries are far larger
// than this subset needs and bring a transitive parser-generator dependency.
func parse(query string) ([]step, error) {
	if !strings.HasPrefix(query, "$") {
		return nil, errors.New("jsonpath: query must start with '$'")
	}
	src := query[1:]
	steps := []step{}
	recurseNext := false
	for len(src) > 0 {
		// After `..` we accept an identifier, wildcard, or `[`-selector
		// directly — no intervening `.`. Handle that case before the
		// dispatch switch so the parser can land on `author` in `$..author`.
		if recurseNext && (isIdentStart(src[0]) || src[0] == '*') {
			s, rest, err := consumeRecursiveHead(src)
			if err != nil {
				return nil, err
			}
			steps = append(steps, s)
			recurseNext = false
			src = rest
			continue
		}
		switch src[0] {
		case '.':
			newSteps, rest, nextRecurse, err := consumeDot(src, recurseNext)
			if err != nil {
				return nil, err
			}
			steps = append(steps, newSteps...)
			recurseNext = nextRecurse
			src = rest
		case '[':
			s, rest, err := consumeBracket(src)
			if err != nil {
				return nil, err
			}
			s.recursive = recurseNext
			recurseNext = false
			steps = append(steps, s)
			src = rest
		default:
			return nil, fmt.Errorf("jsonpath: unexpected character %q at remainder %q", src[0], src)
		}
	}
	if recurseNext {
		return nil, errors.New("jsonpath: trailing '..'")
	}
	return steps, nil
}

// consumeRecursiveHead handles the token immediately after `..` when it is an
// identifier or wildcard (the `[`-selector case is handled by the normal
// bracket path on the next iteration with recurseNext still set).
func consumeRecursiveHead(src string) (step, string, error) {
	if src[0] == '*' {
		return step{kind: stepWildcard, recursive: true}, src[1:], nil
	}
	name, rest, err := consumeIdent(src)
	if err != nil {
		return step{}, src, err
	}
	return step{kind: stepName, name: name, recursive: true}, rest, nil
}

// consumeDot handles a leading `.` token: either recursive descent (`..`),
// plain child (`.name`), or plain wildcard (`.*`). It returns the steps it
// produced (zero for `..`, one otherwise), the remaining source, and whether
// recurseNext should be set for the next iteration.
func consumeDot(src string, recurseNext bool) ([]step, string, bool, error) {
	// `..` is recursive descent; mark recurseNext and emit no step.
	if len(src) > 1 && src[1] == '.' {
		return nil, src[2:], true, nil
	}
	src = src[1:]
	if len(src) == 0 {
		return nil, src, false, errors.New("jsonpath: trailing '.'")
	}
	if src[0] == '*' {
		return []step{{kind: stepWildcard, recursive: recurseNext}}, src[1:], false, nil
	}
	name, rest, err := consumeIdent(src)
	if err != nil {
		return nil, src, false, err
	}
	return []step{{kind: stepName, name: name, recursive: recurseNext}}, rest, false, nil
}

// consumeIdent reads a bare identifier in the [A-Za-z_][A-Za-z0-9_]* shape.
// Names with special characters must use bracket form (`['weird name']`).
func consumeIdent(s string) (string, string, error) {
	if len(s) == 0 || !isIdentStart(s[0]) {
		return "", s, fmt.Errorf("jsonpath: expected identifier, got %q", s)
	}
	i := 1
	for i < len(s) && isIdentPart(s[i]) {
		i++
	}
	return s[:i], s[i:], nil
}

func isIdentStart(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '_'
}

func isIdentPart(b byte) bool {
	return isIdentStart(b) || (b >= '0' && b <= '9')
}

// consumeBracket reads one bracket selector — `[N]`, `[*]`, `['name']`, or
// `["name"]`. Returns the corresponding step plus the trailing input.
func consumeBracket(src string) (step, string, error) {
	if !strings.HasPrefix(src, "[") {
		return step{}, src, errors.New("jsonpath: expected '['")
	}
	end := strings.IndexByte(src, ']')
	if end < 0 {
		return step{}, src, errors.New("jsonpath: unterminated '['")
	}
	body := strings.TrimSpace(src[1:end])
	rest := src[end+1:]
	switch {
	case body == "*":
		return step{kind: stepWildcard}, rest, nil
	case strings.HasPrefix(body, "'") && strings.HasSuffix(body, "'") && len(body) >= 2:
		return step{kind: stepName, name: body[1 : len(body)-1]}, rest, nil
	case strings.HasPrefix(body, `"`) && strings.HasSuffix(body, `"`) && len(body) >= 2:
		return step{kind: stepName, name: body[1 : len(body)-1]}, rest, nil
	default:
		// Numeric index. Negative indices and slices are out of subset scope.
		if strings.ContainsAny(body, ":,") {
			return step{}, src, errors.New("jsonpath: slices/unions not supported in this subset")
		}
		n, err := strconv.Atoi(body)
		if err != nil {
			return step{}, src, fmt.Errorf("jsonpath: invalid index %q", body)
		}
		if n < 0 {
			return step{}, src, errors.New("jsonpath: negative indices not supported")
		}
		return step{kind: stepIndex, index: n}, rest, nil
	}
}

// walk applies steps to value and appends every match to out. Recursive
// descent steps fan out: at every node in the subtree below value, we apply
// the step as if non-recursive.
func walk(value any, path string, steps []step, out *[]Match) {
	if len(steps) == 0 {
		*out = append(*out, Match{Path: path, Value: value})
		return
	}
	s := steps[0]
	rest := steps[1:]

	if s.recursive {
		// Apply s to every node in the subtree rooted at value (including
		// value itself). Path tracks where we are.
		descendApply(value, path, s, rest, out)
		return
	}

	applyOne(value, path, s, rest, out)
}

func applyOne(value any, path string, s step, rest []step, out *[]Match) {
	switch s.kind {
	case stepName:
		obj, ok := value.(map[string]any)
		if !ok {
			return
		}
		child, ok := obj[s.name]
		if !ok {
			return
		}
		walk(child, fmt.Sprintf("%s['%s']", path, s.name), rest, out)
	case stepIndex:
		arr, ok := value.([]any)
		if !ok {
			return
		}
		if s.index >= len(arr) {
			return
		}
		walk(arr[s.index], fmt.Sprintf("%s[%d]", path, s.index), rest, out)
	case stepWildcard:
		switch v := value.(type) {
		case map[string]any:
			// Iterate keys in lexical order so output is deterministic.
			keys := sortedKeys(v)
			for _, k := range keys {
				walk(v[k], fmt.Sprintf("%s['%s']", path, k), rest, out)
			}
		case []any:
			for i, c := range v {
				walk(c, fmt.Sprintf("%s[%d]", path, i), rest, out)
			}
		}
	}
}

// descendApply walks every node in the subtree at value and tries `s` as a
// non-recursive step at each. This is the RFC 9535 `..` operator.
func descendApply(value any, path string, s step, rest []step, out *[]Match) {
	// Try at the current node first.
	nonRec := s
	nonRec.recursive = false
	applyOne(value, path, nonRec, rest, out)
	// Then recurse into children.
	switch v := value.(type) {
	case map[string]any:
		for _, k := range sortedKeys(v) {
			descendApply(v[k], fmt.Sprintf("%s['%s']", path, k), s, rest, out)
		}
	case []any:
		for i, c := range v {
			descendApply(c, fmt.Sprintf("%s[%d]", path, i), s, rest, out)
		}
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Plain sort.Strings without importing sort — keep std-lib surface tight.
	// Insertion sort is fine; objects rarely have many keys.
	for i := 1; i < len(keys); i++ {
		j := i
		for j > 0 && keys[j-1] > keys[j] {
			keys[j-1], keys[j] = keys[j], keys[j-1]
			j--
		}
	}
	return keys
}
