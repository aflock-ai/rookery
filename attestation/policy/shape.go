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

package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Expected shapes, spelled with the schema's own member names (step.go
// Attestation, RegoPolicy; policy.go Step, Functionary).
const (
	shapeRegoPolicy  = `{"name": "<rule name>", "module": "<base64 rego>"}`
	shapeAttestation = `{"type": "<predicate type>", "regopolicies": [...]}`
	shapeFunctionary = `{"type": "root", "certConstraint": {...}} or {"type": "publickey", "publickeyid": "..."}`
)

// ShapeErrors explains, by JSON path and expected shape, each place along the
// steps -> attestations -> regopolicies path where a policy document holds a
// value of the wrong JSON kind. encoding/json reports that mistake as "cannot
// unmarshal string into Go struct field attestation.steps.attestations.
// regopolicies of type policy.regoPolicy", which names neither the element nor
// what to write instead.
//
// It is an explainer, never a gate: it reports only kinds the policy decoder
// itself refuses (an object position holding a string, number, boolean or
// array; a list position holding a non-array), and is silent on null, which
// the decoder accepts. Callers use it to replace the decoder's message after
// the decoder has already failed, so it cannot add a refusal the verifier
// never had. A document that is not JSON yields nothing.
func ShapeErrors(payload []byte) []string {
	var doc map[string]any
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil
	}
	var out []string
	steps, ok := doc["steps"]
	if !ok || steps == nil {
		return nil
	}
	stepMap, ok := steps.(map[string]any)
	if !ok {
		return []string{fmt.Sprintf(`steps must be an object mapping each step name to its step; got %s`, jsonKind(steps))}
	}
	names := make([]string, 0, len(stepMap))
	for name := range stepMap {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, stepShapeErrors(name, stepMap[name])...)
	}
	return out
}

func stepShapeErrors(name string, v any) []string {
	path := "steps." + pathSegment(name)
	if v == nil {
		return nil
	}
	step, ok := v.(map[string]any)
	if !ok {
		return []string{fmt.Sprintf(`%s must be an object {"name": %s, "functionaries": [...], "attestations": [...]}; got %s`,
			path, strconv.Quote(name), jsonKind(v))}
	}
	out := listShapeErrors(path+".functionaries", step["functionaries"], shapeFunctionary, nil)
	return append(out, listShapeErrors(path+".attestations", step["attestations"], shapeAttestation, attestationShapeErrors)...)
}

func attestationShapeErrors(path string, att map[string]any) []string {
	return listShapeErrors(path+".regopolicies", att["regopolicies"], shapeRegoPolicy, regoPolicyShapeErrors)
}

func regoPolicyShapeErrors(path string, rp map[string]any) []string {
	var out []string
	if v, ok := rp["name"]; ok && v != nil {
		if _, isString := v.(string); !isString {
			out = append(out, fmt.Sprintf("%s.name must be a string; got %s", path, jsonKind(v)))
		}
	}
	if v, ok := rp["module"]; ok && v != nil {
		if _, isString := v.(string); !isString {
			out = append(out, fmt.Sprintf("%s.module must be a string (the rego module, base64-encoded); got %s", path, jsonKind(v)))
		}
	}
	return out
}

// listShapeErrors checks a list of objects: the list itself must be an array
// (or null/absent), each element an object (or null), and each object is
// handed to inner.
func listShapeErrors(path string, v any, elemShape string, inner func(string, map[string]any) []string) []string {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return []string{fmt.Sprintf("%s must be an array of objects [%s]; got %s", path, elemShape, jsonKind(v))}
	}
	var out []string
	for i, e := range list {
		elemPath := fmt.Sprintf("%s[%d]", path, i)
		if e == nil {
			continue
		}
		obj, ok := e.(map[string]any)
		if !ok {
			out = append(out, fmt.Sprintf("%s must be an object %s; got %s", elemPath, elemShape, jsonKind(e)))
			continue
		}
		if inner != nil {
			out = append(out, inner(elemPath, obj)...)
		}
	}
	return out
}

func jsonKind(v any) string {
	switch v.(type) {
	case string:
		return "a string"
	case float64, json.Number:
		return "a number"
	case bool:
		return "a boolean"
	case []any:
		return "an array"
	case map[string]any:
		return "an object"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// pathSegment prints a step name as written when it is plain, and quoted when
// it holds anything a terminal might act on or a reader might misparse.
func pathSegment(name string) string {
	plain := name != ""
	for _, r := range name {
		if !unicode.IsPrint(r) || r == '.' || r == '[' || r == '"' || unicode.IsSpace(r) {
			plain = false
			break
		}
	}
	if plain {
		return name
	}
	return strconv.Quote(name)
}

// explainDecodeError returns err with the shape explanation in front when the
// payload has one, and err unchanged otherwise.
func explainDecodeError(payload []byte, err error) error {
	if err == nil {
		return nil
	}
	shape := ShapeErrors(payload)
	if len(shape) == 0 {
		return err
	}
	return fmt.Errorf("%s (decoder: %w)", strings.Join(shape, "; "), err)
}
