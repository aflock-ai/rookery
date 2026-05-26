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

package detection

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gobwas/glob"
)

// evalProductGlob matches if any product path matches any of the
// given glob patterns. Patterns are forward-slash normalized; product
// paths are already normalized by the product attestor's caller.
func evalProductGlob(patterns []string, ctx *EvalContext) EvalResult {
	if len(patterns) == 0 {
		return EvalResult{State: StateNoMatch, Rule: "product_glob:empty"}
	}
	if len(ctx.Products) == 0 {
		return EvalResult{State: StateNoMatch, Rule: "product_glob:no-products"}
	}

	compiled := make([]glob.Glob, 0, len(patterns))
	for _, p := range patterns {
		g, err := glob.Compile(p, '/')
		if err != nil {
			return EvalResult{State: StateNoMatch, Rule: "product_glob:invalid:" + err.Error()}
		}
		compiled = append(compiled, g)
	}

	for path := range ctx.Products {
		normalized := filepath.ToSlash(path)
		for _, g := range compiled {
			if matched, _ := safeGlobMatch(g, normalized); matched {
				return EvalResult{
					State: StateMatch,
					Rule:  "product_glob:" + strings.Join(patterns, ",") + ":" + path,
				}
			}
		}
	}
	return EvalResult{State: StateNoMatch, Rule: "product_glob:miss"}
}

// evalProductMime is reserved syntax. Live MIME sniffing would require
// re-opening every product file at planning time, which conflicts with
// the planning-step performance budget. The intended implementation
// will sniff lazily and cache; for now this predicate always misses so
// detector.yamls that reference it compile but don't match. This keeps
// the schema stable for forward compatibility. The ctx parameter is
// retained to keep the evaluator signature uniform across leaves.
func evalProductMime(mime string, _ *EvalContext) EvalResult {
	if mime == "" {
		return EvalResult{State: StateNoMatch, Rule: "product_mime:empty"}
	}
	return EvalResult{State: StateNoMatch, Rule: "product_mime:reserved:" + mime}
}

// evalMaterialChanged matches if the named path appears in the
// materials-diff list. Path matching is filepath.ToSlash-normalized on
// both sides for cross-platform consistency. The predicate accepts
// either an exact path or a glob (gobwas/glob detects the difference
// automatically by checking for meta characters).
func evalMaterialChanged(path string, ctx *EvalContext) EvalResult {
	if path == "" {
		return EvalResult{State: StateNoMatch, Rule: "material_changed:empty"}
	}
	if len(ctx.MaterialsDiff) == 0 {
		return EvalResult{State: StateNoMatch, Rule: "material_changed:no-diff"}
	}

	want := filepath.ToSlash(path)
	if strings.ContainsAny(want, "*?[") {
		g, err := glob.Compile(want, '/')
		if err != nil {
			return EvalResult{State: StateNoMatch, Rule: "material_changed:invalid:" + err.Error()}
		}
		for _, m := range ctx.MaterialsDiff {
			ms := filepath.ToSlash(m)
			if matched, _ := safeGlobMatch(g, ms); matched {
				return EvalResult{State: StateMatch, Rule: "material_changed:" + path + ":" + m}
			}
		}
		return EvalResult{State: StateNoMatch, Rule: "material_changed:miss:" + path}
	}

	for _, m := range ctx.MaterialsDiff {
		if filepath.ToSlash(m) == want {
			return EvalResult{State: StateMatch, Rule: "material_changed:" + path}
		}
	}
	return EvalResult{State: StateNoMatch, Rule: "material_changed:miss:" + path}
}

// evalExitCode matches against the command's exit code using one of
// the eq / ne / in selectors. The validator guarantees exactly one is
// set.
func evalExitCode(leaf *ExitCodeLeaf, ctx *EvalContext) EvalResult {
	if leaf == nil {
		return EvalResult{State: StateNoMatch, Rule: "exit_code:empty"}
	}
	got := ctx.ExitCode
	if leaf.Eq != nil {
		if got == *leaf.Eq {
			return EvalResult{State: StateMatch, Rule: fmt.Sprintf("exit_code:eq:%d", *leaf.Eq)}
		}
		return EvalResult{State: StateNoMatch, Rule: fmt.Sprintf("exit_code:eq:miss:%d!=%d", got, *leaf.Eq)}
	}
	if leaf.Ne != nil {
		if got != *leaf.Ne {
			return EvalResult{State: StateMatch, Rule: fmt.Sprintf("exit_code:ne:%d", *leaf.Ne)}
		}
		return EvalResult{State: StateNoMatch, Rule: fmt.Sprintf("exit_code:ne:miss:%d", got)}
	}
	for _, v := range leaf.In {
		if got == v {
			return EvalResult{State: StateMatch, Rule: fmt.Sprintf("exit_code:in:%d", got)}
		}
	}
	return EvalResult{State: StateNoMatch, Rule: fmt.Sprintf("exit_code:in:miss:%d", got)}
}
