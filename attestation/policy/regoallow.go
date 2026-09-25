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
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/ast"
)

// The rego engine is deny-only: it queries each module's `deny` and passes a
// collection when no module denies. `allow` is never queried. A module that
// defines allow without a deny that depends on it therefore reads as if allow
// gated the step when it does not, and `default allow := false` over an empty
// deny passes everything (#9820 E3). Such a module set is refused, before
// evaluation and at `cilock policy validate`. A deny depends on allow when
// allow is reachable from it, directly (`deny[msg] { not allow }`) or through
// helper rules.

var (
	allowCheckMu    sync.Mutex
	allowCheckCache = map[[32]byte]error{}
)

// CheckRegoAllowUsed returns an error when a module in the set defines `allow`
// and no deny rule reaches it. A set that does not compile returns nil; the
// evaluator and the syntax check refuse it with the compiler's error.
func CheckRegoAllowUsed(policies []RegoPolicy) error {
	key := lintSetKey(policies)
	allowCheckMu.Lock()
	cached, ok := allowCheckCache[key]
	allowCheckMu.Unlock()
	if ok {
		return cached
	}
	err := checkAllowUsed(policies)
	allowCheckMu.Lock()
	defer allowCheckMu.Unlock()
	if len(allowCheckCache) < failOpenLintCacheMax {
		allowCheckCache[key] = err
	}
	return err
}

func checkAllowUsed(policies []RegoPolicy) error {
	compiled, names, err := compileRegoSet(policies)
	if err != nil {
		return nil //nolint:nilerr // the evaluator reports the compile error itself
	}
	reached := newRuleIndex(compiled).polarities(compiled)
	for i, m := range compiled {
		defines := false
		for _, top := range m.Rules {
			if ruleNamed(top, "allow") {
				defines = true
			}
		}
		if defines && !reachedRuleRefers(reached, m.Package.Path.Append(ast.StringTerm("allow"))) {
			return fmt.Errorf("rego module %q defines `allow`, but no deny rule depends on it: the engine only queries deny, so allow has no effect and this module passes whatever allow says (#9820). Express the condition in deny, for example `deny[msg] { not allow; msg := \"...\" }`, or remove allow", names[i])
		}
	}
	return nil
}

// reachedRuleRefers reports whether any rule deny reaches (deny included)
// refers to path. A reference, not reachability of the allow rule itself, is
// the test: the reachability walk does not visit `default` rules, and
// `default allow := false` with `deny { not allow }` is the canonical gate.
func reachedRuleRefers(reached map[*ast.Rule][]polarity, path ast.Ref) bool {
	for rule, pols := range reached {
		if len(pols) == 0 {
			continue
		}
		found := false
		ast.WalkRefs(rule, func(ref ast.Ref) bool {
			// A read of allow itself (or under it), or of a document that
			// contains it: `object.get(data.gate, "allow", false)` reads
			// data.gate, and `data` alone reads everything.
			if ref.HasPrefix(path) || path.HasPrefix(ref.GroundPrefix()) {
				found = true
			}
			return found
		})
		if found {
			return true
		}
	}
	return false
}

func ruleNamed(rule *ast.Rule, name string) bool {
	ref := rule.Head.Ref()
	return len(ref) > 0 && ref[0].Value.Compare(ast.Var(name)) == 0
}
