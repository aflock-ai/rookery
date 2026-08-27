// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package product

import (
	"fmt"
	"sort"
	"strings"
)

// maxContributorsShown bounds the "largest contributors" list. Three is enough
// to identify the offender without turning a diagnostic into a wall of paths.
const maxContributorsShown = 3

// dominantChildShare is how much of a directory's product count must sit in a
// single child before the report descends into that child. A `web/` group that
// is 99% `web/node_modules/` should be reported as `web/node_modules/`, because
// that is the directory the operator would actually exclude — but a `src/` group
// spread evenly across ten children should stay reported as `src/`.
const dominantChildShare = 0.8

// maxContributorDepth stops the descent from printing an entire path. Three
// segments names a dependency or build directory in every layout we have seen.
const maxContributorDepth = 3

// checkProductCount refuses a run whose recorded product set is too large to
// produce a usable attestation.
//
// This is deliberately an ERROR at attest time rather than a warning or a
// silent truncation. Truncating would sign an attestation that claims to
// describe the build's products while omitting most of them — a false claim,
// and the worst of the three options. Warning would leave the operator to
// discover the problem at push time, which is where it was discovered before
// this check existed, several layers from the cause.
func (a *Attestor) checkProductCount(pairs []productPair) error {
	if a.maxProducts <= 0 || len(pairs) <= a.maxProducts {
		return nil
	}

	paths := make([]string, 0, len(pairs))
	for _, p := range pairs {
		paths = append(paths, p.normalized)
	}
	contributors := topContributors(paths)

	var b strings.Builder
	fmt.Fprintf(&b, "product attestor: %d files matched, which exceeds the limit of %d.\n\n",
		len(pairs), a.maxProducts)
	b.WriteString("An attestation this large is refused by the evidence store rather than\n")
	b.WriteString("verified, so the run is stopped here where the cause is still visible.\n")
	b.WriteString("A product set this size normally means a dependency or build directory\n")
	b.WriteString("is being recorded as deliverables.\n")

	if len(contributors) > 0 {
		b.WriteString("\nLargest contributors:\n")
		unsafe := 0
		for _, c := range contributors {
			// An unsafe name is still the diagnostic the operator needs, so it is
			// always shown -- as a QUOTED Go literal, which escapes control
			// characters instead of letting them reach the terminal, and which
			// reads unambiguously as data rather than as something to paste.
			if shellSafePath(c.dir) {
				fmt.Fprintf(&b, "  %8d  %s/\n", c.count, c.dir)
				continue
			}
			unsafe++
			fmt.Fprintf(&b, "  %8d  %q  (unusual characters -- quoted, and left out of the command below)\n",
				c.count, c.dir)
		}
		if glob := suggestedExcludeGlob(contributors); glob != "" {
			fmt.Fprintf(&b, "\nExclude them with:\n  --exclude-glob '%s'\n", glob)
		}
		if unsafe > 0 {
			fmt.Fprintf(&b, "\n%d of these contain characters a shell would act on, so no ready-made\n"+
				"command is offered for them. Write the pattern yourself after checking the name.\n", unsafe)
		}
	}

	b.WriteString("\nOr raise the limit deliberately with --max-products=<n> (0 disables it).")
	return fmt.Errorf("%s", b.String())
}

type contributor struct {
	dir   string
	count int
}

// shellSafePath reports whether a path may be interpolated into the suggested
// command.
//
// THIS IS AN ALLOWLIST ON PURPOSE. The paths come from the build's own output,
// which in a supply-chain tool is data an attacker may influence, and the output
// is a command we invite the operator to paste into a shell. A blocklist of
// "dangerous characters" is the wrong shape: it has to be complete to be
// correct, and the input it must catch is by construction the unusual one nobody
// enumerated. So: letters, digits, and the four punctuation characters real
// directory names need. Everything else is data, not command text.
//
// A leading '-' is rejected separately. It is shell-inert, but it turns the path
// into something the receiving program may read as a flag.
func shellSafePath(p string) bool {
	if p == "" || strings.HasPrefix(p, "-") {
		return false
	}
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '/':
		default:
			return false
		}
	}
	// ".." would let the pasted suggestion reach outside the workspace.
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// suggestedExcludeGlob renders a copy-pasteable glob covering the contributors
// that are safe to interpolate. It returns "" when none are, so the caller omits
// the command rather than emitting one the operator must audit before using.
//
// A single directory gets a plain pattern; several get the brace form, which is
// what gobwas/glob accepts and what the exclude-glob flag already compiles.
func suggestedExcludeGlob(cs []contributor) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		if !shellSafePath(c.dir) {
			continue
		}
		parts = append(parts, c.dir+"/**")
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	default:
		return "{" + strings.Join(parts, ",") + "}"
	}
}

// topContributors ranks directories by how many products they hold.
//
// It reports the directory an operator would actually exclude, which is not
// always the top-level one: a monorepo whose products are 40,000 files under
// `web/node_modules/` should be told `web/node_modules`, not `web`. So a group
// descends into its child whenever that child holds nearly all of it.
//
// One pass builds every directory prefix count up to maxContributorDepth, and
// the descent then reads that map. This runs on the pathological input by
// construction — the check exists for the 83,000-file case, so anything
// quadratic in the path count would hang exactly when it is needed.
func topContributors(paths []string) []contributor {
	// prefixCount[d] = how many paths live under directory d.
	prefixCount := make(map[string]int, len(paths))
	// children[d] = the set of immediate child directories of d that hold products.
	children := make(map[string]map[string]struct{})

	for _, p := range paths {
		segs := strings.Split(p, "/")
		// segs[len-1] is the file name, so directories run to len(segs)-1.
		limit := min(len(segs)-1, maxContributorDepth)
		for depth := 1; depth <= limit; depth++ {
			dir := strings.Join(segs[:depth], "/")
			prefixCount[dir]++
			if depth > 1 {
				parent := strings.Join(segs[:depth-1], "/")
				if children[parent] == nil {
					children[parent] = make(map[string]struct{})
				}
				children[parent][dir] = struct{}{}
			}
		}
	}

	// Rank the top-level directories, then descend each one.
	out := make([]contributor, 0, 8)
	for dir, n := range prefixCount {
		if strings.Contains(dir, "/") {
			continue // only depth-1 roots seed the ranking
		}
		label, count := descend(dir, n, prefixCount, children)
		out = append(out, contributor{dir: label, count: count})
	}

	// Count descending, then path ascending so the output is deterministic
	// for equal counts — an error message that reorders between runs is a
	// diff nobody can read.
	sort.Slice(out, func(i, j int) bool {
		if out[i].count != out[j].count {
			return out[i].count > out[j].count
		}
		return out[i].dir < out[j].dir
	})
	if len(out) > maxContributorsShown {
		out = out[:maxContributorsShown]
	}
	return out
}

// descend walks from dir into its dominant child for as long as one child holds
// at least dominantChildShare of the current directory's products.
func descend(dir string, count int, prefixCount map[string]int, children map[string]map[string]struct{}) (string, int) {
	for depth := 1; depth < maxContributorDepth; depth++ {
		best, bestN := "", 0
		for child := range children[dir] {
			if n := prefixCount[child]; n > bestN || (n == bestN && child < best) {
				best, bestN = child, n
			}
		}
		if best == "" || count == 0 || float64(bestN)/float64(count) < dominantChildShare {
			break
		}
		dir, count = best, bestN
	}
	return dir, count
}
