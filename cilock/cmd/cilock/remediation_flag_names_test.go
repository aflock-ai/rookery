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

// jade:ring local
//
// Deterministic pre-push regression coverage: it parses source and builds the
// cobra tree in-process — no network, no deployed artifact, no fixtures.

package main

// Guard for the class of defect in #9230: an attestor's diagnostic offers the
// operator a command line, and the flag it names is one the CLI's own parser
// rejects. The cost is not cosmetic — the product-overflow message fires at the
// END of a run, so a wrong flag name costs a whole gate cycle before the
// operator learns the suggestion was never valid.
//
// The class exists because there are TWO names for the same knob. An attestor
// registers a config option under a bare name ("exclude-glob"); the CLI
// namespaces every attestor option when it turns it into a flag, so the parser
// only ever sees "attestor-product-exclude-glob". Nothing connected the two,
// so a message could name either and the compiler was happy.
//
// These tests quantify over collections rather than over the two strings that
// were wrong, because an assertion on two literals does not stop the third:
//
//	TestAttestorOptionFlagNamesAreRegistered — for EVERY registered attestor and
//	  EVERY option it registers, the name registry.AttestorFlagName() produces is
//	  a flag the CLI actually accepts. This is what makes the helper safe to use.
//	TestAttestorMessagesNameRealFlags — for EVERY attestor the shipped binary
//	  registers, every flag name appearing in a user-facing message in that
//	  attestor's own package is checked two ways: a namespaced "--attestor-…"
//	  name must exist on the CLI, and a BARE option name must not appear at all
//	  (it is the internal spelling, never the one the parser takes).
//
// This file lives in package main on purpose, matching main_test.go: the set of
// attestors under test is exactly the set the shipped binary blank-imports.
//
// Two limits, stated rather than left to be discovered:
//
//   - Scope is message TEXT, not comments. A comment naming a stale flag is
//     misleading but nobody pastes it into a shell, and attestors quote other
//     tools' flags in comments constantly (measured: 179 flag-shaped tokens in
//     attestor comments, against 24 in messages), so a comment rule would be
//     mostly false positives.
//   - Change detection does not select this lane on a plugin-only edit.
//     `subtrees/rookery/plugins/attestors/` maps to the "rookery" service,
//     whose tests run in subtrees/rookery/attestation (#9052); the "cilock"
//     service's include is subtrees/rookery/cilock/ only. Adding the plugin
//     tree to that include is rejected by ci/changedetect's own gating-coverage
//     invariant — a service may not claim a module its test dir cannot test.
//     So this guard runs on a cilock change and in a full `jade test`, not on
//     an attestor-only change. Closing that needs the per-plugin gated
//     services #9052 tracks, not an exemption here.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/cilock/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// rookeryModulePath prefixes every in-repo package path, and is how a factory's
// runtime symbol name is turned back into a directory on disk.
const rookeryModulePath = "github.com/aflock-ai/rookery/"

// attestorCommands are the commands that instantiate attestors, and therefore
// the commands whose flag set an attestor's remediation may name. Both register
// the namespaced attestor options (see cilock/internal/options.addFlags).
var attestorCommands = []string{"run", "attest"}

// flagTokenRe matches a long flag as it appears inside message text.
//
// Deliberately lowercase-only and dash-separated with no trailing dash, which
// is the shape every cilock flag has. That excludes PEM banners ("--BEGIN"),
// and it makes a wildcard reference like "--attestor-*-export" match only
// "--attestor", which carries no "attestor-" prefix and is therefore not
// mistaken for a concrete flag claim.
var flagTokenRe = regexp.MustCompile(`--[a-z][a-z0-9]*(?:-[a-z0-9]+)*`)

// messageSinkSelectors are the call targets whose string arguments end up in
// front of a human. Scanning sinks rather than every string literal is what
// keeps this honest: attestors legitimately mention OTHER programs' flags in
// their own argv construction ("docker run --cap-add=BPF", "pack build
// --report-output-dir"), and those are data, not a claim about cilock's parser.
// Message text is the only place where naming a flag is a promise.
var messageSinkSelectors = map[string]bool{
	"Errorf": true, "Sprintf": true, "Fprintf": true,
	"Sprint": true, "Sprintln": true, "Fprint": true, "Fprintln": true,
	"Printf": true, "Println": true, "Print": true,
	"WriteString": true,
	"Warnf":       true, "Infof": true, "Debugf": true,
	"Warn": true, "Info": true, "Debug": true, "Error": true,
}

// flagToken is one long-flag name found in one message string.
type flagToken struct {
	name string // without the leading "--"
	file string
	line int
}

// isMessageSink reports whether a call's string arguments reach a human.
func isMessageSink(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if id, ok := sel.X.(*ast.Ident); ok && id.Name == "errors" && sel.Sel.Name == "New" {
		return true
	}
	return messageSinkSelectors[sel.Sel.Name]
}

// scanMessageFlagTokens parses one Go source file and returns every long-flag
// name appearing in a string literal that reaches a message sink.
//
// src may be nil, in which case the file is read from disk; passing source
// directly is what lets the test prove the scanner still detects a planted
// violation (see TestScannerDetectsAPlantedViolation).
func scanMessageFlagTokens(fset *token.FileSet, path string, src any) ([]flagToken, error) {
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}

	var found []flagToken
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isMessageSink(call) {
			return true
		}
		for _, arg := range call.Args {
			ast.Inspect(arg, func(m ast.Node) bool {
				lit, ok := m.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				text, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return true
				}
				for _, tok := range flagTokenRe.FindAllString(text, -1) {
					found = append(found, flagToken{
						name: strings.TrimPrefix(tok, "--"),
						file: path,
						line: fset.Position(lit.Pos()).Line,
					})
				}
				return true
			})
		}
		return true
	})
	return found, nil
}

// rookeryRoot resolves the repository root of the rookery module tree from this
// package's directory, and fails closed rather than silently scanning nothing.
func rookeryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve rookery root: %v", err)
	}
	// Sentinel: a directory that exists in every checkout of this tree.
	if _, err := os.Stat(filepath.Join(root, "plugins", "attestors")); err != nil {
		t.Fatalf("rookery root %q does not look like a rookery checkout (plugins/attestors missing: %v)", root, err)
	}
	return root
}

// factoryPackagePath recovers the import path of the package that registered an
// attestor, by reading the factory function's own symbol name. This is the only
// mapping that cannot drift: an attestor's registered NAME and its directory
// differ in practice ("command-run" lives in commandrun/), so guessing the
// directory from the name would quietly scan the wrong files.
func factoryPackagePath[T any](factory registry.FactoryFunc[T]) string {
	fn := runtime.FuncForPC(reflect.ValueOf(factory).Pointer())
	if fn == nil {
		return ""
	}
	// e.g. github.com/aflock-ai/rookery/plugins/attestors/product.init.1.func1
	full := fn.Name()
	slash := strings.LastIndex(full, "/")
	if slash < 0 {
		return ""
	}
	last := full[slash+1:]
	dot := strings.Index(last, ".")
	if dot < 0 {
		return ""
	}
	return full[:slash+1] + last[:dot]
}

// attestorPackageDir maps a registered attestor to the directory holding its
// source, or "" when the attestor is not part of this module tree.
func attestorPackageDir(root string, entry registry.Entry[attestation.Attestor]) string {
	pkg := factoryPackagePath(entry.Factory)
	rel, ok := strings.CutPrefix(pkg, rookeryModulePath)
	if !ok || rel == "" {
		return ""
	}
	return filepath.Join(root, filepath.FromSlash(rel))
}

// attestorCommandFlags is the set of long flag names accepted by the commands
// that run attestors. Ground truth: the real cobra tree, not a restatement of
// how flags are supposed to be named.
func attestorCommandFlags(t *testing.T) map[string]bool {
	t.Helper()
	root := cli.New()
	flags := make(map[string]bool)
	collect := func(fs *pflag.FlagSet) {
		fs.VisitAll(func(f *pflag.Flag) { flags[f.Name] = true })
	}
	collect(root.PersistentFlags())

	seen := make(map[string]bool)
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			for _, want := range attestorCommands {
				if sub.Name() == want {
					seen[want] = true
					collect(sub.Flags())
					collect(sub.PersistentFlags())
				}
			}
			walk(sub)
		}
	}
	walk(root)

	for _, want := range attestorCommands {
		if !seen[want] {
			t.Fatalf("command %q not found in the cilock command tree; this test would compare against an empty flag set", want)
		}
	}
	if len(flags) == 0 {
		t.Fatal("collected zero flags from the cilock command tree")
	}
	return flags
}

// TestAttestorOptionFlagNamesAreRegistered is the universal that makes
// registry.AttestorFlagName safe to build remediation text with: for every
// attestor the binary ships and every option it registers, the name the helper
// produces is a flag the CLI really accepts.
//
// Worth being precise about what this does and does not prove, because the
// helper and the CLI's flag registration now share one implementation:
//
//   - It is NOT tautological. Verified by mutation: changing only
//     AttestorFlagName's prefix (leaving registration on FlagName) turns all 34
//     option→flag pairs red. The two paths are pinned together, not identical.
//   - It catches a registered option that produces no flag at all. addFlags has
//     a `default:` arm that only logs, so an option whose type the switch does
//     not handle is silently flagless while the helper still names it.
//   - An attestor module's own tests cannot do this job. They live in a module
//     that cannot import the CLI, so they can only assert "the message says
//     what the helper says" — true even when the helper has drifted. That is
//     why this test is here and not in plugins/attestors/product.
func TestAttestorOptionFlagNamesAreRegistered(t *testing.T) {
	flags := attestorCommandFlags(t)
	entries := attestation.RegistrationEntries()
	if len(entries) == 0 {
		t.Fatal("no attestors registered; the binary's blank imports are missing")
	}

	checked := 0
	for _, entry := range entries {
		for _, opt := range entry.Options {
			name := registry.AttestorFlagName(entry.Name, opt.Name())
			checked++
			if !flags[name] {
				t.Errorf("attestor %q option %q maps to flag --%s, which no attestor-running command registers",
					entry.Name, opt.Name(), name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no attestor options examined; the registry exposed none, so this test proved nothing")
	}
	t.Logf("checked %d option→flag names across %d attestors", checked, len(entries))
}

// TestAttestorMessagesNameRealFlags is the guard the issue asked for: every flag
// name printed in an attestor's user-facing messages must be a flag the CLI
// registers.
//
// Two rules, both quantified over the shipped attestor set rather than over
// known-bad strings:
//
//	namespaced — a "--attestor-…" name must exist on an attestor-running command.
//	bare       — an attestor must never print "--<its own option name>"; that is
//	             the internal registration spelling, and the parser rejects it.
//	             This is precisely the #9230 defect.
func TestAttestorMessagesNameRealFlags(t *testing.T) {
	root := rookeryRoot(t)
	flags := attestorCommandFlags(t)
	entries := attestation.RegistrationEntries()
	if len(entries) == 0 {
		t.Fatal("no attestors registered; the binary's blank imports are missing")
	}

	// dir → attestor name → bare option names it registers.
	type owner struct {
		attestor string
		option   string
	}
	bareOptionsByDir := make(map[string][]owner)
	dirs := make(map[string]bool)
	for _, entry := range entries {
		dir := attestorPackageDir(root, entry)
		if dir == "" {
			t.Errorf("attestor %q: could not resolve its source directory from its factory symbol", entry.Name)
			continue
		}
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("attestor %q: resolved source directory %q does not exist: %v", entry.Name, dir, err)
			continue
		}
		dirs[dir] = true
		for _, opt := range entry.Options {
			bareOptionsByDir[dir] = append(bareOptionsByDir[dir], owner{attestor: entry.Name, option: opt.Name()})
		}
	}
	if len(dirs) == 0 {
		t.Fatal("resolved zero attestor source directories; nothing would be scanned")
	}

	sorted := make([]string, 0, len(dirs))
	for dir := range dirs {
		sorted = append(sorted, dir)
	}
	sort.Strings(sorted)

	fset := token.NewFileSet()
	filesScanned, tokensSeen := 0, 0
	for _, dir := range sorted {
		goFiles, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatalf("glob %q: %v", dir, err)
		}
		for _, path := range goFiles {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			found, err := scanMessageFlagTokens(fset, path, nil)
			if err != nil {
				t.Errorf("parse %s: %v", path, err)
				continue
			}
			filesScanned++
			tokensSeen += len(found)

			for _, tok := range found {
				rel, relErr := filepath.Rel(root, tok.file)
				if relErr != nil {
					rel = tok.file
				}
				where := fmt.Sprintf("%s:%d", rel, tok.line)

				// Rule 1: a namespaced name must be real.
				if strings.HasPrefix(tok.name, registry.AttestorFlagPrefix+"-") && !flags[tok.name] {
					t.Errorf("%s: message names --%s, which no attestor-running command registers.\n"+
						"\tBuild the name with registry.AttestorFlagName(<attestor>, <option>) instead of typing it.", where, tok.name)
					continue
				}

				// Rule 2: a bare option name is the internal spelling; the parser
				// only ever sees the namespaced form.
				for _, own := range bareOptionsByDir[dir] {
					if tok.name != own.option {
						continue
					}
					t.Errorf("%s: message names --%s, but that is attestor %q's internal OPTION name — "+
						"the CLI registers it as --%s, and rejects --%s as an unknown flag.\n"+
						"\tBuild the name with registry.AttestorFlagName(%q, %q).",
						where, tok.name, own.attestor,
						registry.AttestorFlagName(own.attestor, own.option), tok.name,
						own.attestor, own.option)
				}
			}
		}
	}

	// Positive controls. A scan that reached no files, or found no flag names at
	// all, is indistinguishable from a clean tree unless it is asserted against.
	if filesScanned == 0 {
		t.Fatal("scanned zero files; this test proved nothing about any message")
	}
	if tokensSeen == 0 {
		t.Fatal("found zero flag names in any attestor message; the extractor is broken, " +
			"not the tree (attestors are known to name flags such as --attestor-vex-file)")
	}
	t.Logf("scanned %d files across %d attestor packages, %d flag names in messages", filesScanned, len(dirs), tokensSeen)
}

// TestScannerDetectsAPlantedViolation mutation-tests the guard above. Without
// it, a scanner that silently extracted nothing would report a green tree
// forever, which is the failure mode the positive controls above only partly
// cover: they prove SOMETHING was found, not that the #9230 shape is found.
func TestScannerDetectsAPlantedViolation(t *testing.T) {
	const planted = `package product

import "fmt"

func remediate(glob string) error {
	return fmt.Errorf("Exclude them with:\n  --exclude-glob '%s'\n", glob)
}
`
	fset := token.NewFileSet()
	found, err := scanMessageFlagTokens(fset, "planted.go", planted)
	if err != nil {
		t.Fatalf("parse planted source: %v", err)
	}

	names := make([]string, 0, len(found))
	for _, tok := range found {
		names = append(names, tok.name)
	}
	if !slices.Contains(names, "exclude-glob") {
		t.Fatalf("scanner missed the planted bare option name; got %v", names)
	}

	// And the inverse: a flag named in argv construction rather than message
	// text must NOT be reported, or the guard would fire on every attestor that
	// shells out to another tool.
	const argv = `package buildpacks

import "os/exec"

func run() *exec.Cmd {
	args := []string{"--cap-add=BPF"}
	return exec.Command("docker", args...)
}
`
	found, err = scanMessageFlagTokens(fset, "argv.go", argv)
	if err != nil {
		t.Fatalf("parse argv source: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("scanner reported argv flags as message text: %v", found)
	}
}
