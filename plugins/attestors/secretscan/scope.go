// Copyright 2026 The Rookery Contributors
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

// Package secretscan provides functionality for detecting secrets and sensitive information.
// This file (scope.go) decides WHICH files and attestations a scan reads (#9313).
package secretscan

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/gobwas/glob"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// ScopeFiles names which set of files a scan reads.
type ScopeFiles string

const (
	// ScopeProducts scans the products recorded by earlier attestors. This is
	// the only behaviour the attestor had before scope existed, and the default.
	ScopeProducts ScopeFiles = "products"
	// ScopeDiff scans the products plus everything that changed since the
	// merge-base of a git ref and HEAD, in all three places a path can carry
	// bytes: what the commits hold, what the index has staged, and what is on
	// disk. Every tracked file whose change leaves something to read (added,
	// modified, type-changed — only deletions are left out), and untracked
	// files that are not ignored.
	// It answers the push-gate question, "did this change introduce a
	// secret", without re-reading a tree that was already scanned when it was
	// pushed.
	ScopeDiff ScopeFiles = "diff"
	// ScopeTree scans the products plus every regular file under the working
	// directory, except anything under a .git directory.
	ScopeTree ScopeFiles = "tree"

	// diffScopePrefix is the spelling of ScopeDiff on the command line:
	// "diff:<base-ref>".
	diffScopePrefix = "diff:"
)

// scopeSpec is the parsed form of the scope option.
type scopeSpec struct {
	Files   ScopeFiles
	BaseRef string
}

// parseScope parses the scope option. It is called when the option is set so
// a typo fails the run before anything is scanned, and again in Attest so a
// value set programmatically gets the same check.
func parseScope(s string) (scopeSpec, error) {
	switch {
	case s == string(ScopeProducts):
		return scopeSpec{Files: ScopeProducts}, nil
	case s == string(ScopeTree):
		return scopeSpec{Files: ScopeTree}, nil
	case strings.HasPrefix(s, diffScopePrefix):
		ref := strings.TrimPrefix(s, diffScopePrefix)
		if ref == "" {
			return scopeSpec{}, fmt.Errorf("secretscan scope %q: diff needs a base ref, e.g. diff:origin/main", s)
		}
		return scopeSpec{Files: ScopeDiff, BaseRef: ref}, nil
	default:
		return scopeSpec{}, fmt.Errorf("secretscan scope %q: want %s, %s, or %s<base-ref>", s, ScopeProducts, ScopeTree, diffScopePrefix)
	}
}

// ScanScope is recorded in the predicate whenever the operator narrowed or
// widened the scan from its default, so a verifier can see exactly what the
// findings cover. It is absent on a default scan, which keeps the predicate
// of every existing user byte-identical.
type ScanScope struct {
	// Files is which set of files was read: products, diff or tree.
	Files ScopeFiles `json:"files"`
	// BaseRef is the ref the operator named for a diff scan, as typed.
	BaseRef string `json:"baseRef,omitempty"`
	// BaseCommit is the commit the diff was taken against: the merge-base of
	// BaseRef and HEAD, resolved at scan time.
	BaseCommit string `json:"baseCommit,omitempty"`
	// Attestations is whether prior attestors' JSON (including command-run
	// stdout and stderr) was scanned.
	Attestations bool `json:"attestations"`
	// IncludeGlob and ExcludeGlob are the path filters applied to every file
	// considered, in the same glob dialect as --attestor-product-include-glob.
	IncludeGlob string `json:"includeGlob,omitempty"`
	ExcludeGlob string `json:"excludeGlob,omitempty"`
	// ProductDigestMismatches lists products whose bytes at scan time were
	// not the bytes the product attestor recorded. The subject for such a
	// product carries the digest of what was SCANNED — a signed claim binds
	// to the bytes this attestor observed, never to another attestor's record
	// — and the disagreement is stated here rather than quietly correlated
	// away, because "the file changed between the product snapshot and the
	// scan" is evidence a policy may want to deny on. Absent when every
	// product's bytes were what was recorded, which is the common case.
	ProductDigestMismatches []ProductDigestMismatch `json:"productDigestMismatches,omitempty"`
	// FilesScanned is how many sets of bytes the scan covered, which is
	// exactly the number of subjects: every product read, every diff or tree
	// file read off disk, and every committed or staged blob read out of the
	// object store whose bytes were not already scanned for that path.
	// Anything skipped as binary or over the size limit is neither counted nor
	// a subject, and identical bytes reached by two routes count once.
	FilesScanned int `json:"filesScanned"`
}

// ProductDigestMismatch is one product whose bytes at scan time were not the
// bytes the product attestor recorded. Both digests are stated so a verifier
// can see exactly what disagreed rather than being told only that something
// did.
type ProductDigestMismatch struct {
	// Path is the product key, so the entry lines up with the "product:<path>"
	// subject and with the product attestor's own record.
	Path string `json:"path"`
	// Recorded is the digest the product attestor published for this path.
	Recorded cryptoutil.DigestSet `json:"recordedDigest,omitempty"`
	// Scanned is the digest of the bytes secretscan read, which is also what
	// the subject carries.
	Scanned cryptoutil.DigestSet `json:"scannedDigest"`
}

// WithScope sets which files the scan reads: "products" (default), "tree",
// or "diff:<base-ref>". See ScopeFiles.
func WithScope(scope string) Option {
	return func(a *Attestor) { a.scope = scope }
}

// WithScanAttestations sets whether prior attestors' JSON is scanned
// (default true). The material inventory and command-run output live there;
// turning it off confines the scan to files.
func WithScanAttestations(scan bool) Option {
	return func(a *Attestor) { a.scanPriorAttestations = scan }
}

// WithIncludeGlob restricts the scan to paths matching the glob (default:
// everything). One pattern; use brace alternation for several.
func WithIncludeGlob(g string) Option {
	return func(a *Attestor) { a.includeGlob = g }
}

// WithExcludeGlob removes paths matching the glob from the scan (default:
// nothing). Exclude wins over include. One pattern; use brace alternation
// for several.
func WithExcludeGlob(g string) Option {
	return func(a *Attestor) { a.excludeGlob = g }
}

// scopeConfigOptions registers the four scope options under the attestor's
// flag namespace (--attestor-secretscan-<name>).
func scopeConfigOptions() []registry.Configurer {
	return []registry.Configurer{
		// Option: which files are scanned (default: the recorded products)
		registry.StringConfigOption(
			"scope",
			"Which files to scan: 'products' (the files earlier attestors recorded), 'tree' (every file under the working directory), or 'diff:<base-ref>' (products plus files changed since the merge-base of <base-ref> and HEAD, including untracked files)",
			defaultScope,
			func(a attestation.Attestor, scope string) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				if _, err := parseScope(scope); err != nil {
					return a, err
				}
				WithScope(scope)(secretscanAttestor)
				return secretscanAttestor, nil
			},
		),

		// Option: whether prior attestations are scanned (default: true)
		registry.BoolConfigOption(
			"scan-attestations",
			"Scan the JSON of attestors that ran earlier in this step, including command-run stdout and stderr; set false to scan files only",
			defaultScanAttestations,
			func(a attestation.Attestor, scan bool) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				WithScanAttestations(scan)(secretscanAttestor)
				return secretscanAttestor, nil
			},
		),

		// Option: path include glob (default: everything)
		registry.StringConfigOption(
			"include-glob",
			"Only scan paths matching this glob, relative to the working directory (one pattern; use brace alternation for several, e.g. '{src,cmd}/**')",
			defaultIncludeGlob,
			func(a attestation.Attestor, g string) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				WithIncludeGlob(g)(secretscanAttestor)
				return secretscanAttestor, nil
			},
		),

		// Option: path exclude glob (default: nothing)
		registry.StringConfigOption(
			"exclude-glob",
			"Never scan paths matching this glob, relative to the working directory; exclude wins over include (one pattern; use brace alternation for several, e.g. '{**/,}{vendor,node_modules}/**')",
			defaultExcludeGlob,
			func(a attestation.Attestor, g string) (attestation.Attestor, error) {
				secretscanAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a secretscan attestor", a)
				}

				WithExcludeGlob(g)(secretscanAttestor)
				return secretscanAttestor, nil
			},
		),
	}
}

// scopeIsDefault reports whether the operator left every scope option alone,
// in which case no ScanScope is recorded. defaultScanAttestations is true, so
// the field is tested directly.
func (a *Attestor) scopeIsDefault() bool {
	return a.scope == defaultScope && a.scanPriorAttestations &&
		a.includeGlob == defaultIncludeGlob && a.excludeGlob == defaultExcludeGlob
}

// compileScope parses the scope and compiles the globs. Any failure is a
// failure to observe: the run stops before anything is scanned rather than
// scanning something other than what the operator asked for.
func (a *Attestor) compileScope() (scopeSpec, error) {
	spec, err := parseScope(a.scope)
	if err != nil {
		return scopeSpec{}, err
	}
	a.compiledIncludeGlob = nil
	if a.includeGlob != "" {
		g, err := glob.Compile(a.includeGlob)
		if err != nil {
			return scopeSpec{}, fmt.Errorf("secretscan include-glob %q: %w", a.includeGlob, err)
		}
		a.compiledIncludeGlob = g
	}
	a.compiledExcludeGlob = nil
	if a.excludeGlob != "" {
		g, err := glob.Compile(a.excludeGlob)
		if err != nil {
			return scopeSpec{}, fmt.Errorf("secretscan exclude-glob %q: %w", a.excludeGlob, err)
		}
		a.compiledExcludeGlob = g
	}
	return spec, nil
}

// pathInScope applies the globs to a slash-separated path relative to the
// working directory. Exclude wins; include, when set, must match.
//
// A glob that panics mid-match (gobwas/glob can, on a pattern that compiled
// cleanly) is recorded as a scan error and the path is scanned anyway. The
// alternative is a file dropped from the scan by a decision nobody made,
// which is the same silence this file exists to prevent: with the guard on,
// the recorded error fails the run instead.
func (a *Attestor) pathInScope(rel string) bool {
	if a.compiledExcludeGlob != nil {
		matched, err := safeGlobMatch(a.compiledExcludeGlob, rel)
		if err != nil {
			a.scanErrors = append(a.scanErrors, fmt.Errorf("matching exclude-glob %q against %s: %w", a.excludeGlob, rel, err))
			return true
		}
		if matched {
			return false
		}
	}
	if a.compiledIncludeGlob != nil {
		matched, err := safeGlobMatch(a.compiledIncludeGlob, rel)
		if err != nil {
			a.scanErrors = append(a.scanErrors, fmt.Errorf("matching include-glob %q against %s: %w", a.includeGlob, rel, err))
			return true
		}
		return matched
	}
	return true
}

// productScopePath is the path a product's globs are matched against: the
// product key reduced to a slash-separated path relative to the working
// directory, which is what the include/exclude globs are documented against.
//
// Product keys are normally already relative, but a capture mode may record
// them absolute. An absolute key never matched a relative include glob, so
// scanProducts dropped it — and scanFiles then skipped it too, because it IS
// a product. The file was read by neither path and appeared nowhere in the
// evidence. Reducing both sides to the same spelling makes the hand-off
// exact in either direction: nothing scanned twice, nothing skipped by both.
//
// A key that does not sit under the working directory is returned unchanged.
// There is no relative spelling of it, and no working-tree listing can name
// it either, so there is nothing to hand off.
//
// wdSpellings comes from workingDirSpellings and is resolved once per scan by
// the caller, not once per key: it costs an EvalSymlinks, and a scan can carry
// thousands of products.
func productScopePath(key string, wdSpellings []string) string {
	if !filepath.IsAbs(key) {
		return filepath.ToSlash(filepath.Clean(key))
	}
	for _, base := range wdSpellings {
		rel, err := filepath.Rel(base, key)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(key)
}

// workingDirSpellings is the working directory as written and with symlinks
// resolved. A product key recorded by another attestor may be spelled either
// way, and only one of them makes it relative.
func workingDirSpellings(workingDir string) []string {
	if workingDir == "" {
		return nil
	}
	abs, err := filepath.Abs(workingDir)
	if err != nil {
		return nil
	}
	spellings := []string{abs}
	if real, err := filepath.EvalSymlinks(abs); err == nil && real != abs {
		spellings = append(spellings, real)
	}
	return spellings
}

// gitCommand builds every git invocation this package makes. It exists so
// that OBJECT REPLACEMENT CANNOT BE FORGOTTEN AT A CALL SITE.
//
// refs/replace/* rewrites what git RETURNS for an object: point a replace ref
// at a clean blob and cat-file, diff, rev-parse and ls-tree all hand back the
// substitute, while an ordinary push still sends the original object to the
// remote. A scan that honours replacements therefore reads something the push
// does not carry, and can report clean over a commit whose real bytes hold a
// secret. Replacement is a local rewriting convenience; evidence about what a
// commit contains must be about the objects the commit actually names.
//
// Both mechanisms are set. The flag covers this process, and the environment
// variable covers anything git spawns for it (a pager, a promisor fetch, any
// helper), so neither can reintroduce replacement behind the flag.
func gitCommand(ctx *attestation.AttestationContext, dir string, args ...string) *exec.Cmd {
	full := append([]string{"--no-replace-objects"}, args...)
	cmd := exec.CommandContext(ctx.Context(), "git", full...) //nolint:gosec // G204: fixed git subcommands; the only operator input is a ref, passed as an argument, never through a shell
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_NO_REPLACE_OBJECTS=1")
	return cmd
}

// gitOutput runs git in dir and returns its stdout, with stderr folded into
// the error so an unresolvable ref is explained.
func gitOutput(ctx *attestation.AttestationContext, dir string, args ...string) ([]byte, error) {
	cmd := gitCommand(ctx, dir, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// splitNUL splits NUL-terminated git output into paths.
func splitNUL(out []byte) []string {
	var paths []string
	for _, p := range bytes.Split(out, []byte{0}) {
		if len(p) > 0 {
			paths = append(paths, string(p))
		}
	}
	return paths
}

// blobSource names WHICH of a path's several versions a blob is. A path can
// carry three different sets of bytes at once — what HEAD committed, what the
// index has staged, and what is on disk — and only the third is a file. The
// other two are read from the object store and named apart, because "the file
// is clean" says nothing about the other two.
type blobSource string

const (
	blobFromCommit blobSource = "commit"
	blobFromIndex  blobSource = "index"
)

// committedBlob is one path's content as some commit or the index holds it,
// named by object id. It exists because the working tree is neither of them.
type committedBlob struct {
	Rel string
	OID string
	// Commit is the commit that INTRODUCED these bytes at this path, set for
	// blobSource commit. A push publishes every newly reachable commit, so a
	// blob's home is a specific commit, not "the tip".
	Commit string
	Source blobSource
}

// key is the subject and finding location for a blob. Committed content names
// the commit that introduced it: a path can be given different bytes by
// several commits in one push, and "commit:<path>" would let one overwrite
// another and misstate which bytes were scanned.
func (b committedBlob) key() string {
	if b.Source == blobFromCommit {
		return "commit:" + b.Commit + ":" + b.Rel
	}
	return string(b.Source) + ":" + b.Rel
}

// diffScan is what a diff scope resolves to: the base commit, the files to
// read off disk, and the committed blobs the working tree no longer
// represents and which must therefore be read from the object store.
type diffScan struct {
	Base  string
	Files []string
	Blobs []committedBlob
}

// diffFiles resolves what a diff scope covers: everything that changed
// between the merge-base of baseRef and HEAD and what is here now.
//
// THE EVIDENCE IS BOUND TO A COMMIT, AND THE WORKING TREE IS NOT THE COMMIT.
// `git diff <base>` compares the base against the WORKING TREE, so commit a
// secret and then restore that path to its base contents — or just delete the
// file — and it drops out of that listing while the pushed commit still
// contains it. With no products recorded, the scan then reported clean over a
// commit carrying a secret. So the commit is read from the object store:
//
//   - `git diff --raw <base> HEAD` names every path the COMMITS changed,
//     with the destination mode and blob id.
//   - EVERY one of those blobs is read from the object store, unconditionally.
//
// An earlier fix read the blob only for paths `git diff HEAD` called dirty,
// on the premise that every other committed path is faithfully represented on
// disk. THAT PREMISE IS USER-OVERRIDABLE AND THE OVERRIDE IS TRIVIAL: after
// committing a secret, `git update-index --assume-unchanged <path>` (or
// --skip-worktree) tells git to stop comparing that path, so it vanishes from
// every dirty listing while the disk copy is replaced with clean text. git's
// own answer to "is this dirty" is attacker-controlled input, so it cannot
// gate whether committed content gets examined. The working tree is NEVER a
// proxy for the commit — not "usually", not "unless git says otherwise".
// There is no condition on the blob read, so there is nothing left to fool.
//
// On top of the commit, uncommitted work is scanned too, because it is about
// to become a commit: tracked changes from `git diff <base>` (staged and
// unstaged alike) and untracked files from `git ls-files --others`. Both are
// asked for root-relative paths (`git diff` prints them that way; `ls-files`
// needs --full-name), which are then made relative to workingDir; a change
// outside workingDir is skipped. Deletions are never listed: there is nothing
// to read. Every failure is returned rather than treated as "no changes",
// because a diff scan that quietly scanned nothing would satisfy a no-secrets
// policy with a scan of nothing.
func diffFiles(ctx *attestation.AttestationContext, workingDir, baseRef string) (diffScan, error) {
	root, base, err := resolveDiffBase(ctx, workingDir, baseRef)
	if err != nil {
		return diffScan{}, err
	}
	committed, err := historyBlobs(ctx, workingDir, base)
	if err != nil {
		return diffScan{}, err
	}
	staged, err := stagedChanges(ctx, workingDir, base)
	if err != nil {
		return diffScan{}, err
	}
	worktree, err := workingTreeChanges(ctx, workingDir, base)
	if err != nil {
		return diffScan{}, err
	}
	toWD, err := newRootRelativeMapper(workingDir, root)
	if err != nil {
		return diffScan{}, err
	}
	return diffScan{
		Base:  base,
		Files: relativeFiles(worktree, toWD),
		Blobs: relativeBlobs(append(committed, staged...), toWD),
	}, nil
}

// stagedChanges answers "what has been staged that the base does not have",
// with the blob id of each path's content IN THE INDEX.
//
// A path can hold three different sets of bytes at once. Reading the commit
// and the file on disk left the middle one unread: stage a secret, then put
// clean text back in the working copy, and the commit does not have it yet,
// the file does not have it any more, and `git commit` carries it anyway. The
// index is its own source and is read as one.
//
// Against an older base this listing overlaps the committed one for every
// path that is committed and unmodified in the index. That costs one extra
// object read each, and the by-digest dedup drops the second scan, so the
// overlap is paid in reads rather than in duplicate evidence.
func stagedChanges(ctx *attestation.AttestationContext, workingDir, base string) ([]committedBlob, error) {
	rawOut, err := gitOutput(ctx, workingDir,
		"-c", "diff.relative=false",
		"diff", "-r", "--cached", "--raw", "--no-renames", "--abbrev=64", "--diff-filter=d", "-z", base)
	if err != nil {
		return nil, fmt.Errorf("secretscan diff scope: %w", err)
	}
	staged, err := parseDiffRaw(rawOut, blobFromIndex, "")
	if err != nil {
		return nil, fmt.Errorf("secretscan diff scope: %w", err)
	}
	return staged, nil
}

// resolveDiffBase answers "which repository, and which commit are we diffing
// against". Both failures are failures to observe, not empty diffs: a
// directory that is not a work tree, or a base ref that does not resolve,
// stops the scan rather than letting it cover nothing.
func resolveDiffBase(ctx *attestation.AttestationContext, workingDir, baseRef string) (root, base string, err error) {
	rootOut, err := gitOutput(ctx, workingDir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", "", fmt.Errorf("secretscan diff scope: %s is not inside a git work tree: %w", workingDir, err)
	}
	// This is the ONE place left that asks git a question about ancestry, and
	// it asks only WHICH commit the base is. Everything downstream — which
	// commits are newly reachable, and which blobs each introduces — is read
	// from the objects themselves. A view that could make merge-base answer
	// wrongly (a graft, a shallow boundary) is refused outright before this
	// runs; see refuseAlteredHistoryView.
	baseOut, err := gitOutput(ctx, workingDir, "merge-base", baseRef, "HEAD")
	if err != nil {
		return "", "", fmt.Errorf("secretscan diff scope: cannot resolve base %q: %w", baseRef, err)
	}
	return strings.TrimSpace(string(rootOut)), strings.TrimSpace(string(baseOut)), nil
}

// refuseAlteredHistoryView refuses to produce evidence at all when the
// repository's view of its own history is one this attestor cannot trust.
//
// The walk reads parents from the commit objects precisely so a graft cannot
// narrow it, but that only covers the mechanisms we know. A grafted or shallow
// checkout says, on its face, that the history here is not the history that
// was published — so the honest output is no attestation rather than one that
// quietly covers less. It carries commandrun.ErrNotAttestable, the sentinel
// the codebase already uses for "this run cannot be signed", so a caller tests
// the refusal by identity instead of by wording.
func refuseAlteredHistoryView(ctx *attestation.AttestationContext, workingDir string) error {
	graftPath, err := gitOutput(ctx, workingDir, "rev-parse", "--git-path", "info/grafts")
	if err != nil {
		return fmt.Errorf("secretscan diff scope: %w", err)
	}
	grafts := strings.TrimSpace(string(graftPath))
	if !filepath.IsAbs(grafts) {
		grafts = filepath.Join(workingDir, grafts)
	}
	if _, err := os.Stat(grafts); err == nil {
		return notAttestable(fmt.Sprintf("secretscan diff scope: %s exists, so git reports parents this attestor cannot verify against the commit objects; refusing to attest a history whose shape is overridden", grafts))
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("secretscan diff scope: checking %s: %w", grafts, err)
	}

	shallowOut, err := gitOutput(ctx, workingDir, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return fmt.Errorf("secretscan diff scope: %w", err)
	}
	if strings.TrimSpace(string(shallowOut)) == "true" {
		return notAttestable("secretscan diff scope: this is a shallow repository, so its boundary commits do not name their real parents; refusing to attest a history that is not all here")
	}
	return nil
}

// notAttestable wraps a refusal so errors.Is(err, commandrun.ErrNotAttestable)
// holds while the operator-facing message stays exactly as written.
func notAttestable(msg string) error {
	return &notAttestableHistory{msg: msg}
}

type notAttestableHistory struct{ msg string }

func (e *notAttestableHistory) Error() string { return e.msg }
func (e *notAttestableHistory) Is(target error) bool {
	return target == commandrun.ErrNotAttestable
}

// historyBlobs answers "what does this push NEWLY PUBLISH".
//
// The unit of coverage is the newly reachable COMMIT SET, not the endpoint
// diff. `git diff <base> HEAD` compares two trees, so a secret added in one
// commit and deleted in the next is invisible to it — base->HEAD is clean, the
// index is clean, the working tree is clean, and the objects the push sends
// still carry the secret, readable by anyone who fetches, forever. What a push
// publishes is every commit reachable from HEAD and not from the base, so that
// is what is enumerated.
//
// For each such commit, the blobs it INTRODUCED: present in its tree and not
// present at that path in ANY parent. Every parent is read, not just the
// first — a secret added and removed again on a side branch sits on no
// first-parent tree and in no tree at HEAD, and first-parent traversal walks
// straight past it. For a single-parent commit, the common case, the
// intersection is just that one diff and this is one git process per commit.
//
// Blobs already reachable from the base are not enumerated, so history
// scanning does not widen the scan to the whole repository: a secret the base
// already published is not this push's doing.
func historyBlobs(ctx *attestation.AttestationContext, workingDir, base string) ([]committedBlob, error) {
	commits, err := newlyReachableCommits(ctx, workingDir, base)
	if err != nil {
		return nil, err
	}
	var blobs []committedBlob
	for _, c := range commits {
		introduced, err := introducedBlobs(ctx, workingDir, c.OID, c.Parents)
		if err != nil {
			return nil, err
		}
		blobs = append(blobs, introduced...)
	}
	return blobs, nil
}

// commitObject is what a commit's OWN BYTES say about its ancestry. Nothing
// here is git's opinion, and nothing here is a date: parents are parsed out of
// the object, which is the one description of history that a graft, a replace
// ref or a shallow boundary cannot rewrite.
type commitObject struct {
	OID     string
	Parents []string
}

// newlyReachableCommits returns the commits reachable from HEAD and not from
// base, parents before children, walking PARENT LINES READ FROM THE COMMIT
// OBJECTS.
//
// It deliberately does not ask `git rev-list`. `.git/info/grafts` rewrites
// what git REPORTS for a commit's parents and --no-replace-objects does not
// disable it, so a graft joining a clean tip straight to the base makes
// rev-list omit the secret-bearing commit between them; delete the graft
// before pushing and the pushed history is unchanged while the evidence was
// clean. The objects still name the real parents.
//
// IT ALSO MAKES NO ORDERING ASSUMPTION. An earlier version walked both ends
// newest first by commit date, which is not ancestry. With R the parent of
// both B and S, H merging B and S, and dates B=100, R=200, S=300, H=400, the
// walk against base B ran out of head-side work while only B was queued and
// reported R — which B already publishes — as new: a secret introduced in R
// and deleted on both branches would block a clean push forever, blaming it
// for history the base already carried. A date is metadata anyone can set, and
// rebases, imports and wrong clocks set it wrongly without anyone trying. Only
// parent lines say what a commit descends from, so only parent lines are read,
// and no date is read anywhere in this package.
//
// Two passes, no ordering: mark everything the base publishes, then walk from
// HEAD and keep what is not marked.
func newlyReachableCommits(ctx *attestation.AttestationContext, workingDir, base string) ([]commitObject, error) {
	headOut, err := gitOutput(ctx, workingDir, "rev-parse", "HEAD^{commit}")
	if err != nil {
		return nil, fmt.Errorf("secretscan diff scope: resolving HEAD: %w", err)
	}
	head := strings.TrimSpace(string(headOut))

	reader, err := startCatFileBatch(ctx, workingDir, nil)
	if err != nil {
		return nil, fmt.Errorf("secretscan diff scope: %w", err)
	}
	defer reader.kill()

	published, err := reader.ancestors(base)
	if err != nil {
		return nil, fmt.Errorf("secretscan diff scope: walking the base's history: %w", err)
	}
	newly, err := reader.ancestorsExcept(head, published)
	if err != nil {
		return nil, fmt.Errorf("secretscan diff scope: walking this push's history: %w", err)
	}
	if err := reader.close(); err != nil {
		return nil, fmt.Errorf("secretscan diff scope: %w", err)
	}
	return parentsFirst(newly), nil
}

// ancestors marks every commit reachable from start, following parent lines
// from the objects. A commit already marked is not expanded again, so each one
// is read once and the walk ends at the roots — bounded by the commits it
// actually meets, with no assumption about the order they arrive in.
func (b *catFileBatch) ancestors(start string) (map[string]struct{}, error) {
	marked := map[string]struct{}{}
	stack := []string{start}
	for len(stack) > 0 {
		oid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, seen := marked[oid]; seen {
			continue
		}
		marked[oid] = struct{}{}
		c, err := b.commit(oid)
		if err != nil {
			return nil, err
		}
		stack = append(stack, c.Parents...)
	}
	return marked, nil
}

// ancestorsExcept walks from start and returns the commits NOT in excluded. An
// excluded commit is skipped AND NOT EXPANDED: everything behind it is
// reachable from the base too, so what comes back is exactly what the push
// publishes.
func (b *catFileBatch) ancestorsExcept(start string, excluded map[string]struct{}) ([]commitObject, error) {
	var newly []commitObject
	seen := map[string]struct{}{}
	stack := []string{start}
	for len(stack) > 0 {
		oid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, done := seen[oid]; done {
			continue
		}
		seen[oid] = struct{}{}
		if _, isPublished := excluded[oid]; isPublished {
			continue
		}
		c, err := b.commit(oid)
		if err != nil {
			return nil, err
		}
		newly = append(newly, c)
		stack = append(stack, c.Parents...)
	}
	return newly, nil
}

// parentsFirst orders the set so a commit follows the parents it has within
// it. This is what makes the evidence name the commit that INTRODUCED a set of
// bytes when several carry them: the first scanned wins the name, and "first"
// has to mean earlier in the history, never earlier on a clock.
func parentsFirst(newly []commitObject) []commitObject {
	byOID := make(map[string]commitObject, len(newly))
	for _, c := range newly {
		byOID[c.OID] = c
	}
	ordered := make([]commitObject, 0, len(newly))
	emitted := make(map[string]bool, len(newly))
	var visit func(string)
	visit = func(oid string) {
		if emitted[oid] {
			return
		}
		c, ok := byOID[oid]
		if !ok {
			return // reachable from the base, or not in this push at all
		}
		emitted[oid] = true
		for _, parent := range c.Parents {
			visit(parent)
		}
		ordered = append(ordered, c)
	}
	for _, c := range newly {
		visit(c.OID)
	}
	return ordered
}

// introducedBlobs lists the blobs commit sha gives a path that no parent
// already gave it. A blob that only differs from SOME parents came from the
// others and was already reachable, so the per-parent listings are intersected.
func introducedBlobs(ctx *attestation.AttestationContext, workingDir, sha string, parents []string) ([]committedBlob, error) {
	if len(parents) == 0 {
		// A root commit has no parent to diff against; --root spells its whole
		// tree as additions.
		// -r is NOT optional: diff-tree is plumbing and does not recurse by
		// default, so without it a subdirectory comes back as its TREE object
		// and every blob inside it goes unlisted. A secret one directory down
		// in a root commit was read by nobody.
		raw, err := gitOutput(ctx, workingDir, "-c", "diff.relative=false",
			"diff-tree", "-r", "--root", "--no-commit-id",
			"--raw", "--no-renames", "--abbrev=64", "--diff-filter=d", "-z", sha)
		if err != nil {
			return nil, fmt.Errorf("secretscan diff scope: %w", err)
		}
		return parseDiffRaw(raw, blobFromCommit, sha)
	}
	var common []committedBlob
	for i, parent := range parents {
		// -r is the default for `git diff`, stated anyway so that no listing in
		// this file can be read as maybe-recursive.
		raw, err := gitOutput(ctx, workingDir, "-c", "diff.relative=false",
			"diff", "-r", "--raw", "--no-renames", "--abbrev=64", "--diff-filter=d", "-z", parent, sha)
		if err != nil {
			return nil, fmt.Errorf("secretscan diff scope: %w", err)
		}
		entries, err := parseDiffRaw(raw, blobFromCommit, sha)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			common = entries
			continue
		}
		common = intersectBlobs(common, entries)
		if len(common) == 0 {
			return nil, nil
		}
	}
	return common, nil
}

// intersectBlobs keeps the entries present in both listings, matched on path
// AND object id: the same path holding different bytes in two parents is not
// the same blob.
func intersectBlobs(a, b []committedBlob) []committedBlob {
	inB := make(map[string]struct{}, len(b))
	for _, e := range b {
		inB[e.Rel+"\x00"+e.OID] = struct{}{}
	}
	kept := a[:0]
	for _, e := range a {
		if _, ok := inB[e.Rel+"\x00"+e.OID]; ok {
			kept = append(kept, e)
		}
	}
	return kept
}

// workingTreeChanges answers "what is here now that the base does not have",
// as root-relative git paths: tracked changes (staged and unstaged alike) plus
// untracked files that are not ignored. It is scanned ON TOP of the commit,
// never instead of it — uncommitted work is about to become a commit.
func workingTreeChanges(ctx *attestation.AttestationContext, workingDir, base string) ([]string, error) {
	changed, err := gitOutput(ctx, workingDir,
		// diff.relative, set in the repository's or the operator's git config,
		// makes git print paths relative to the CURRENT directory instead of
		// the repository root. The caller joins these onto the root, so under
		// a working directory below the root every changed path would then
		// look like it is outside the scan and the diff would come back empty
		// and successful. Pin it rather than inherit it.
		"-c", "diff.relative=false",
		"diff", "--name-only", "--no-renames",
		// Name what is NOT read, not what is. An allow-list (ACMR) silently
		// dropped every class of change it forgot: a tracked symlink replaced
		// by a regular file holding a secret is a TYPE change, so the secret
		// walked into the tree past a diff scan that reported clean. Deletion
		// is the only status excluded, because there is no file left to read.
		"--diff-filter=d",
		"-z", base)
	if err != nil {
		return nil, fmt.Errorf("secretscan diff scope: %w", err)
	}
	untracked, err := gitOutput(ctx, workingDir, "ls-files", "--others", "--exclude-standard", "--full-name", "-z")
	if err != nil {
		return nil, fmt.Errorf("secretscan diff scope: %w", err)
	}
	return append(splitNUL(changed), splitNUL(untracked)...), nil
}

// newRootRelativeMapper answers "how does a path git printed become a path
// this scan can name". git prints root-relative paths and reports the REAL
// path of the root (symlinks resolved, which on macOS turns /var into
// /private/var), so the working directory is resolved the same way or every
// path looks like it is outside it and the scan comes back empty and
// successful. Failing to resolve is a failure to observe, not an empty diff,
// so the error is returned rather than swallowed.
//
// The returned mapper reports ok=false for a path outside the working
// directory: not this step's to scan.
func newRootRelativeMapper(workingDir, root string) (func(string) (string, bool), error) {
	absWD, err := filepath.Abs(workingDir)
	if err != nil {
		return nil, err
	}
	absWD, err = filepath.EvalSymlinks(absWD)
	if err != nil {
		return nil, fmt.Errorf("secretscan diff scope: resolving working directory %s: %w", workingDir, err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("secretscan diff scope: resolving repository root %s: %w", root, err)
	}
	return func(p string) (string, bool) {
		rel, err := filepath.Rel(absWD, filepath.Join(realRoot, filepath.FromSlash(p)))
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			log.Debugf("(attestation/secretscan) diff scope: %s is outside the working directory, skipping", p)
			return "", false
		}
		return filepath.ToSlash(rel), true
	}, nil
}

// relativeFiles maps the working-tree listing into the scan's paths, dropping
// anything outside the working directory and collapsing the duplicate a path
// that is both tracked-changed and listed again would otherwise produce.
func relativeFiles(paths []string, toWD func(string) (string, bool)) []string {
	seen := map[string]struct{}{}
	var files []string
	for _, p := range paths {
		rel, ok := toWD(p)
		if !ok {
			continue
		}
		if _, dup := seen[rel]; dup {
			continue
		}
		seen[rel] = struct{}{}
		files = append(files, rel)
	}
	return files
}

// relativeBlobs maps the committed listing into the scan's paths. Object ids
// are carried through untouched: they name the bytes, and the path only names
// where the bytes live.
func relativeBlobs(committed []committedBlob, toWD func(string) (string, bool)) []committedBlob {
	var blobs []committedBlob
	for _, b := range committed {
		rel, ok := toWD(b.Rel)
		if !ok {
			continue
		}
		blobs = append(blobs, committedBlob{Rel: rel, OID: b.OID, Commit: b.Commit, Source: b.Source})
	}
	return blobs
}

// parseDiffRaw parses `git diff --raw -z` output. Each record is a metadata
// field ":<srcmode> <dstmode> <srcoid> <dstoid> <status>" followed by NUL and
// then the NUL-terminated path; --no-renames keeps it to one path per record.
// A record it cannot parse is an error, not a skipped path: dropping one here
// would put a committed file back out of reach of the scan, which is the
// whole defect this listing exists to close.
func parseDiffRaw(out []byte, source blobSource, commit string) ([]committedBlob, error) {
	fields := bytes.Split(out, []byte{0})
	// -z terminates (not separates) records, so the tail is one empty field.
	if len(fields) > 0 && len(fields[len(fields)-1]) == 0 {
		fields = fields[:len(fields)-1]
	}
	if len(fields)%2 != 0 {
		return nil, fmt.Errorf("git diff --raw: %d NUL-separated fields, want metadata/path pairs", len(fields))
	}
	var blobs []committedBlob
	for i := 0; i < len(fields); i += 2 {
		meta, path := string(fields[i]), string(fields[i+1])
		if !strings.HasPrefix(meta, ":") {
			return nil, fmt.Errorf("git diff --raw: unparseable record %q", meta)
		}
		parts := strings.Fields(meta[1:])
		if len(parts) < 5 {
			return nil, fmt.Errorf("git diff --raw: unparseable record %q", meta)
		}
		dstMode, dstOID := parts[1], parts[3]
		switch dstMode {
		case "160000":
			// A submodule gitlink is the ONLY mode skipped, because it is not
			// a blob at all: the object lives in another repository, so
			// cat-file cannot read it and every repo with a submodule would
			// become a scan error, which is fatal.
			log.Debugf("(attestation/secretscan) diff scope: %s is a submodule gitlink, not a blob", path)
			continue
		case "100644", "100755", "120000":
			// Regular files, executables, and symlinks. A symlink's blob is
			// the recorded target string, which is attacker-chosen text the
			// commit carries; reading it dereferences nothing. Skipping it by
			// mode was a hole: `update-index --cacheinfo 120000,<oid>,<path>`
			// puts arbitrary bytes behind a symlink mode.
		default:
			// Anything else — a tree at 040000 above all — means the listing
			// was not recursive. That is a BUG IN THIS CODE, not a path to
			// skip, and skipping it is precisely how a secret nested one
			// directory down in a root commit went unread. Fail loudly.
			return nil, fmt.Errorf("git diff --raw: %s in %s has mode %s, which is not a blob: the listing was not recursive", path, commit, dstMode)
		}
		blobs = append(blobs, committedBlob{Rel: path, OID: dstOID, Commit: commit, Source: source})
	}
	return blobs, nil
}

// treeFiles lists every regular file under workingDir except those under a
// .git directory, as slash-separated paths relative to the resolved root.
//
// Symlinks INSIDE the tree are not followed: a target inside the tree is
// listed under its own path anyway, and a target outside the tree is outside
// the scan. The ROOT is the opposite case, because the root IS the scan.
// filepath.WalkDir does not follow a symlink handed to it as the root; it
// calls the callback once with a non-directory entry, the callback skips it,
// and the walk returns an EMPTY listing and NO error — clean `tree` evidence
// produced by reading nothing. CI checkouts under a symlinked path (macOS
// /tmp, a symlinked workspace) land exactly there. So the root is resolved
// first, and a root that is not a walkable directory is an error: a scan that
// read nothing must not be able to satisfy a no-secrets policy.
func treeFiles(workingDir string) ([]string, error) {
	root, err := filepath.EvalSymlinks(workingDir)
	if err != nil {
		return nil, fmt.Errorf("secretscan tree scope: resolving %s: %w", workingDir, err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("secretscan tree scope: %s: %w", workingDir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("secretscan tree scope: %s is not a directory", workingDir)
	}

	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("secretscan tree scope: walking %s: %w", workingDir, err)
	}
	return files, nil
}

// scanFiles scans the working-tree files a diff or tree scope lists. Per-file
// failures are recorded in scanErrors, never dropped: they fail the run.
//
// It no longer consults the product inventory. Skipping a path because it
// APPEARS in that inventory was membership standing in for coverage: when
// product metadata declared a file binary, scanProducts did not read it and
// scanFiles skipped it for being "already a product", so a text file with a
// secret that another attestor had labelled binary was read by nobody. The
// only thing that may skip a read now is this attestor having already scanned
// those exact bytes for that path, which scanContent decides by digest — so a
// file a product really did cover is still read once and reported once.
func (a *Attestor) scanFiles(ctx *attestation.AttestationContext, rels []string, detector *detect.Detector) {
	for _, rel := range rels {
		absPath := filepath.Join(ctx.WorkingDir(), filepath.FromSlash(rel))
		if !a.pathInScope(rel) {
			continue
		}
		if err := a.scanOneFile(ctx, rel, absPath, detector); err != nil {
			a.scanErrors = append(a.scanErrors, fmt.Errorf("scanning file %s: %w", rel, err))
		}
	}
}

// scanOneFile reads one working-tree file, records it as a subject keyed
// "file:<path>" with the digest of the bytes read, and locates its findings
// as "file:<path>". Directories, symlinks, oversized files and binaries are
// skipped without error, exactly as products are.
func (a *Attestor) scanOneFile(ctx *attestation.AttestationContext, rel, absPath string, detector *detect.Detector) error {
	info, err := os.Lstat(absPath)
	if err != nil {
		// Listed by git a moment ago and gone now: an error, not a
		// silently narrower scan.
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if exceeds, err := a.exceedsMaxFileSize(absPath); err != nil || exceeds {
		return err
	}
	content, err := a.readFileContent(absPath)
	if err != nil {
		return err
	}
	return a.scanContent(ctx, "file:"+rel, rel, absPath, content, detector)
}

// forEachCommittedBlob reads the named objects in ONE `git cat-file --batch`
// process and hands each one to fn AS IT ARRIVES, then drops it.
//
// It streams rather than collecting. Building a map of every blob first held
// the whole eligible diff at once — 1,000 distinct 9 MB files meant ~9 GB
// live despite the per-file limit, including binaries about to be discarded.
// Handing each blob straight to fn keeps exactly one live at a time, so what
// this reader holds does not grow with the size of the diff. Measured: the
// live set after GC is 1 MB whether the diff carries 5 or 30 four-megabyte
// blobs, and reader+digest peak is flat at 9 MB across both. (Total process
// peak still moves with diff size, because SCANNING a blob allocates
// transient copies; that garbage is reclaimable under pressure, which the
// retained map was not.)
//
// One request line is written per entry, in order, and one response is read
// per entry, in order; duplicate object ids simply cost a second cheap read
// rather than needing a map to fan back out to their several paths.
//
// An object git reports as missing is an error, not a silent omission: the
// caller asked for a blob the commit's own tree names, so failing to produce
// it is a hole in the coverage and must fail the scan.
func forEachCommittedBlob(
	ctx *attestation.AttestationContext,
	dir string,
	blobs []committedBlob,
	maxBytes int64,
	fn func(blob committedBlob, content []byte),
) error {
	if len(blobs) == 0 {
		return nil
	}
	batch, err := startCatFileBatch(ctx, dir, blobs)
	if err != nil {
		return err
	}
	// Kill and reap on any early return, so a parse failure cannot leave git
	// blocked on a pipe nobody is draining. A no-op once close has reaped it.
	defer batch.kill()

	for _, blob := range blobs {
		content, ok, err := batch.next(blob, maxBytes)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		// content is scoped to this iteration, so it is unreachable once the
		// iteration ends: at most one blob is live at a time.
		fn(blob, content)
	}
	return batch.close()
}

// catFileBatch is a running `git cat-file --batch`, fed every object id up
// front and read back one response at a time.
type catFileBatch struct {
	cmd      *exec.Cmd
	reader   *bufio.Reader
	stderr   *bytes.Buffer
	stdin    io.WriteCloser
	finished bool
}

// startCatFileBatch launches the process and writes every object id to its
// stdin from a goroutine, so feeding the request list cannot deadlock against
// reading the responses: both pipes are drained concurrently.
func startCatFileBatch(ctx *attestation.AttestationContext, dir string, blobs []committedBlob) (*catFileBatch, error) {
	cmd := gitCommand(ctx, dir, "cat-file", "--batch")
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("git cat-file --batch: %w", err)
	}
	if len(blobs) > 0 {
		go func() {
			defer func() { _ = stdin.Close() }()
			for _, blob := range blobs {
				if _, err := io.WriteString(stdin, blob.OID+"\n"); err != nil {
					return
				}
			}
		}()
	}
	return &catFileBatch{cmd: cmd, reader: bufio.NewReader(stdout), stderr: stderr, stdin: stdin}, nil
}

// commit asks for one commit object and parses the ancestry out of its bytes.
// The walk needs request/response rather than the bulk send the blob reader
// uses, because which object it wants next depends on what the last one said.
func (b *catFileBatch) commit(oid string) (commitObject, error) {
	if _, err := io.WriteString(b.stdin, oid+"\n"); err != nil {
		return commitObject{}, fmt.Errorf("git cat-file --batch: requesting %s: %w", oid, err)
	}
	gotOID, kind, size, err := b.headerOf()
	if err != nil {
		return commitObject{}, err
	}
	if kind != "commit" {
		return commitObject{}, fmt.Errorf("git cat-file --batch: %s is a %s, not a commit", oid, kind)
	}
	content, err := b.body(gotOID, size)
	if err != nil {
		return commitObject{}, err
	}
	return parseCommitObject(gotOID, content)
}

// parseCommitObject reads a commit object's header for the ONLY thing this
// package wants from it: the "parent <oid>" lines naming its real ancestry.
// The header ends at the first blank line; nothing after it is ancestry. The
// committer and author lines carry dates and are deliberately NOT read — see
// newlyReachableCommits for what ordering by date cost.
func parseCommitObject(oid string, content []byte) (commitObject, error) {
	c := commitObject{OID: oid}
	for _, line := range strings.Split(string(content), "\n") {
		if line == "" {
			break
		}
		if parent, ok := strings.CutPrefix(line, "parent "); ok {
			c.Parents = append(c.Parents, strings.TrimSpace(parent))
		}
	}
	return c, nil
}

// next reads one response. ok is false for an object deliberately skipped —
// only ever one over the size limit, which is skipped exactly as an oversized
// file is — so a caller can tell "nothing to scan here" from "zero bytes".
func (b *catFileBatch) next(blob committedBlob, maxBytes int64) (content []byte, ok bool, err error) {
	oid, size, err := b.header()
	if err != nil {
		return nil, false, err
	}
	if maxBytes > 0 && size > maxBytes {
		log.Debugf("(attestation/secretscan) skipping large committed blob %s (%d bytes)", blob.Rel, size)
		if err := b.discard(size); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	content, err = b.body(oid, size)
	if err != nil {
		return nil, false, err
	}
	return content, true, nil
}

// header reads and parses one "<oid> <type> <size>" line. An object git
// reports as missing is an error, not a silent omission: the caller asked for
// a blob the commit's own tree names, so failing to produce it is a hole in
// the coverage and must fail the scan.
func (b *catFileBatch) header() (oid string, size int64, err error) {
	oid, _, size, err = b.headerOf()
	return oid, size, err
}

// headerOf also returns the object TYPE, which the blob path does not need but
// the commit walk must check: asking for a commit and being handed something
// else means the walk is not reading the history it thinks it is.
func (b *catFileBatch) headerOf() (oid, kind string, size int64, err error) {
	line, err := b.reader.ReadString('\n')
	if err != nil {
		return "", "", 0, fmt.Errorf("git cat-file --batch: reading header: %w: %s", err, strings.TrimSpace(b.stderr.String()))
	}
	fields := strings.Fields(line)
	if len(fields) == 2 && (fields[1] == "missing" || fields[1] == "ambiguous") {
		return "", "", 0, fmt.Errorf("git cat-file --batch: object %s is %s", fields[0], fields[1])
	}
	if len(fields) != 3 {
		return "", "", 0, fmt.Errorf("git cat-file --batch: unparseable header %q", strings.TrimSpace(line))
	}
	size, err = strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return "", "", 0, fmt.Errorf("git cat-file --batch: unparseable size in %q", strings.TrimSpace(line))
	}
	return fields[0], fields[1], size, nil
}

// body reads one object's contents. git writes them followed by one LF, which
// is consumed here so the next header starts at a record boundary.
func (b *catFileBatch) body(oid string, size int64) ([]byte, error) {
	content := make([]byte, size)
	if _, err := io.ReadFull(b.reader, content); err != nil {
		return nil, fmt.Errorf("git cat-file --batch: reading object %s: %w", oid, err)
	}
	if _, err := b.reader.Discard(1); err != nil {
		return nil, fmt.Errorf("git cat-file --batch: reading object separator: %w", err)
	}
	return content, nil
}

// discard consumes an object this scan will not read, plus its trailing LF,
// so the stream stays aligned without the bytes ever being retained.
func (b *catFileBatch) discard(size int64) error {
	if _, err := io.CopyN(io.Discard, b.reader, size+1); err != nil {
		return fmt.Errorf("git cat-file --batch: discarding oversized object: %w", err)
	}
	return nil
}

// close reaps the process and reports a non-zero exit, with stderr folded in.
func (b *catFileBatch) close() error {
	b.finished = true
	if b.stdin != nil {
		_ = b.stdin.Close()
	}
	if err := b.cmd.Wait(); err != nil {
		return fmt.Errorf("git cat-file --batch: %w: %s", err, strings.TrimSpace(b.stderr.String()))
	}
	return nil
}

// kill tears the process down on an abandoned read. It is safe after close:
// a reaped process must not be waited on twice.
func (b *catFileBatch) kill() {
	if b.finished {
		return
	}
	b.finished = true
	if b.stdin != nil {
		_ = b.stdin.Close()
	}
	_ = b.cmd.Process.Kill()
	_ = b.cmd.Wait()
}

// scanCommittedBlobs scans the bytes the COMMIT holds for every path the
// commits changed, read from the object store. There is no condition on the
// read: see diffFiles for why any condition derived from working-tree state —
// including git's own dirty listing — is attacker-controlled and therefore
// cannot gate whether committed content is examined.
//
// What the digest comparison suppresses is only the redundant SECOND SCAN of
// bytes this attestor already scanned for that same path, whether it read them
// off disk (file:) or as a product (product:). Identical content is therefore
// reported once, under whichever identity read it first. The comparison is
// decided entirely on buffers this attestor read and hashed itself, never on
// anything git or another attestor claims, and every uncertain case falls
// through to scanning the blob:
//
//   - nothing recorded for the path — the earlier read was skipped (binary,
//     oversized, non-regular, or a product another attestor declared binary)
//     or it failed — scan the blob,
//   - digests differ, so the earlier bytes were something else — scan the blob,
//   - no hash algorithms configured, so equality cannot be shown — scan the
//     blob.
//
// Per-blob failures are recorded in scanErrors, which fails the run: a blob
// the commit named and we could not read is a hole in the coverage.
func (a *Attestor) scanCommittedBlobs(ctx *attestation.AttestationContext, workingDir string, blobs []committedBlob, detector *detect.Detector) {
	inScope := make([]committedBlob, 0, len(blobs))
	for _, blob := range blobs {
		if a.pathInScope(blob.Rel) {
			inScope = append(inScope, blob)
		}
	}
	if len(inScope) == 0 {
		return
	}

	var maxBytes int64
	if a.maxFileSizeMB > 0 {
		maxBytes = int64(a.maxFileSizeMB) * 1024 * 1024
	}
	err := forEachCommittedBlob(ctx, workingDir, inScope, maxBytes, func(blob committedBlob, content []byte) {
		// "commit:<path>" and "index:<path>" are deliberately distinct from
		// "file:<path>" and from each other: they are three different sets of
		// bytes for one path, and when more than one is recorded they differ.
		// One key for all of them would let one digest overwrite another and
		// make the evidence misstate what was scanned. scanContent drops the
		// ones that turn out to be identical.
		key := blob.key()
		if err := a.scanContent(ctx, key, blob.Rel, key, content, detector); err != nil {
			a.scanErrors = append(a.scanErrors, fmt.Errorf("scanning committed blob %s (%s): %w", blob.Rel, blob.OID, err))
		}
	})
	if err != nil {
		a.scanErrors = append(a.scanErrors, fmt.Errorf("reading committed blobs: %w", err))
	}
}

// recordScannedDigests remembers the digest of bytes this attestor actually
// scanned for a working-directory-relative path. It is append-only and per
// path: two DIFFERENT paths that happen to hold identical bytes are still both
// scanned and both named, because the evidence must name every file it
// covered. Every reader computes the digests as it reads, so this takes them
// rather than the bytes.
func (a *Attestor) recordScannedDigests(path string, digests cryptoutil.DigestSet) {
	if path == "" || len(digests) == 0 {
		return
	}
	if a.scannedDigests == nil {
		a.scannedDigests = map[string][]cryptoutil.DigestSet{}
	}
	a.scannedDigests[path] = append(a.scannedDigests[path], digests)
}

// alreadyScanned reports whether content is byte-for-byte something this
// attestor already scanned for that path, by any route. It compares digests
// computed over buffers this attestor read itself, so no external claim can
// make it answer yes, and it answers no whenever equality cannot be positively
// shown.
func (a *Attestor) alreadyScannedDigests(path string, digests cryptoutil.DigestSet) bool {
	recorded, ok := a.scannedDigests[path]
	if !ok || len(recorded) == 0 || len(digests) == 0 {
		return false
	}
	for _, candidate := range recorded {
		if digestSetsEqual(candidate, digests) {
			return true
		}
	}
	return false
}

// digestSetsEqual compares two digest sets entry for entry. An empty set is
// never equal to anything: absence of evidence is not equality.
func digestSetsEqual(a, b cryptoutil.DigestSet) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for value, hex := range a {
		if b[value] != hex {
			return false
		}
	}
	return true
}

// scanContent is the one place bytes become evidence, whatever they were read
// from. It records them as a subject under key with the digest of exactly the
// bytes scanned, so a subject can never claim coverage of bytes nobody looked
// at, and remembers that digest against path so a later reader of the same
// path can tell it would be rescanning identical bytes. Binaries are skipped
// without error, exactly as products are.
func (a *Attestor) scanContent(ctx *attestation.AttestationContext, key, path, sourceID string, content []byte, detector *detect.Detector) error {
	digests, err := cryptoutil.CalculateDigestSetFromBytes(content, ctx.Hashes())
	if err != nil {
		return fmt.Errorf("digesting: %w", err)
	}
	// Bytes this attestor already scanned for this path are not scanned again,
	// whichever source read them first. This is the ONLY reason a read is
	// skipped here, and it rests on two digests computed over two buffers this
	// attestor read itself — never on an inventory, a label, or a claim.
	if a.alreadyScannedDigests(path, digests) {
		log.Debugf("(attestation/secretscan) %s is byte-identical to content already scanned for that path", key)
		return nil
	}
	if isBinaryFile(http.DetectContentType(content)) {
		log.Debugf("(attestation/secretscan) skipping binary content: %s", key)
		return nil
	}
	findings, err := a.scanBytes(content, sourceID, detector, make(map[string]struct{}), 0)
	if err != nil {
		return err
	}
	for i := range findings {
		findings[i].Location = key
	}
	a.Findings = append(a.Findings, findings...)
	a.subjects[key] = digests
	a.recordScannedDigests(path, digests)
	a.filesScanned++
	return nil
}
