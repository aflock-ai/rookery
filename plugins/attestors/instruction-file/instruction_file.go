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

// Package instructionfile attests the AGENT INSTRUCTION FILES present in a
// workspace — CLAUDE.md, AGENTS.md, SKILLS.md, .cursorrules and their kin —
// so a verifier can pin exactly which standing instructions an autonomous
// agent was operating under when it produced an artifact.
//
// # Why this exists
//
// An instruction file is executable in every sense that matters: it changes
// what an agent does, it is rarely reviewed with the rigor of code, and it is
// invisible in the resulting diff. Signing its digest turns "the agent was
// following the reviewed instructions" from an assumption into a checkable
// claim.
//
// # What it captures, and what it deliberately does not
//
// Digests, sizes, paths and the recognized convention — NOT file content.
// Instruction files routinely carry internal hostnames, ticket numbers and
// occasionally credentials, and a signed attestation is a durable, widely
// readable artifact. The subject digest pins the bytes exactly; a verifier who
// legitimately holds the file can confirm the match, and one who does not
// learns nothing from us.
//
// Like every attestor here this one records FACTS, not a verdict. It does not
// decide whether an instruction file is acceptable. Policy does.
//
// # The signer question
//
// The predicate's Signer block is the reason this attestor is not simply a
// second lockfiles. See signer.go: it distinguishes a credential belonging to
// a human's interactive session from one belonging to a workload, on an axis
// ORTHOGONAL to keyed-versus-keyless, and it is honest about the fact that at
// prematerial time it can only observe the environment. Read PredicateCaveat
// before writing a policy against it.
package instructionfile

import (
	"crypto"
	_ "embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/invopop/jsonschema"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	// Name is the attestor's registered name.
	Name = "instruction-file"

	// Type is the predicate type. It lives in the aflock namespace alongside
	// material/v0.3, product/v0.3, inclusion-proof/v0.1 and scubagoggles/v0.1.
	//
	// This is a FIRST-CLASS aflock predicate rather than an adoption of nono's
	// vendor type or an expression in in-toto SCAI. There is no ratified
	// in-toto predicate for prompts, instructions or agent inputs — the
	// spec's predicates directory contains provenance, vsa, scai,
	// runtime-trace, test-result, release, reference, link, spdx, cyclonedx,
	// vuln and svr, and nothing covering this — so no standard is being
	// ignored. The Statement envelope stays in-toto v1 regardless.
	Type = "https://aflock.ai/attestations/instruction-file/v0.1"

	// RunType is prematerial: instruction files are INPUTS that shape the run,
	// so they must be captured before anything acts on them.
	RunType = attestation.PreMaterialRunType

	// maxFileBytes caps the size of a file this attestor will digest. A file
	// beyond it is recorded with a skip reason rather than silently dropped —
	// absence and refusal are different facts and must not look alike.
	maxFileBytes = 4 << 20 // 4 MiB
)

// PredicateCaveat is the standing, machine-readable statement of what this
// predicate is worth. It is emitted on EVERY run, and it exists because the
// Signer block invites a stronger reading than the evidence supports.
//
// The file digests are strong: they are computed from bytes on disk and a
// verifier can reproduce them. The Signer block is NOT of that character. It
// is derived from environment variables and process state at prematerial time,
// BEFORE any signing has occurred, and any ancestor process can set an
// environment variable. It is corroborating context.
//
// The authoritative check on who signed is the DSSE signing CERTIFICATE — its
// SAN, its issuer, and the Fulcio extensions carrying the workload's
// repository and workflow — enforced by the policy's functionary constraint.
// A policy that gates on signer.kind ALONE can be defeated by setting
// GITHUB_ACTIONS=true. Gate on the certificate; use signer.kind as the
// defense-in-depth cross-check that catches a mismatch between what the
// environment claimed and what the certificate proves.
const PredicateCaveat = "File digests are computed from bytes on disk and are reproducible. " +
	"The signer block is derived from environment variables and process state at prematerial time, " +
	"before signing, and any ancestor process can set an environment variable. " +
	"It is corroborating context, not proof. The authoritative check on signer identity is the " +
	"DSSE signing certificate, enforced by the policy's functionary constraint."

// Compile-time interface checks.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
}

// Scope records whose instructions a file carries.
type Scope string

const (
	// ScopeRepository means the file is committed in the workspace and shared
	// by everyone who checks it out — reviewable through normal code review.
	ScopeRepository Scope = "repository"

	// ScopeDirectory means the file governs only its own subtree. Nested
	// instruction files are a common way for a change to alter agent behavior
	// far from where a reviewer is looking.
	ScopeDirectory Scope = "directory"
)

// MatchKind records how a convention entry is matched against the tree.
type MatchKind string

const (
	// MatchBasename matches the file's base name anywhere in the tree.
	MatchBasename MatchKind = "basename"

	// MatchRelPath matches a declared path relative to the search root — the
	// file AT that path, or, when the path turns out to be a DIRECTORY, every
	// file beneath it.
	//
	// The directory arm is not a special case bolted on for one vendor; it is
	// what makes the kind honest about the pre-gate it must agree with. The
	// gate's file_exists predicate is a stat, and a stat succeeds on a
	// directory. So a declared path that exists as a directory ACTIVATES this
	// attestor, and if matching only ever considered the exact path, the walk
	// would hand inspectFile nothing — WalkDir never passes directories to it —
	// and the run would emit `status: complete` with no subjects while real
	// instructions sat inside.
	//
	// Cursor is the live example: `.cursor/rules` was a single file and is now
	// a `.cursor/rules/` DIRECTORY of `.mdc` rule files. Both shapes are in the
	// wild, and this kind covers each without a second table entry — which
	// matters because the next convention to grow a directory form gets the
	// behaviour for free instead of reproducing the defect.
	MatchRelPath MatchKind = "relpath"
)

// convention is one recognized instruction-file shape. This is the third table
// this package sweeps: every entry must declare a pattern, a non-empty
// convention name, a legal scope and a legal match kind, or conventions_test
// fails. A hand-written list in a test would go stale the moment a new agent
// vendor is added; quantifying over this table cannot.
type convention struct {
	// Pattern is a base name (MatchBasename) or a slash-separated path
	// relative to the search root (MatchRelPath).
	Pattern string

	// Match selects how Pattern is interpreted.
	Match MatchKind

	// Convention is the stable identifier for the agent product or ecosystem
	// this file belongs to.
	Convention string

	// Scope is the default scope for a match; a basename match below the
	// search root is promoted to ScopeDirectory at scan time.
	Scope Scope
}

// conventions lists the instruction-file shapes this attestor recognizes.
//
// Scope note: this is an ALLOWLIST of known conventions, not a heuristic. A
// file it does not recognize is not attested, and that is the honest failure
// mode — silently digesting every Markdown file in a tree would produce a
// predicate whose subjects nobody could reason about.
var conventions = []convention{
	{Pattern: "CLAUDE.md", Match: MatchBasename, Convention: "claude-code", Scope: ScopeRepository},
	{Pattern: "AGENTS.md", Match: MatchBasename, Convention: "agents-md", Scope: ScopeRepository},
	{Pattern: "SKILLS.md", Match: MatchBasename, Convention: "skills-md", Scope: ScopeRepository},
	{Pattern: "GEMINI.md", Match: MatchBasename, Convention: "gemini-cli", Scope: ScopeRepository},
	{Pattern: ".cursorrules", Match: MatchBasename, Convention: "cursor", Scope: ScopeRepository},
	{Pattern: ".windsurfrules", Match: MatchBasename, Convention: "windsurf", Scope: ScopeRepository},
	{Pattern: ".aider.conf.yml", Match: MatchBasename, Convention: "aider", Scope: ScopeRepository},
	{Pattern: ".github/copilot-instructions.md", Match: MatchRelPath, Convention: "github-copilot", Scope: ScopeRepository},
	// Cursor ships BOTH shapes: the legacy form is a single `.cursor/rules`
	// file, the current form a `.cursor/rules/` DIRECTORY holding one `.mdc`
	// per rule. One entry covers both, because MatchRelPath matches the path or
	// anything beneath it when it is a directory. See MatchRelPath for why that
	// is the kind's job rather than a second table row.
	{Pattern: ".cursor/rules", Match: MatchRelPath, Convention: "cursor", Scope: ScopeRepository},
}

// conventionDirs is the set of directory paths, relative and slash-separated,
// that a declared convention requires the walk to ENTER. Derived from the
// conventions table rather than written out, so a convention added under a new
// dot-directory becomes reachable without a second edit here.
var conventionDirs = deriveConventionDirs()

func deriveConventionDirs() map[string]bool {
	out := map[string]bool{}
	for _, c := range conventions {
		if c.Match == MatchBasename {
			continue
		}
		p := strings.TrimSuffix(c.Pattern, "/")
		for {
			i := strings.LastIndex(p, "/")
			if i < 0 {
				break
			}
			p = p[:i]
			out[p] = true
		}
	}
	return out
}

// shouldDescendDir decides whether the walk enters one directory.
//
// The hidden-directory rule exists to keep this scan in AGREEMENT with the
// detector that decides whether the scan runs at all. The pre-gate's recursive
// glob walk does not descend hidden directories (shouldDescend in
// attestation/detection/preds_static.go), so a basename match underneath one
// could be found by the scan but could never activate the attestor. That
// disagreement is silent in the worst way: a workspace whose only CLAUDE.md
// sat in `.hidden/` produced no predicate at all, while an otherwise-activated
// run would have digested it — the same evidence present or absent depending
// on an unrelated file elsewhere in the tree.
//
// Hidden directories a declared convention names — `.github`, `.cursor` — are
// still entered, because the pre-gate reaches those through exact file_exists
// paths rather than through the glob walk. Basename matches beneath them stay
// refused; see underHiddenDir.
func shouldDescendDir(rel, name string) bool {
	// Inside a DECLARED convention subtree every directory is in scope, and
	// neither the ignore list nor the hidden rule may prune it.
	//
	// Both of those rules exist to keep the general walk in agreement with the
	// pre-gate's recursive glob, which is a statement about where the scan goes
	// LOOKING. They have no business inside a subtree the pre-gate named
	// outright: `.cursor/rules` activates this attestor through an exact
	// file_exists stat, not through the glob, so the glob's pruning rules never
	// applied to its contents in the first place.
	//
	// Applying them anyway produced the failure this attestor exists to
	// remove. `.cursor/rules/vendor/rule.mdc` is a real Cursor rule file:
	// `vendor` is on the ignore list, so the walk skipped it, no record was
	// made, no warning was raised, and the predicate reported `status:
	// complete` for a workspace whose instructions it had silently declined to
	// read. `.cursor/rules/.private/rule.mdc` failed the same way through the
	// hidden rule. A control that reports "fine" when it did not look is worse
	// than no control.
	if underDeclaredConventionTree(rel) {
		return true
	}
	if ignoredDirs[name] {
		return false
	}
	if strings.HasPrefix(name, ".") && !conventionDirs[rel] {
		return false
	}
	return true
}

// underDeclaredConventionTree reports whether rel is a declared relative-path
// convention or sits beneath one.
//
// Derived from the conventions table rather than written out, so a convention
// that grows a directory form is covered here the day it is added rather than
// on the day someone remembers this function exists. The trailing separator on
// the prefix is required: without it ".cursor/rulesX" would count as being
// inside ".cursor/rules", which is the same off-by-one matchConvention guards
// against for the same reason.
func underDeclaredConventionTree(rel string) bool {
	for _, c := range conventions {
		if c.Match != MatchRelPath {
			continue
		}
		p := strings.TrimSuffix(c.Pattern, "/")
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

// underHiddenDir reports whether any DIRECTORY component of rel is hidden.
//
// A base-name convention is only recognized outside hidden directories, which
// is precisely the reach of the pre-gate's glob walk. Without this, descending
// `.github` for copilot-instructions.md would also make `.github/CLAUDE.md`
// scannable — a file the detector's glob can never see, reopening the same
// disagreement one directory deeper.
func underHiddenDir(rel string) bool {
	parts := strings.Split(rel, "/")
	for _, p := range parts[:len(parts)-1] {
		if strings.HasPrefix(p, ".") {
			return true
		}
	}
	return false
}

// ignoredDirs are skipped during the walk. Mirrors the lockfiles attestor:
// a vendored dependency's instruction file is not this workspace's evidence.
var ignoredDirs = map[string]bool{
	"node_modules": true,
	"vendor":       true,
	".git":         true,
	".svn":         true,
	".hg":          true,
	"__pycache__":  true,
	"venv":         true,
	".venv":        true,
	"target":       true,
	"build":        true,
	"dist":         true,
}

// InstructionFile is one discovered instruction file.
type InstructionFile struct {
	// Path is relative to the search root, always slash-separated so the
	// predicate is identical on Windows and Unix.
	Path string `json:"path"`

	// Digest is the SHA-256 of the file's bytes. Empty only when SkipReason
	// explains why it could not be computed.
	Digest cryptoutil.DigestSet `json:"digest,omitempty"`

	// SizeBytes is the file's size on disk.
	SizeBytes int64 `json:"sizeBytes"`

	// Convention identifies the agent product or ecosystem.
	Convention string `json:"convention"`

	// Scope records whether the file governs the whole workspace or a subtree.
	Scope Scope `json:"scope"`

	// SkipReason, when non-empty, states why the file was found but not
	// digested. A present-but-undigested file is a DIFFERENT fact from an
	// absent one, and collapsing the two is how a policy comes to believe a
	// file it never saw was clean.
	SkipReason string `json:"skipReason,omitempty"`
}

// ScanStatus is the outcome of the walk itself, distinct from whether any
// instruction file was found.
type ScanStatus string

const (
	// StatusComplete means the walk finished and every directory under the
	// search root was examined. A Files list that is empty under this status
	// is a positive claim: this workspace has no recognized instruction files.
	StatusComplete ScanStatus = "complete"

	// StatusIncomplete means the walk started but did not examine everything —
	// an unreadable directory, a traversal error. NOTHING is claimed about the
	// unexamined remainder. A policy requiring "no unreviewed instruction
	// files" must treat incomplete the way it treats unavailable, never as
	// complete-and-empty.
	StatusIncomplete ScanStatus = "incomplete"

	// StatusUnavailable means the walk could not be performed at all.
	StatusUnavailable ScanStatus = "unavailable"
)

// AllScanStatuses returns every declared ScanStatus in sorted order.
func AllScanStatuses() []ScanStatus {
	return []ScanStatus{StatusComplete, StatusIncomplete, StatusUnavailable}
}

// Attestor captures the workspace's agent instruction files.
type Attestor struct {
	// Files are the discovered instruction files, sorted by path so the
	// predicate is byte-identical across runs on the same tree.
	Files []InstructionFile `json:"files"`

	// Signer states the principal class of the credential that will sign this
	// attestation. See signer.go and PredicateCaveat.
	Signer Signer `json:"signer"`

	// Status is the outcome of the walk. Required — see ScanStatus.
	Status ScanStatus `json:"status"`

	// Warnings name what went wrong during the walk, sorted.
	Warnings []string `json:"warnings,omitempty"`

	// Caveat is the standing machine-readable disclaimer, always PredicateCaveat.
	Caveat string `json:"caveat"`

	// searchRoot is the directory the walk starts from. Unexported: it is
	// process state, not evidence.
	searchRoot string
}

// New returns an Attestor with an empty, non-nil Files slice so the predicate
// serializes `"files": []` rather than `"files": null`. A null there reads to a
// rego policy as an absent key, which is exactly the absence-as-permission trap
// the Status field exists to close.
func New() *Attestor {
	return &Attestor{
		Files:  []InstructionFile{},
		Status: StatusUnavailable,
		Caveat: PredicateCaveat,
	}
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }

// Schema returns the attestor's JSON Schema. The Signer sub-schema carries the
// conditional constraints generated in Signer.JSONSchemaExtend.
func (a *Attestor) Schema() *jsonschema.Schema { return jsonschema.Reflect(a) }

// Attest walks the workspace for recognized instruction files and records the
// signer context.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	root := a.searchRoot
	if root == "" {
		root = ctx.WorkingDir()
	}
	if root == "" {
		root = "."
	}

	a.Caveat = PredicateCaveat
	a.Signer = detectSigner(os.Getenv, stdinIsTTY())

	files, warnings, err := scan(root)
	a.Files = files
	a.Warnings = warnings
	sort.Strings(a.Warnings)

	switch {
	case err != nil:
		a.Status = StatusUnavailable
		return fmt.Errorf("instruction-file scan failed under %s: %w", root, err)
	case len(warnings) > 0:
		// Fail closed: a walk that could not read part of the tree makes no
		// claim about the part it did not read.
		a.Status = StatusIncomplete
	case anyFileSkipped(files):
		// Fail closed again, for the case warnings do NOT cover.
		//
		// Most refusals here are not walk errors and deliberately raise no
		// warning: a symlink, a non-regular entry and an over-cap file are all
		// ORDINARY findings about a file that was located successfully. They
		// were therefore invisible to the check above, while contributing no
		// subject either, because Subjects skips a record with no digest.
		//
		// The two together produced the worst possible predicate. A workspace
		// whose only CLAUDE.md is a symlink emitted `status: complete` with an
		// empty subject list — a signed statement that the tree was fully
		// examined and contained nothing, when in fact the one file that
		// mattered was found and refused. A policy reading that sees a clean
		// result, which is the precise failure this attestor exists to remove:
		// a control that reports "fine" when it did not look stops anyone
		// looking.
		//
		// A file this attestor declined to digest makes the scan incomplete.
		// The record and its SkipReason still travel, so the reason is legible;
		// what changes is that the predicate no longer claims completeness it
		// does not have.
		a.Status = StatusIncomplete
	default:
		a.Status = StatusComplete
	}

	return nil
}

// anyFileSkipped reports whether any matched file was located but not digested.
func anyFileSkipped(files []InstructionFile) bool {
	for _, f := range files {
		if f.SkipReason != "" {
			return true
		}
	}
	return false
}

// Subjects returns one subject per digested instruction file, keyed
// `instructionfile:<path>` with the file's own SHA-256 as the digest.
//
// The digest is the FILE's, not a hash of its path, so the subject joins by
// content: two runs that saw the same CLAUDE.md produce the same digest, and a
// policy can pin an approved instruction file by digest across repositories.
// Files skipped without a digest contribute no subject — a subject with no
// digest would be an anchor to nothing.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	for _, f := range a.Files {
		if len(f.Digest) == 0 {
			continue
		}
		subjects[fmt.Sprintf("instructionfile:%s", f.Path)] = f.Digest
	}
	return subjects
}

// scan walks root and returns the recognized instruction files sorted by path,
// plus any warnings. A per-entry error becomes a warning rather than aborting:
// one unreadable directory should downgrade the claim to incomplete, not
// destroy the evidence for the rest of the tree.
// resolveScanRoot canonicalizes and validates the search root before a sweep.
//
// The ROOT itself is resolved through its symlinks first. os.Stat and
// os.OpenRoot follow a symlinked root, but filepath.WalkDir lstats it and
// enumerates nothing — so a symlinked working directory (macOS /tmp, direnv
// layouts) would sign `status: complete` over an empty file list. Resolving
// once up front makes all three observers agree on the same real directory;
// the in-walk no-follow guarantees are unchanged, because they concern
// components UNDER the root, which are still opened through the pinned root
// handle.
func resolveScanRoot(root string) (string, error) {
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("search root %s is not a directory", resolved)
	}
	return resolved, nil
}

func scan(root string) ([]InstructionFile, []string, error) {
	root, err := resolveScanRoot(root)
	if err != nil {
		return []InstructionFile{}, nil, err
	}

	// One root handle for the whole walk. Every instruction file is opened
	// THROUGH it, so no ancestor component of any path is resolved by name
	// again after the walk observed it. A directory swapped for a symlink mid
	// walk therefore cannot redirect a digest outside the workspace, whatever
	// WalkDir happened to enumerate.
	rootHandle, rootErr := os.OpenRoot(root)
	if rootErr != nil {
		return []InstructionFile{}, nil, rootErr
	}
	defer func() { _ = rootHandle.Close() }()

	files := []InstructionFile{}
	warnings := []string{}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("unreadable path %s: %v", relSlash(root, path), err))
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if path != root && !shouldDescendDir(relSlash(root, path), d.Name()) {
				return fs.SkipDir
			}
			return nil
		}

		f, warning, matched := inspectFile(rootHandle, root, path, d)
		if !matched {
			return nil
		}
		files = append(files, f)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		return nil
	})

	if walkErr != nil {
		log.Debugf("(attestation/instruction-file) walk error under %s: %v", root, walkErr)
		return files, warnings, walkErr
	}

	// Deterministic ordering: signed evidence must not vary with filesystem
	// enumeration order.
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, warnings, nil
}

// inspectFile decides whether one walked entry is a recognized instruction file
// and, if so, builds its record.
//
// It returns the record, an optional warning, and whether the entry matched at
// all. Every failure to digest produces a RECORD with a SkipReason rather than
// a dropped entry: a file found and refused is a different fact from a file
// that was never there, and collapsing the two is how a policy comes to believe
// a file it never saw was clean.
//
// # One open, one handle
//
// This function opens the file EXACTLY ONCE, and every fact it publishes — the
// entry's type, its size, its digest — is read off that one descriptor. It does
// not stat a path and then read the same path, because those are two different
// questions asked at two different moments and nothing guarantees the same file
// answers both.
//
// The previous shape did exactly that: WalkDir's lstat classified a regular
// file, and a later os.ReadFile re-resolved the name. A path replaced in
// between — the classification still cached and no longer true — turned the
// attestor into a content-confirmation ORACLE. Plant a symlink where CLAUDE.md
// belongs and the SHA-256 of any file the build user can read is published into
// signed evidence, as a subject, keyed by a path those bytes never came from.
// The digest is genuine, the signature verifies, and the statement is false,
// which is the worst shape a supply-chain claim can take. A FIFO in the same
// position was worse still in a different direction: the read blocked forever
// and no evidence was ever produced at all.
//
// The same defect class cost the sibling alps-evidence attestor four review
// rounds (see plugins/attestors/alps-evidence/fsutil.go). Its lesson is the one
// applied here — the defect kept coming back because it was EXPRESSIBLE in many
// places, so the fix is to leave exactly one place able to express it.
func inspectFile(rootHandle *os.Root, root, path string, d fs.DirEntry) (InstructionFile, string, bool) {
	conv, ok := matchConvention(root, path, d.Name())
	if !ok {
		return InstructionFile{}, "", false
	}

	rel := relSlash(root, path)
	f := InstructionFile{
		Path:       rel,
		Convention: conv.Convention,
		Scope:      scopeFor(conv, root, path),
	}

	// The path handed to the opener is relative to the root handle, so the
	// ancestors are resolved under it rather than re-walked by name.
	relNative, relErr := filepath.Rel(root, path)
	if relErr != nil {
		f.SkipReason = fmt.Sprintf("path resolution failed: %v", relErr)
		return f, fmt.Sprintf("path resolution failed for %s: %v", rel, relErr), true
	}

	// A symlink the walk already knows about is refused here without an open.
	// This is NOT the security boundary — a link swapped in after the walk
	// classified the entry is still cached as a regular file at this point, and
	// only the open below catches that. It earns its place for two other
	// reasons: it avoids a syscall in the common case, and it is the only
	// symlink defense on platforms whose open(2) has no O_NOFOLLOW, where
	// openInstructionFile cannot refuse a leaf link on its own — see
	// openat_other.go for exactly what that fallback does and does not
	// guarantee.
	if d.Type()&fs.ModeSymlink != 0 {
		f.SkipReason = "symlink not followed"
		return f, "", true
	}

	// THE open. Everything below reads from this descriptor.
	//
	// Ancestors are resolved under the root handle so no parent component can
	// redirect the read outside the workspace, and the final component is
	// opened with no-follow semantics where the platform provides them. See
	// openat_unix.go for why both halves are required and openat_other.go for
	// what the non-Unix fallback does and does not guarantee.
	handle, openErr := openInstructionFile(rootHandle, relNative)
	if openErr != nil {
		if isSymlinkRefusal(openErr) {
			// The entry became a symlink between the walk's lstat and this
			// open. Reported exactly like a statically-known link: the
			// predicate should not distinguish "was a link" from "became one".
			f.SkipReason = "symlink not followed"
			return f, "", true
		}
		f.SkipReason = fmt.Sprintf("open failed: %v", openErr)
		return f, fmt.Sprintf("open failed for %s: %v", rel, openErr), true
	}
	defer func() { _ = handle.Close() }()

	// fstat on the HANDLE, never a second stat on the path.
	fi, statErr := handle.Stat()
	if statErr != nil {
		f.SkipReason = fmt.Sprintf("stat failed: %v", statErr)
		return f, fmt.Sprintf("stat failed for %s: %v", rel, statErr), true
	}

	// A directory, device or socket is not an instruction file. On a platform
	// without O_NOFOLLOW this check is also what stops a swapped symlink to a
	// non-regular target; a link to a regular file there is still caught by the
	// DirEntry check above in every case the walk classified.
	if !fi.Mode().IsRegular() {
		f.SkipReason = "not a regular file"
		return f, "", true
	}
	f.SizeBytes = fi.Size()

	if fi.Size() > maxFileBytes {
		f.SkipReason = fmt.Sprintf("exceeds %d byte cap", int64(maxFileBytes))
		return f, "", true
	}

	// The read goes one byte PAST the cap on purpose. A file exactly at the cap
	// is still digested, one over it is caught by the READ rather than trusted
	// from a size measured earlier, and a file that grew between the fstat and
	// here cannot spend more than one byte of extra memory.
	content, readErr := io.ReadAll(io.LimitReader(handle, maxFileBytes+1))
	if readErr != nil {
		f.SkipReason = fmt.Sprintf("read failed: %v", readErr)
		return f, fmt.Sprintf("read failed for %s: %v", rel, readErr), true
	}
	if int64(len(content)) > maxFileBytes {
		f.SkipReason = fmt.Sprintf("exceeds %d byte cap", int64(maxFileBytes))
		return f, "", true
	}

	// The published size is the size of the bytes that were actually digested,
	// not the one fstat reported a moment earlier. Two fields describing the
	// same file must not be able to disagree.
	f.SizeBytes = int64(len(content))

	digest, digestErr := cryptoutil.CalculateDigestSetFromBytes(content, []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
	})
	if digestErr != nil {
		f.SkipReason = fmt.Sprintf("digest failed: %v", digestErr)
		return f, fmt.Sprintf("digest failed for %s: %v", rel, digestErr), true
	}

	f.Digest = digest
	return f, "", true
}

// matchConvention returns the convention matching this file, if any. Exact
// relative-path entries are checked before base-name entries so a more
// specific rule wins.
func matchConvention(root, path, base string) (convention, bool) {
	rel := relSlash(root, path)
	for _, c := range conventions {
		if c.Match != MatchRelPath {
			continue
		}
		// The path itself, or anything beneath it when it is a directory. The
		// separator in the prefix is required: without it ".cursor/rulesX"
		// would match a convention declared as ".cursor/rules".
		if c.Pattern == rel || strings.HasPrefix(rel, c.Pattern+"/") {
			return c, true
		}
	}
	// Base names are recognized only outside hidden directories, which is
	// exactly the reach of the pre-gate's glob walk. See underHiddenDir.
	if underHiddenDir(rel) {
		return convention{}, false
	}
	for _, c := range conventions {
		if c.Match == MatchBasename && c.Pattern == base {
			return c, true
		}
	}
	return convention{}, false
}

// scopeFor promotes a base-name match found below the search root to directory
// scope: a nested CLAUDE.md governs its subtree, not the workspace.
func scopeFor(c convention, root, path string) Scope {
	if c.Match != MatchBasename {
		return c.Scope
	}
	if strings.Contains(relSlash(root, path), "/") {
		return ScopeDirectory
	}
	return c.Scope
}

// relSlash renders path relative to root with forward slashes, so a predicate
// produced on Windows is byte-identical to one produced on Unix.
func relSlash(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
