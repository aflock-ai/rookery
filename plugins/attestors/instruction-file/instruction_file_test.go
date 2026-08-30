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

package instructionfile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/invopop/jsonschema"
	tekuri "github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"
)

// ---------------------------------------------------------------------------
// Sweeps over the conventions table.
// ---------------------------------------------------------------------------

// TestSweep_EveryConventionIsWellFormed asserts each entry declares a usable
// pattern, a convention name and legal enums, and that the match kind agrees
// with the pattern's shape. A relpath entry with no separator would silently
// never match; a basename entry containing one would too.
func TestSweep_EveryConventionIsWellFormed(t *testing.T) {
	if len(conventions) == 0 {
		t.Fatal("conventions table is empty — this attestor could never find anything")
	}

	legalScopes := map[Scope]bool{ScopeRepository: true, ScopeDirectory: true}
	legalMatches := map[MatchKind]bool{MatchBasename: true, MatchRelPath: true}
	seen := map[string]bool{}

	for _, c := range conventions {
		t.Run(c.Pattern, func(t *testing.T) {
			if strings.TrimSpace(c.Pattern) == "" {
				t.Error("empty Pattern")
			}
			if seen[string(c.Match)+"|"+c.Pattern] {
				t.Errorf("duplicate pattern %q for match kind %q; the first entry always wins", c.Pattern, c.Match)
			}
			seen[string(c.Match)+"|"+c.Pattern] = true

			if strings.TrimSpace(c.Convention) == "" {
				t.Errorf("pattern %q has an empty Convention name", c.Pattern)
			}
			if !legalScopes[c.Scope] {
				t.Errorf("pattern %q has illegal scope %q", c.Pattern, c.Scope)
			}
			if !legalMatches[c.Match] {
				t.Errorf("pattern %q has illegal match kind %q", c.Pattern, c.Match)
			}

			switch c.Match {
			case MatchBasename:
				if strings.Contains(c.Pattern, "/") {
					t.Errorf("basename pattern %q contains a separator; it can never match a base name", c.Pattern)
				}
			case MatchRelPath:
				if !strings.Contains(c.Pattern, "/") {
					t.Errorf("relpath pattern %q has no separator; declare it as a basename match instead", c.Pattern)
				}
				if filepath.IsAbs(c.Pattern) {
					t.Errorf("relpath pattern %q is absolute; patterns are relative to the search root", c.Pattern)
				}
			}
		})
	}
}

// writeTreeForAllConventions materializes a workspace containing EVERY entry in
// the conventions table, and returns the root plus the relative paths written.
func writeTreeForAllConventions(t *testing.T) (string, []string) {
	t.Helper()
	root := t.TempDir()
	written := make([]string, 0, len(conventions))

	for i, c := range conventions {
		rel := c.Pattern
		if c.Match == MatchBasename {
			rel = c.Pattern
		}
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %q: %v", rel, err)
		}
		// Distinct content per file so digests differ and a mixed-up mapping
		// between path and digest cannot pass unnoticed.
		body := strings.Repeat("instruction ", i+1) + c.Convention + "\n"
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("write %q: %v", rel, err)
		}
		written = append(written, rel)
	}
	return root, written
}

// TestSweep_EveryConventionIsDiscovered is the derived-set test that makes the
// conventions table authoritative: it builds a tree containing every declared
// entry and asserts the scan finds each one, with the right convention name and
// a real digest. A convention added to the table but not wired into matching
// fails here on the day it is added.
func TestSweep_EveryConventionIsDiscovered(t *testing.T) {
	root, written := writeTreeForAllConventions(t)

	files, warnings, err := scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings on a clean tree: %v", warnings)
	}

	byPath := map[string]InstructionFile{}
	for _, f := range files {
		byPath[f.Path] = f
	}

	for i, c := range conventions {
		rel := written[i]
		t.Run(rel, func(t *testing.T) {
			got, ok := byPath[rel]
			if !ok {
				t.Fatalf("convention %q (pattern %q) was written to the tree but not discovered; got paths %v", c.Convention, c.Pattern, sortedKeys(byPath))
			}
			if got.Convention != c.Convention {
				t.Errorf("convention = %q, want %q", got.Convention, c.Convention)
			}
			if len(got.Digest) == 0 {
				t.Errorf("no digest recorded for %q", rel)
			}
			if got.SkipReason != "" {
				t.Errorf("unexpected skip reason %q", got.SkipReason)
			}
			if got.SizeBytes <= 0 {
				t.Errorf("sizeBytes = %d, want > 0", got.SizeBytes)
			}
		})
	}
}

// TestSweep_EveryConventionProducesASubject asserts every discovered file
// contributes a subject, derived from the same table. Subjects are how a policy
// pins an approved instruction file, so a convention that produces no subject is
// invisible to verification.
func TestSweep_EveryConventionProducesASubject(t *testing.T) {
	root, written := writeTreeForAllConventions(t)

	a := New()
	a.searchRoot = root
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}

	subjects := a.Subjects()
	for _, rel := range written {
		key := "instructionfile:" + rel
		ds, ok := subjects[key]
		if !ok {
			t.Errorf("no subject %q; declared conventions must be verifiable", key)
			continue
		}
		if len(ds) == 0 {
			t.Errorf("subject %q has an empty digest set", key)
		}
	}
}

// TestSubjectDigestIsTheFileNotThePath pins the join semantics. The subject
// digest must be the SHA-256 of the file's BYTES, so an approved instruction
// file can be pinned by digest across repositories. Hashing the path instead
// would silently produce a subject that joins on nothing.
func TestSubjectDigestIsTheFileNotThePath(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	body := []byte("# identical instructions\n")

	if err := os.WriteFile(filepath.Join(rootA, "CLAUDE.md"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	// Same content, DIFFERENT path.
	if err := os.MkdirAll(filepath.Join(rootB, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootB, "sub", "CLAUDE.md"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	digestOf := func(root string) string {
		a := New()
		a.searchRoot = root
		if err := a.Attest(&attestation.AttestationContext{}); err != nil {
			t.Fatalf("attest: %v", err)
		}
		for _, ds := range a.Subjects() {
			for _, v := range ds {
				return v
			}
		}
		t.Fatalf("no subject produced under %s", root)
		return ""
	}

	if got, want := digestOf(rootB), digestOf(rootA); got != want {
		t.Errorf("identical content at different paths produced different digests (%q vs %q); the subject is not joining on content", got, want)
	}
}

// TestNestedInstructionFileIsDirectoryScoped asserts a nested match is promoted
// to directory scope. A nested instruction file is a common way to alter agent
// behavior far from where a reviewer is looking, so the predicate must
// distinguish it from a root-level one.
func TestNestedInstructionFileIsDirectoryScoped(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("root\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pkg", "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkg", "deep", "CLAUDE.md"), []byte("nested\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	files, _, err := scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	scopes := map[string]Scope{}
	for _, f := range files {
		scopes[f.Path] = f.Scope
	}
	if scopes["CLAUDE.md"] != ScopeRepository {
		t.Errorf("root CLAUDE.md scope = %q, want repository", scopes["CLAUDE.md"])
	}
	if scopes["pkg/deep/CLAUDE.md"] != ScopeDirectory {
		t.Errorf("nested CLAUDE.md scope = %q, want directory", scopes["pkg/deep/CLAUDE.md"])
	}
}

// TestIgnoredDirsAreSkipped asserts a vendored dependency's instruction file is
// not attested as this workspace's evidence.
func TestIgnoredDirsAreSkipped(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "pkg", "CLAUDE.md"), []byte("vendored\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	files, _, err := scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range files {
		if strings.HasPrefix(f.Path, "node_modules/") {
			t.Errorf("attested a vendored instruction file %q", f.Path)
		}
	}
}

// TestUnrecognizedFilesAreNotAttested pins the allowlist property. The
// conventions table is an allowlist, not a heuristic: silently digesting every
// Markdown file in a tree would produce a predicate whose subjects nobody could
// reason about. The decoys below sit right next to real matches and include
// near-misses on both match kinds.
func TestUnrecognizedFilesAreNotAttested(t *testing.T) {
	root := t.TempDir()

	// One genuine match, so the scan is not trivially empty.
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("real\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	decoys := []string{
		"README.md",
		"NOTES.md",
		"claude.md",               // wrong case
		"CLAUDE.markdown",         // wrong extension
		"CLAUDE.md.bak",           // suffixed
		"copilot-instructions.md", // relpath convention, but at the wrong location
		"docs/AGENTS.txt",         // wrong extension, nested
	}
	for _, rel := range decoys {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("decoy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	files, _, err := scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	got := map[string]bool{}
	for _, f := range files {
		got[f.Path] = true
	}
	if !got["CLAUDE.md"] {
		t.Error("the genuine CLAUDE.md was not attested; the test is not exercising a real match")
	}
	for _, rel := range decoys {
		if got[rel] {
			t.Errorf("attested unrecognized file %q; the conventions table must be an allowlist", rel)
		}
	}
	if len(files) != 1 {
		t.Errorf("expected exactly 1 attested file, got %d: %v", len(files), sortedKeys(got))
	}
}

// TestUnreadableInstructionFileIsRecordedAndDowngradesStatus covers the
// read-failure path inside inspectFile: a matched file we could not read must be
// RECORDED with a reason, must contribute no subject, and must downgrade the
// scan to incomplete.
func TestUnreadableInstructionFileIsRecordedAndDowngradesStatus(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission bits do not restrict reads")
	}
	root := t.TempDir()
	target := filepath.Join(root, "CLAUDE.md")
	if err := os.WriteFile(target, []byte("secret instructions\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o600) })

	a := New()
	a.searchRoot = root
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}

	if len(a.Files) != 1 {
		t.Fatalf("expected the unreadable file to be RECORDED, got %d files", len(a.Files))
	}
	if a.Files[0].SkipReason == "" {
		t.Error("unreadable file carries no SkipReason; refusal must be visible")
	}
	if len(a.Files[0].Digest) != 0 {
		t.Error("unreadable file carries a digest")
	}
	if len(a.Subjects()) != 0 {
		t.Error("unreadable file contributed a subject; a subject with no digest anchors to nothing")
	}
	if a.Status != StatusIncomplete {
		t.Errorf("status = %q, want incomplete — a file we could not read means the claim is partial", a.Status)
	}
	if len(a.Warnings) == 0 {
		t.Error("expected a warning naming the unreadable file")
	}
}

// TestSymlinkedInstructionFileIsRecordedButNotFollowed asserts a symlinked
// instruction file is recorded (its presence is evidence) but not digested,
// since it could point outside the workspace entirely.
func TestSymlinkedInstructionFileIsRecordedButNotFollowed(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "elsewhere.md")
	if err := os.WriteFile(target, []byte("instructions from outside the workspace\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	link := filepath.Join(root, "CLAUDE.md")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}

	files, _, err := scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected the symlink to be RECORDED, got %d files", len(files))
	}
	if files[0].SkipReason != "symlink not followed" {
		t.Errorf("SkipReason = %q, want %q", files[0].SkipReason, "symlink not followed")
	}
	if len(files[0].Digest) != 0 {
		t.Error("the symlink was digested; its target may lie outside the workspace")
	}
}

// TestContentIsNeverRecorded is a privacy gate. Instruction files routinely
// carry internal hostnames and occasionally credentials, and a signed
// attestation is durable and widely readable. If someone adds a Content field
// later, this fails.
func TestContentIsNeverRecorded(t *testing.T) {
	root := t.TempDir()
	const secret = "SUPER-SECRET-CANARY-VALUE-do-not-sign-me"
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("# rules\n"+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := New()
	a.searchRoot = root
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Errorf("instruction file content leaked into the predicate: %s", raw)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed status contract.
// ---------------------------------------------------------------------------

// TestEmptyTreeIsCompleteNotUnavailable asserts an empty result under a readable
// tree is a POSITIVE claim ("this workspace has no instruction files"), distinct
// from "we could not look".
func TestEmptyTreeIsCompleteNotUnavailable(t *testing.T) {
	a := New()
	a.searchRoot = t.TempDir()
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if a.Status != StatusComplete {
		t.Errorf("status = %q on a readable empty tree, want complete", a.Status)
	}
	if len(a.Files) != 0 {
		t.Errorf("expected no files, got %v", a.Files)
	}
}

// TestFilesSerializesAsEmptyArrayNotNull closes the absence-as-permission trap:
// a `null` reads to rego as an absent key, so a policy checking the file list
// would see nothing rather than an empty list.
func TestFilesSerializesAsEmptyArrayNotNull(t *testing.T) {
	a := New()
	a.searchRoot = t.TempDir()
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"files":[]`)) {
		t.Errorf("files did not serialize as an empty array: %s", raw)
	}
}

// TestAttestOnMissingRootReportsUnavailable covers the early-return path: when
// the search root cannot even be stat'd, the status must be `unavailable` (we
// could not look), never `complete` (we looked and found nothing), and the file
// list must still serialize as an array rather than null.
func TestAttestOnMissingRootReportsUnavailable(t *testing.T) {
	a := New()
	a.searchRoot = filepath.Join(t.TempDir(), "does-not-exist")

	err := a.Attest(&attestation.AttestationContext{})
	if err == nil {
		t.Fatal("expected an error when the search root does not exist")
	}
	if a.Status != StatusUnavailable {
		t.Errorf("status = %q, want unavailable — a root we could not read must never read as an empty workspace", a.Status)
	}
	raw, marshalErr := json.Marshal(a)
	if marshalErr != nil {
		t.Fatalf("marshal: %v", marshalErr)
	}
	if !bytes.Contains(raw, []byte(`"files":[]`)) {
		t.Errorf("files did not serialize as an empty array on the error path: %s", raw)
	}
}

// TestAttestOnNonDirectoryRootReportsUnavailable covers the second early return.
func TestAttestOnNonDirectoryRootReportsUnavailable(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := New()
	a.searchRoot = file
	if err := a.Attest(&attestation.AttestationContext{}); err == nil {
		t.Fatal("expected an error when the search root is not a directory")
	}
	if a.Status != StatusUnavailable {
		t.Errorf("status = %q, want unavailable", a.Status)
	}
}

// TestFilesAreSortedByPath asserts the predicate's file ordering is explicitly
// sorted. filepath.WalkDir happens to enumerate lexically today, so a
// determinism test alone cannot tell whether the sort is load-bearing; this
// asserts the property directly.
func TestFilesAreSortedByPath(t *testing.T) {
	root, _ := writeTreeForAllConventions(t)
	files, _, err := scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("need at least two files to check ordering, got %d", len(files))
	}
	for i := 1; i < len(files); i++ {
		if files[i-1].Path >= files[i].Path {
			t.Errorf("files are not sorted by path: %q came before %q", files[i-1].Path, files[i].Path)
		}
	}
}

// TestOversizedFileIsRecordedWithoutDigestAndProducesNoSubject covers the
// present-but-undigested case. A file found and refused is a DIFFERENT fact
// from a file that was never there, so it must appear in the predicate with a
// reason — and it must NOT contribute a subject, because a subject with no
// digest is an anchor to nothing.
func TestOversizedFileIsRecordedWithoutDigestAndProducesNoSubject(t *testing.T) {
	root := t.TempDir()
	big := bytes.Repeat([]byte("x"), maxFileBytes+1)
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), big, 0o600); err != nil {
		t.Fatal(err)
	}

	a := New()
	a.searchRoot = root
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}

	if len(a.Files) != 1 {
		t.Fatalf("expected the oversized file to be RECORDED, got %d files", len(a.Files))
	}
	got := a.Files[0]
	if got.SkipReason == "" {
		t.Error("oversized file carries no SkipReason; refusal must be visible, not silent")
	}
	if len(got.Digest) != 0 {
		t.Error("oversized file carries a digest but was supposed to be skipped")
	}
	if n := len(a.Subjects()); n != 0 {
		t.Errorf("expected no subjects for an undigested file, got %d: %v", n, sortedKeys(a.Subjects()))
	}
}

// TestUnreadableDirDowngradesToIncomplete asserts a walk that could not read
// part of the tree makes no claim about the part it did not read.
func TestUnreadableDirDowngradesToIncomplete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission bits do not restrict the walk")
	}
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.MkdirAll(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "CLAUDE.md"), []byte("hidden\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	a := New()
	a.searchRoot = root
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if a.Status != StatusIncomplete {
		t.Errorf("status = %q with an unreadable directory, want incomplete — a partial walk must never read as a complete one", a.Status)
	}
	if len(a.Warnings) == 0 {
		t.Error("expected a warning naming the unreadable path")
	}
}

// TestCaveatIsAlwaysEmitted asserts the standing disclaimer is present on every
// run. It is the field that stops a reader over-trusting the signer block.
func TestCaveatIsAlwaysEmitted(t *testing.T) {
	a := New()
	a.searchRoot = t.TempDir()
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if a.Caveat != PredicateCaveat {
		t.Errorf("caveat = %q, want the standing PredicateCaveat", a.Caveat)
	}
	// The caveat is load-bearing prose: it is the field that stops a reader
	// treating the environment-derived signer block as proof. Each clause below
	// is a distinct claim the caveat must make, so dropping any one is caught.
	for _, required := range []string{
		"certificate",  // names the actual authority on signer identity
		"environment",  // names where the signer block really came from
		"reproducible", // distinguishes the strong half (digests) from the weak
	} {
		if !strings.Contains(a.Caveat, required) {
			t.Errorf("caveat does not mention %q; it must distinguish the reproducible file digests from the environment-derived signer block, and name the certificate as the authority: %q", required, a.Caveat)
		}
	}
}

// TestAttestIsDeterministic asserts repeated runs over the same tree produce a
// byte-identical predicate. Directory enumeration order is not guaranteed, and
// signed evidence that varies run to run cannot be reproduced by a verifier.
func TestAttestIsDeterministic(t *testing.T) {
	root, _ := writeTreeForAllConventions(t)

	run := func() []byte {
		a := New()
		a.searchRoot = root
		if err := a.Attest(&attestation.AttestationContext{}); err != nil {
			t.Fatalf("attest: %v", err)
		}
		raw, err := json.Marshal(a.Files)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return raw
	}

	first := run()
	for i := 0; i < 10; i++ {
		if next := run(); !bytes.Equal(first, next) {
			t.Fatalf("attest is nondeterministic:\n first: %s\n  then: %s", first, next)
		}
	}
}

// ---------------------------------------------------------------------------
// Registration and the declared contract.
// ---------------------------------------------------------------------------

// TestPredicateTypeIsTheAflockNamespacedOne pins the decided type. Changing it
// is a breaking change for every policy that names it.
func TestPredicateTypeIsTheAflockNamespacedOne(t *testing.T) {
	if Type != "https://aflock.ai/attestations/instruction-file/v0.1" {
		t.Errorf("Type = %q; the decided predicate type is https://aflock.ai/attestations/instruction-file/v0.1", Type)
	}
	if got := New().Type(); got != Type {
		t.Errorf("Type() = %q, want %q", got, Type)
	}
	if got := New().RunType(); got != attestation.PreMaterialRunType {
		t.Errorf("RunType() = %q, want prematerial — instruction files are inputs and must be captured before anything acts on them", got)
	}
}

// TestSweep_DetectorContractMatchesReality sweeps the declared contract in
// detector.yaml against the live attestor. The contract is the machine-readable
// promise the catalog and CI both read; a promise the code does not keep is
// worse than no promise.
func TestSweep_DetectorContractMatchesReality(t *testing.T) {
	parsed, err := detection.ParseDetectorYAML(detectorYAML)
	if err != nil {
		t.Fatalf("parse detector.yaml: %v", err)
	}
	if parsed.Name != Name {
		t.Errorf("detector name = %q, want %q", parsed.Name, Name)
	}
	if parsed.Contract == nil {
		t.Fatal("detector.yaml declares no contract")
	}
	if parsed.Contract.PredicateType != Type {
		t.Errorf("contract predicate_type = %q, want %q", parsed.Contract.PredicateType, Type)
	}
	if parsed.Contract.RunType != string(RunType) {
		t.Errorf("contract run_type = %q, want %q", parsed.Contract.RunType, RunType)
	}
	if parsed.Contract.SchemaRequired && New().Schema() == nil {
		t.Error("contract asserts schema_required but Schema() is nil")
	}

	// Every declared subject prefix must actually be emitted.
	root, _ := writeTreeForAllConventions(t)
	a := New()
	a.searchRoot = root
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	subjects := a.Subjects()

	if len(parsed.Contract.Subjects) == 0 {
		t.Fatal("contract declares no subjects, but the attestor emits them")
	}
	for _, claim := range parsed.Contract.Subjects {
		found := false
		for key := range subjects {
			if strings.HasPrefix(key, claim.Prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("contract declares subject prefix %q but no emitted subject starts with it; emitted %v", claim.Prefix, sortedKeys(subjects))
		}
	}

	// And the converse: nothing is emitted that the contract does not declare.
	for key := range subjects {
		declared := false
		for _, claim := range parsed.Contract.Subjects {
			if strings.HasPrefix(key, claim.Prefix) {
				declared = true
				break
			}
		}
		if !declared {
			t.Errorf("emitted subject %q matches no declared contract prefix", key)
		}
	}
}

// TestPredicateValidatesAgainstItsOwnSchema mirrors the testkit gate: a
// predicate that does not conform to its declared schema is a contract no
// verifier can rely on. Run over a real tree so the Signer block is populated.
func TestPredicateValidatesAgainstItsOwnSchema(t *testing.T) {
	root, _ := writeTreeForAllConventions(t)
	a := New()
	a.searchRoot = root
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}

	schemaJSON, err := json.Marshal(a.Schema())
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
	c := tekuri.NewCompiler()
	if err := c.AddResource("attestor.schema.json", bytes.NewReader(schemaJSON)); err != nil {
		t.Fatalf("add resource: %v", err)
	}
	sch, err := c.Compile("attestor.schema.json")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal predicate: %v", err)
	}
	if err := sch.Validate(doc); err != nil {
		t.Errorf("predicate does not validate against its own Schema(): %v\npredicate: %s", err, raw)
	}
}

// TestSchemaIsReflectableAndNonNil guards the invopop reflection path, since
// the conditional constraints are attached during reflection.
func TestSchemaIsReflectableAndNonNil(t *testing.T) {
	s := New().Schema()
	if s == nil {
		t.Fatal("Schema() is nil")
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"allOf"`)) {
		t.Error("the reflected schema carries no allOf; the kind/federated conditional was not attached")
	}
	var check map[string]any
	if err := json.Unmarshal(raw, &check); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	_ = jsonschema.Version
}

// sortedKeys returns a map's keys sorted, for stable failure messages.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
