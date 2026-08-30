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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// ---------------------------------------------------------------------------
// A refused file must not report as a complete scan.
// ---------------------------------------------------------------------------
//
// Two independent behaviours combined into a fail-open. Most refusals raise no
// WARNING, because they are ordinary findings about a file that was located
// successfully rather than errors from the walk — a symlink, a non-regular
// entry, an over-cap file. And Subjects() emits nothing for a record with no
// digest, correctly, since a subject with no digest anchors nothing.
//
// So a workspace whose only CLAUDE.md was a symlink produced `status:
// complete` with an empty subject list: a signed claim that the tree was fully
// examined and held no instruction files, when the one file that mattered was
// found and refused. Every individual component behaved as designed, which is
// why the composition went unnoticed.
//
// The sweep below ranges over every way a matched file can be refused and
// asserts the same invariant for each: a scan that declined to digest
// something never calls itself complete.

// skipFixture is one way to produce a matched-but-not-digested file.
type skipFixture struct {
	name string
	// wantReason is the substring the resulting SkipReason must contain, which
	// keeps each fixture pinned to the branch it is meant to exercise. Without
	// it a fixture could drift onto a different refusal path and still pass.
	wantReason string
	setup      func(t *testing.T, root string)
}

// skipFixtures enumerates the refusal branches inspectFile can reach on a
// matched file. Read it against inspectFile: every early return that sets a
// SkipReason and returns true should appear here.
//
// "stat failed", "open failed", "read failed" and "digest failed" are the
// remaining branches. They are reachable only by inducing a genuine I/O fault
// against an already-opened descriptor, which is not portably constructible in
// a unit test — they are the error arms of syscalls the other fixtures already
// drive, and they set SkipReason through the identical code path, so the
// invariant is carried by the branches below.
func skipFixtures() []skipFixture {
	return []skipFixture{
		{
			name:       "symlink",
			wantReason: "symlink",
			setup: func(t *testing.T, root string) {
				t.Helper()
				target := filepath.Join(t.TempDir(), "elsewhere.md")
				if err := os.WriteFile(target, []byte("outside\n"), 0o600); err != nil {
					t.Fatalf("write target: %v", err)
				}
				if err := os.Symlink(target, filepath.Join(root, "CLAUDE.md")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name:       "over-cap",
			wantReason: "cap",
			setup: func(t *testing.T, root string) {
				t.Helper()
				body := make([]byte, maxFileBytes+1)
				if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), body, 0o600); err != nil {
					t.Fatalf("write oversized: %v", err)
				}
			},
		},
	}
}

// TestSweep_ARefusedFileNeverReportsACompleteScan is the invariant.
//
// It asserts all three halves of the failure together, because any one of them
// alone still permits a misleading predicate: the status must not be complete,
// the file must still be REPORTED (a refusal that vanishes is worse than one
// that is graded), and it must carry a reason a reader can act on.
func TestSweep_ARefusedFileNeverReportsACompleteScan(t *testing.T) {
	for _, f := range append(skipFixtures(), unixSkipFixtures()...) {
		t.Run(f.name, func(t *testing.T) {
			root := t.TempDir()
			f.setup(t, root)

			a := New()
			a.searchRoot = root
			if err := a.Attest(&attestation.AttestationContext{}); err != nil {
				t.Fatalf("attest: %v", err)
			}

			if len(a.Files) != 1 {
				t.Fatalf("expected the refused file to still be reported, got %d records", len(a.Files))
			}
			got := a.Files[0]
			if got.SkipReason == "" {
				t.Fatal("no SkipReason: a refusal with no stated reason is indistinguishable from a successful digest that produced nothing")
			}
			if !strings.Contains(got.SkipReason, f.wantReason) {
				t.Errorf("SkipReason = %q, want it to mention %q — this fixture may have drifted onto a different refusal branch", got.SkipReason, f.wantReason)
			}
			if len(got.Digest) != 0 {
				t.Errorf("a refused file carries a digest %v", got.Digest)
			}

			if a.Status == StatusComplete {
				t.Errorf("status = complete with a refused file present. The predicate would assert the tree was fully examined while contributing no subject for the one file that mattered")
			}

			// The consequence the status is standing in for: this predicate
			// anchors nothing, so completeness is the only field a reader has
			// to tell "looked and found nothing" from "looked and was refused".
			if len(a.Subjects()) != 0 {
				t.Errorf("expected no subjects for a refused file, got %d", len(a.Subjects()))
			}
		})
	}
}

// TestACleanTreeStillReportsComplete pins the other side, so the fix above
// cannot be satisfied by grading everything incomplete. A status that is always
// incomplete carries exactly as little information as one that is always
// complete.
func TestACleanTreeStillReportsComplete(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("real instructions\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	a := New()
	a.searchRoot = root
	if err := a.Attest(&attestation.AttestationContext{}); err != nil {
		t.Fatalf("attest: %v", err)
	}
	if a.Status != StatusComplete {
		t.Errorf("status = %q on a tree with one readable instruction file, want complete", a.Status)
	}
	if len(a.Subjects()) != 1 {
		t.Errorf("expected exactly one subject, got %d", len(a.Subjects()))
	}
}
