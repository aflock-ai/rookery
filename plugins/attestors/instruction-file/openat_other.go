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

//go:build !unix

package instructionfile

import (
	"errors"
	"os"
)

// errNoFollowUnavailable is returned instead of a digest on platforms where
// this package cannot open a path with no-follow semantics at every component.
var errNoFollowUnavailable = errors.New(
	"refusing to digest: atomic no-follow open is unavailable on this platform, " +
		"so a path-to-digest binding cannot be guaranteed",
)

// openInstructionFile FAILS CLOSED here, and that is the whole design.
//
// # Why this refuses rather than reads
//
// The Unix implementation descends one component at a time with
// openat(O_NOFOLLOW), so no component of the path can be a symlink and the
// digest is bound to the exact path the walk classified. This platform has no
// portable equivalent. os.Root gives CONTAINMENT — nothing resolves outside the
// workspace — but not IDENTITY: it deliberately re-resolves and follows a
// symlink whose target stays inside the root, at the leaf and among the
// ancestors alike.
//
// The earlier version of this file used os.Root anyway and documented the
// residual hole: an attacker able to write inside the workspace between the
// walk and the open could redirect the digest to a different file INSIDE the
// same workspace. That is a strictly narrower hole than reading arbitrary
// files, and it was argued to be an improvement on the bare path-based open it
// replaced. Both of those things are true and neither is sufficient, because
// the output here is SIGNED EVIDENCE. A predicate that says "the file at
// sub/CLAUDE.md hashes to X" must be false in no case at all; a subject whose
// digest may belong to a neighbouring file is worse than a missing subject,
// since a missing subject is visible and a wrong one is not.
//
// So this platform produces no digest for the file. inspectFile turns the
// error into a SkipReason, the record still travels with its path and its
// reason, and anyFileSkipped drives the scan to `status: incomplete`. A reader
// gets "I found this file and declined to digest it, here is why" — the honest
// answer — rather than a clean-looking `complete` built on a binding this
// platform cannot make. Attestors observe; an observation it cannot stand
// behind is one it must not publish.
//
// Lifting this means implementing a real per-component no-follow traversal with
// the platform's own primitives, not relaxing the check.
func openInstructionFile(*os.Root, string) (*os.File, error) {
	return nil, errNoFollowUnavailable
}

// isSymlinkRefusal always reports false here: this platform never opens the
// file, so a refusal never has a symlink as its specific cause. The refusal is
// reported through errNoFollowUnavailable's own text instead, which names the
// real reason rather than implying a link was seen.
func isSymlinkRefusal(error) bool { return false }
