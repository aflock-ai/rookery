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

package alpsevidence

// This file is the ONLY place in the package that resolves an executable path,
// opens an executable, or reads a file describing one. Four consecutive review
// rounds found the same defect in a new location — a path established at one
// moment paired with bytes read at another inside one signed predicate —
// because the defect was expressible in many places. It is now expressible in
// one, and the type system carries the rest:
//
//   - executableSnapshot is the single value that turns "a process" into "an
//     opened, fstat'd, hashed executable". Resolved path, size, digest and
//     binding kind travel together in it; a consumer that has one has all of
//     them, from one open handle.
//   - matchTimeResolve is the only other resolution. It exists because
//     matching necessarily runs BEFORE a snapshot can exist, and it returns a
//     fingerprintPath — a struct with no way out. It cannot be converted to a
//     string, assigned to a snapshot field, or handed to a version parser.
//   - npmPackageVersion is the only read of a file NEXT TO the image. Round 5
//     found the previous shape — a free function taking a path — being called
//     with the kernel's recorded path, outside the snapshot entirely. It is a
//     METHOD on the snapshot now and takes no path, so the binding is the only
//     thing it can read against.
//   - openAgentPath is the only way this package opens a path it did not
//     choose. Round 5's follow-up found that moving the manifest read here had
//     put an UNBOUNDED read on an agent-controlled path: the check was about
//     which bytes may be paired with which, and said nothing about whether
//     reading them was safe. Every open of an agent-influenced path — the
//     image, the manifest beside it, $CODEX_HOME's config — now goes through
//     one non-blocking, fstat-checked opener.
//
// guards_test.go pins these properties at compile time, and
// TestSymlinkResolutionLivesInExactlyOnePlace,
// TestExecutablesAreOpenedInExactlyOnePlace and
// TestImageAdjacentFilesAreReadInExactlyOnePlace fail if a resolution, an
// open, or a file read appears anywhere a snapshot cannot reach.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// homeDirFunc is indirected so tests can point config discovery at a temporary
// directory without touching the developer's real dotfiles.
var homeDirFunc = os.UserHomeDir

func userHomeDir() string {
	home, err := homeDirFunc()
	if err != nil {
		return ""
	}
	return home
}

// physicalDir resolves a directory to an absolute, symlink-free path, and is
// the only way this package turns a working directory into something it walks
// upward from.
//
// filepath.Abs and filepath.Clean are LEXICAL. Clean in particular rewrites
// "a/b/.." to "a" without asking the filesystem, so on a path reached through
// a symlink the parents it produces are the LINK's parents, not the ones the
// directory actually lives under. Every upward walk in this package looks for
// a project marker or a configuration file in those parents, so a symlinked
// working directory made the walk search a tree the agent was never in.
//
// EvalSymlinks answers the physical question instead, and its failure is a
// refusal rather than a fallback: a directory this attestor cannot locate is
// one whose applicable configuration it cannot enumerate, and falling back to
// the lexical answer is the hazard this resolution exists to close. Callers
// fail closed on ok=false.
//
// It is one helper rather than two open-coded resolutions because the two
// upward walks — projectRootFromWorkingDir and codexProjectConfigPaths — must
// not be able to disagree about where the working directory physically is.
func physicalDir(dir string) (string, bool) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false
	}
	return filepath.Clean(resolved), true
}

// maxProjectRootWalkDepth bounds the upward walk projectRootFromWorkingDir
// performs, for the same reason codexProjectConfigPaths bounds its own: the
// working directory is influenced by the process being described, so an
// unbounded walk is an invitation to spend the attestor's time elsewhere.
const maxProjectRootWalkDepth = 64

// projectRootFromWorkingDir resolves the PROJECT ROOT that repository-scoped
// settings files are anchored to, from the working directory cilock was
// handed.
//
// Cilock receives a WORKING DIRECTORY, not a repository root, and the two
// differ in the ordinary `repo/subdir` invocation. Treating the working
// directory as the root made project-scope discovery look only at
// subdir/.claude (and its siblings), so the repository's own higher-precedence
// settings were never found and a lower-precedence user file could be signed
// as the configured default. The root is therefore discovered the way git
// discovers it: walk up until a directory contains a .git entry (a directory
// for an ordinary checkout, a file for a worktree or submodule — Lstat accepts
// both), bounded.
//
// The working directory is SYMLINK-RESOLVED before the walk, which is why
// this function lives in fsutil.go: TestSymlinkResolutionLivesInExactlyOnePlace
// confines every resolution to this file, where each caller is accounted for.
// The .git boundary lives on the resolved path, and cilock's working
// directory is routinely a symlink (macOS /var to /private/var, direnv and
// worktree layouts): a lexical-only walk from the link's parent either misses
// the real repository or discovers an unrelated one that happens to sit above
// the link, and a lower-precedence user file's model is then signed as the
// configured default. Unlike the other two resolutions here this one does not
// bind evidence to an image — it selects which DIRECTORIES are probed for
// settings files, and every file actually read still goes through
// loadConfigSnapshot's guarded, digested open.
//
// known=false means the walk could not COMPLETE — the path could not be made
// absolute, the symlink resolution failed, a stat failed for a reason other
// than absence, or the depth bound ran out — and the caller must fail closed:
// which project files apply is unknown, so nothing below them may answer.
// Reaching the filesystem root without finding a marker is not that case:
// there demonstrably is no enclosing repository, and the working directory
// itself is the project root, which is also the pre-discovery behavior for
// every non-repo run. An empty workingDir stays empty-and-known: there is
// nothing to discover from.
func projectRootFromWorkingDir(workingDir string) (root string, known bool) {
	if workingDir == "" {
		return "", true
	}
	abs, ok := physicalDir(workingDir)
	if !ok {
		return "", false
	}
	dir := abs
	for depth := 0; depth < maxProjectRootWalkDepth; depth++ {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir, true
		} else if !os.IsNotExist(err) {
			return "", false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs, true
		}
		dir = parent
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Opening a path the agent chose
// ---------------------------------------------------------------------------

// openAgentPath opens a path this attestor did not choose, and is the only way
// the package opens one.
//
// Almost every path here is influenced by the process being described: the
// executable path the kernel recorded (which the agent can replace on disk
// after exec), the package directory beside it, and $CODEX_HOME read out of
// the agent's own environment. Opening one the ordinary way hands the agent
// two ways to stop evidence collection without lying about anything:
//
//   - A FIFO. open(2) for reading BLOCKS until a writer arrives, so the
//     collection hangs before any check can run — which is why the
//     regular-file check the executable snapshot already had did not save it.
//     O_NONBLOCK is what makes the open return; it is a no-op on the regular
//     files this actually wants. The flag is Unix-only, so platformOpenFlags
//     supplies it from a build-tagged file and supplies zero elsewhere.
//   - Anything that is not a regular file. A character device such as
//     /dev/zero reads forever; a directory is not a file at all.
//
// The handle is fstat'd, never the path. stat-then-open is the TOCTOU this
// package already killed once for the digest, and the same reasoning applies
// to a safety check: it has to describe the file the caller is about to read,
// not whatever the name resolved to a moment earlier.
//
// A nil file means "no evidence here", which is the honest reading — a named
// pipe where a config file belongs is not a config file — and is exactly how
// every caller already treats an unopenable path. Callers must still BOUND the
// read; a regular file can be arbitrarily large.
//
// The open also refuses to follow a symlink at the final path component
// (O_NOFOLLOW, where the platform defines it). Following one turned this
// attestor into a content-confirmation oracle: an agent that plants a symlink
// where a config file belongs — or replaces its own recorded executable path
// with one — gets the SHA-256 of ANY file this user can read published into
// signed evidence, confirming the content of a file the predicate was never
// about. A symlink where a regular file belongs is treated exactly like a
// FIFO there: no evidence. The one legitimate symlink this package must still
// digest through — the recorded executable path of a symlink-installed agent
// — is resolved by openExecutable BEFORE this opener runs, and that
// resolution is then verified against the opened handle's own fstat (see
// verifyResolutionAgainstHandle), so refusing links here costs nothing real.
func openAgentPath(path string) (*os.File, os.FileInfo) {
	f, info, _ := openAgentPathState(path)
	return f, info
}

// openAgentPathState is openAgentPath plus one more fact: whether the absence
// of a handle means ABSENT (no entry exists) or DENIED (something is there but
// cannot safely be read — EACCES, a refused symlink, and a non-regular entry
// such as a FIFO are measured cases).
//
// The distinction is load-bearing for config precedence. A higher-precedence
// settings file that exists but cannot be read may set anything, so a caller
// resolving a precedence chain must fail closed on DENIED exactly as it does
// for a file that exists but does not parse — while ABSENT stays what it
// always was, a normal miss that resolution walks past.
func openAgentPathState(path string) (f *os.File, info os.FileInfo, denied bool) {
	if path == "" {
		return nil, nil, false
	}
	f, err := os.OpenFile(path, os.O_RDONLY|platformOpenFlags, 0) //nolint:gosec // G304: opening an agent-influenced path is this function's whole purpose; it is why the fstat below exists
	if err != nil {
		if os.IsNotExist(err) {
			// Nothing is present at this precedence tier.
			return nil, nil, false
		}
		if isSymlinkRefusal(err) {
			// The application may follow a config symlink, while this observer
			// deliberately refuses it. Treat that as an unresolved tier, not
			// as absence: falling through could publish a lower-precedence
			// value that the symlinked file actually overrides.
			return nil, nil, true
		}
		return nil, nil, true
	}
	info, err = f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, true
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		// A real CLI may attempt to read this entry (a FIFO is the measured
		// case), so a precedence resolver cannot pretend the tier is absent and
		// promote a lower file. We learned only that an unsupported entry was
		// present; denied carries exactly that uncertainty without reading it.
		return nil, nil, true
	}
	return f, info, false
}

// readBounded reads an opened handle up to limit bytes and refuses anything
// larger.
//
// The read goes one byte PAST the limit on purpose: a file exactly at the
// limit is still read, and one over it is caught by the read itself rather
// than trusted from a size someone stat'd earlier. Same shape as hashHandle
// and loadConfigSnapshot; this is the third caller, which is why it is a
// function.
func readBounded(f *os.File, limit int64) ([]byte, bool) {
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, false
	}
	return b, true
}

// ---------------------------------------------------------------------------
// Match-time resolution — identity only, never evidence
// ---------------------------------------------------------------------------

// fingerprintPath is a symlink resolution performed while a provider decides
// whether a process is its agent.
//
// A resolution at that moment is unavoidable: which process to snapshot is
// exactly what matching decides, so no snapshot can exist yet. What IS
// avoidable is that resolution leaking into evidence, and the type is how it
// is avoided. fingerprintPath is deliberately a STRUCT with an unexported
// field and no method that yields a path or a string, so:
//
//   - string(f) does not compile — a struct type has no string conversion;
//   - it cannot be assigned to executableSnapshot.resolvedPath, nor to any
//     other field, parameter or variable that holds a path;
//   - it cannot be passed to claudeVersionFromPath, codexVersionFromCaskPath,
//     or any other parser whose output reaches the predicate.
//
// All a fingerprintPath can do is answer the identity questions below, which
// is all matching is allowed to do. Why the asymmetry: identity is a yes/no
// claim published as a fingerprint NAME, and a wrong yes costs an
// attribution; a resolved path that reaches the predicate is PAIRED WITH A
// DIGEST, and a wrong pairing signs two different binaries as one.
//
// Keeping it a struct is load-bearing, not stylistic. guards_test.go pins it.
type fingerprintPath struct{ path string }

// matchTimeResolve is the only symlink resolution outside the executable
// snapshot. Its return type is why that is safe; see fingerprintPath.
//
// Resolution matters for identity because both priority agents are installed
// behind a symlink whose target carries the product's real name or version:
// ~/.local/bin/claude points at ~/.local/share/claude/versions/2.1.237, and
// Homebrew's /opt/homebrew/bin/codex points into
// /opt/homebrew/Caskroom/codex/<version>/codex-<target-triple>. The kernel
// records the path passed to execve, which is the link.
//
// A path that cannot be resolved yields the zero fingerprintPath, which
// matches nothing. That is the correct direction: an unresolvable path is an
// absent fingerprint, never a fallback to the unresolved string, which the
// callers already tested on its own.
func matchTimeResolve(path string) fingerprintPath {
	if path == "" {
		return fingerprintPath{}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fingerprintPath{}
	}
	return fingerprintPath{path: resolved}
}

// differsFrom reports whether resolution actually followed a link somewhere.
// Callers use it to skip a resolved-path rule whose unresolved twin already
// ran, so the recorded fingerprint names the rule that genuinely fired.
func (f fingerprintPath) differsFrom(recorded string) bool {
	return f.path != "" && f.path != recorded
}

// isClaudeVersionsLayout answers Claude Code's install-layout fingerprint
// against the resolved path.
func (f fingerprintPath) isClaudeVersionsLayout() bool {
	return isClaudeVersionsLayout(f.path)
}

// isCodexReleaseBinary answers Codex's release-artifact fingerprint against the
// resolved path. The empty path is in no allowlist, so the zero value answers
// false.
func (f fingerprintPath) isCodexReleaseBinary() bool {
	_, ok := codexReleaseBinaries[lowerBase(f.path)]
	return ok
}

// hasGeminiPackageTail answers Gemini's npm-package fingerprint against the
// resolved path. The zero value has no elements and answers false.
func (f fingerprintPath) hasGeminiPackageTail() bool {
	return hasGeminiPackageTail(pathElements(f.path))
}

// ---------------------------------------------------------------------------
// The executable snapshot — the one place evidence about an image is made
// ---------------------------------------------------------------------------

// Values for ProcessRef.DigestBinding: what the executable evidence is bound
// to.
const (
	// digestBindingProcessImage: the evidence came from a handle to the
	// running process image itself (Linux /proc/<pid>/exe), which stays bound
	// to the exec'd binary even after the path on disk is replaced. On that
	// platform the resolved path is read back OFF THE DESCRIPTOR, so it names
	// the same inode by construction.
	digestBindingProcessImage = "process-image"

	// digestBindingPath: the recorded executable path was opened once and all
	// evidence derived from that single handle, with the resolved path
	// verified against the handle's own fstat before it was allowed in.
	// Internally consistent — resolved path, size and digest describe one file
	// — but nothing proves the path still held the binary this process is
	// executing at the moment of the open. macOS offers no per-process image
	// handle, so this is the honest ceiling there.
	digestBindingPath = "path"
)

// digestSkipUnreadable explains an absent digest when the executable could not
// be opened, fstat'd, or read, or is not a regular file.
const digestSkipUnreadable = "executable not readable"

// digestSkipImageUnavailable explains an absent digest on a platform that CAN
// hand over the running process image but could not do so for this process.
//
// It is a distinct reason from digestSkipUnreadable because it means something
// different and stronger: the process image itself is gone or unreadable, so
// there is nothing left that this predicate could honestly digest. The recorded
// filesystem path is deliberately NOT tried as a fallback — whatever occupies
// that name now need not be what this process is executing.
const digestSkipImageUnavailable = "process image could not be opened; the recorded path is not digested in its place"

// Warnings emitted when the resolved path could not be bound to the digested
// handle. Both are deliberately path-free: warnings enter the signed
// predicate, where an absolute path would leak a home or repository location.
const (
	warnResolutionUnavailable = "the executable path could not be resolved while its image was open; no resolved path is recorded for it"

	warnResolutionMismatch = "the executable path resolved to a different file than the one this predicate digested; no resolved path is recorded, because pairing it with the digest would describe two binaries as one"
)

// openExecutable opens the process image exactly once and reports what the
// returned handle is bound to. It runs BEFORE anything looks at the executable
// path, which is what closes the resolve-then-open window.
//
// Which open is attempted is decided by the SOURCE'S CAPABILITY, not by
// whether an attempt succeeded.
//
// A source that can hand over the running image (processImageOpener) is the
// only thing allowed to answer for that process. If that open fails, the
// process image this predicate describes is gone or unreadable and there is
// nothing left to honestly digest — so it refuses. Falling back to the
// recorded path there was the defect: it digests whatever occupies that NAME
// now, and publishes the result beside a pid, start time, argv and ancestry
// that describe the original process, which is exactly how a replacement file
// gets signed as the original.
//
// The path open remains the honest ceiling for platforms with NO image handle
// at all — macOS is the measured case — and is declared as such through
// digestBindingPath. It goes through openAgentPath because the agent can
// replace what lives at the recorded path after exec; a FIFO there used to
// block this call outright, ahead of the regular-file check, which is why
// having that check was not enough.
//
// The fstat travels back with the handle. It is the same fstat the
// regular-file check was made against, so the caller sizes and digests the
// file that was CHECKED rather than stat'ing the handle a second time and
// hoping the two agree.
func openExecutable(src ProcessSource, p ProcessInfo) (*os.File, os.FileInfo, string) {
	if opener, ok := src.(processImageOpener); ok {
		f, err := opener.OpenProcessImage(p.instance())
		if err != nil {
			return nil, nil, digestSkipImageUnavailable
		}
		// A kernel image handle still has to be a regular file before it can
		// be sized and digested.
		info, serr := f.Stat()
		if serr != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			return nil, nil, digestSkipImageUnavailable
		}
		return f, info, digestBindingProcessImage
	}
	// The recorded path of a symlink-installed agent IS a symlink — measured
	// for both priority agents (~/.local/bin/claude, /opt/homebrew/bin/codex)
	// — and openAgentPath refuses links. So the path leg resolves FIRST and
	// opens the resolved target. This is not the resolve-then-open pairing the
	// snapshot killed: the resolution below is never published on its own —
	// the snapshot re-resolves the RECORDED path afterwards and keeps that
	// answer only when it names the very inode of this open handle
	// (verifyResolutionAgainstHandle), so a link retargeted between these two
	// steps costs the resolved path and the pairing, never signs a wrong one.
	target := p.Executable
	if resolved, err := filepath.EvalSymlinks(p.Executable); err == nil {
		target = resolved
	}
	if f, info := openAgentPath(target); f != nil {
		return f, info, digestBindingPath
	}
	return nil, nil, ""
}

// executableSnapshot is ONE coherent observation of the matched process's
// image, and snapshotExecutable is its only constructor.
//
// Every field describes the same open handle. That is the point: a consumer
// holding a snapshot physically cannot hold a path from one moment and a
// digest from another, because it never holds a path on its own — the resolved
// path, the size, the digest and the binding kind arrive together or not at
// all. Providers, the predicate, and version parsing all read from here, and
// there is no other executable-path helper for them to reach for.
//
// The snapshot holds no open handle — everything derived from the handle is
// computed before it is closed — so it can travel through Detection freely.
type executableSnapshot struct {
	// recordedPath is the path the kernel recorded at exec time, kept here so
	// the snapshot describes its own provenance instead of relying on a caller
	// to pair it back up with the ProcessInfo it came from.
	recordedPath string

	// resolvedPath is the path of the file the handle held, established FROM
	// the handle rather than by an independent lookup: read off the descriptor
	// where the platform can (Linux), otherwise resolved and then VERIFIED
	// against the handle's own fstat (see verifyResolutionAgainstHandle).
	// Empty when it could not be bound to the handle, in which case warnings
	// says why — an absent path is always preferable to one describing other
	// bytes than sha256.
	resolvedPath string

	sizeBytes     int64
	sha256        string
	binding       string
	digestSkipped string

	// info is the fstat of the handle everything else came from. It is kept so
	// a LATER read of a file beside the image can be checked against the very
	// inode this snapshot digested; see npmPackageVersion.
	info os.FileInfo

	// warnings explain an absent resolvedPath. They reach the predicate
	// through Detection.Warnings.
	warnings []string
}

// resolved is how every consumer reads the snapshot's path. Providers call
// this instead of resolving anything themselves; no other resolution available
// to them yields a usable path.
func (s executableSnapshot) resolved() string { return s.resolvedPath }

// snapshotExecutable takes the one snapshot, opening the process image exactly
// once.
//
// Ordering is the mechanism. The handle is acquired FIRST, and every
// subsequent value — the size from its fstat, the digest bounded by that same
// fstat, and the resolved path bound back to it — derives from that one
// handle. The shape this replaces resolved the symlink, then opened the path
// separately, then re-resolved for the predicate and again per provider: a
// replacement landing between any two of those steps made the recorded fields
// describe different binaries. There is now no "between": nothing consults the
// path until the handle exists.
//
// What the handle is bound to — the running image itself, or merely the
// recorded path — is published in DigestBinding rather than glossed over.
func snapshotExecutable(src ProcessSource, p ProcessInfo, digestSizeLimit int64) executableSnapshot {
	snap := executableSnapshot{recordedPath: p.Executable}

	// openExecutable has already fstat'd the handle and refused anything that
	// is not a regular file, so there is no second lookup here for a
	// replacement to land between. When it refuses it says WHICH refusal this
	// was: an unreadable path, or a process image that could not be opened on
	// a platform that offers one. Those are different facts about the run and
	// a reader must not have to guess between them.
	f, info, binding := openExecutable(src, p)
	if f == nil {
		snap.digestSkipped = digestSkipUnreadable
		if binding == digestSkipImageUnavailable {
			snap.digestSkipped = digestSkipImageUnavailable
		}
		return snap
	}
	defer func() { _ = f.Close() }()

	snap.sizeBytes = info.Size()
	snap.binding = binding
	snap.info = info
	snap.resolvedPath, snap.warnings = resolveOpenedImage(f, info, p.Executable)

	switch {
	case digestSizeLimit <= 0:
		snap.digestSkipped = "digesting disabled"
	case snap.sizeBytes > digestSizeLimit:
		snap.digestSkipped = fmt.Sprintf("executable is %d bytes, above the %d byte digest limit", snap.sizeBytes, digestSizeLimit)
	default:
		digest, herr := hashHandle(f, snap.sizeBytes)
		if herr != nil {
			snap.digestSkipped = herr.Error()
			return snap
		}
		snap.sha256 = digest
	}
	return snap
}

// verifyResolutionAgainstHandle resolves recorded and keeps the answer only if
// it names the very file the open handle holds.
//
// This is the honest ceiling where no per-process image handle exists (macOS,
// and the Linux fallback when a descriptor cannot name itself). The resolution
// is still a second path lookup — nothing on the platform avoids that — but
// its result is CHECKED against the handle's own fstat before it is allowed to
// become evidence. A retarget landing in that window makes the check fail, and
// a failed check yields NO resolved path rather than one describing different
// bytes than the digest. Same fail direction hashHandle takes when content
// disagrees with fstat: refuse the pairing rather than publish a plausible one.
func verifyResolutionAgainstHandle(info os.FileInfo, recorded string) (string, []string) {
	if recorded == "" {
		return "", nil
	}
	candidate, err := filepath.EvalSymlinks(recorded)
	if err != nil {
		return "", []string{warnResolutionUnavailable}
	}
	candidateInfo, err := os.Stat(candidate)
	if err != nil || !os.SameFile(info, candidateInfo) {
		return "", []string{warnResolutionMismatch}
	}
	return candidate, nil
}

// hashHandle digests the handle's content, bounded by the size its own fstat
// reported.
//
// The bound is the mechanism, not an optimization: reading one byte past it
// catches a file that grew between fstat and read, and comparing the byte
// count against the fstat'd size catches one that shrank. Either way the
// content no longer matches the size this predicate would pair it with, so no
// digest is produced at all rather than a digest of different bytes.
func hashHandle(f *os.File, size int64) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, size+1))
	if err != nil {
		return "", fmt.Errorf("read failed: %w", err)
	}
	if n != size {
		return "", fmt.Errorf("content changed while hashing: read %d bytes, fstat reported %d", n, size)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---------------------------------------------------------------------------
// Evidence read from the layout AROUND the snapshotted image
// ---------------------------------------------------------------------------

// npmPackageVersionWalkDepth bounds how far up the tree the package lookup
// walks. The measured layouts put the manifest one or two directories above
// the binary; the bound is what stops an unrelated manifest higher up the tree
// from being reached at all.
const npmPackageVersionWalkDepth = 6

// npmManifestReadLimit caps the package-manifest read. A real package.json is
// a couple of kilobytes; the cap exists because the file sits at a path the
// agent chooses, so its size is the agent's choice too.
const npmManifestReadLimit = 1 << 20 // 1 MiB

// npmPackageVersion reads the "version" field out of the package manifest that
// shipped the snapshotted image, for a package installed under the given npm
// namespace (for example "@openai").
//
// It is a METHOD on the snapshot, and it deliberately takes no path, for the
// same reason fingerprintPath is a struct with no way out. The shape this
// replaces was a free function taking a path, and the caller passed it the
// KERNEL-RECORDED path: an npm install landing while the agent runs then
// answered with the NEW package's version, which the predicate published beside
// the OLD image's digest. It did so even when the snapshot had bound no path to
// the handle at all, i.e. in exactly the case where nothing tied the read to
// the running image. With no path parameter there is nothing to pass but the
// binding, and an unbound snapshot yields no version.
//
// Two things this still is NOT, and the caller grades it accordingly:
//
//   - The manifest is a DIFFERENT FILE from the image. Binding the walk to the
//     resolved path narrows the window to the moment after the handle was
//     taken; it does not put the manifest inside the digest.
//   - The manifest is located by DIRECTORY-LAYOUT CONVENTION, not by anything
//     in the digested bytes. That is what AssuranceInferred is defined to
//     cover, and it is how the sibling Caskroom path parse is already graded.
//
// The walk is bounded and requires the package directory's parent to be exactly
// namespace, so it cannot wander into an unrelated package manifest higher up.
//
//nolint:unparam // the sole current caller reads "@openai"; the namespace is the exact-equality anchor the walk is defined by
func (s executableSnapshot) npmPackageVersion(namespace string) string {
	if s.resolvedPath == "" || namespace == "" || s.info == nil {
		return ""
	}
	dir := filepath.Dir(s.resolvedPath)
	for depth := 0; depth < npmPackageVersionWalkDepth && dir != "" && dir != string(filepath.Separator); depth++ {
		if filepath.Base(filepath.Dir(dir)) == namespace {
			// The NEAREST directory whose parent is the namespace is the
			// package that shipped this binary, and the walk ENDS here
			// whatever its manifest says. Continuing upward after a missing,
			// unreadable, or invalid manifest handed back an OUTER scoped
			// package's version — a nested npm tree vendors packages inside
			// packages — and signed, beside the inner executable's digest, a
			// version that demonstrably did not ship it. No version is the
			// honest answer when the shipping package's own manifest cannot
			// supply one; an unrecorded version is an observation gap, which
			// is the direction this attestor fails in.
			v := readPackageJSONVersion(filepath.Join(dir, "package.json"))
			if v == "" || !s.stillDescribesTheDigestedImage() {
				return ""
			}
			return v
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// stillDescribesTheDigestedImage reports whether the snapshot's resolved path
// still names the very file this snapshot digested.
//
// The manifest is read AFTER the image handle has been closed, from a path
// rather than a descriptor, so on its own it is a fresh question to the
// filesystem. npm updates a package by swapping the directory atomically, which
// replaces the binary and the manifest together — so the version read a moment
// ago could belong to a package that no longer contains the digested image.
//
// Re-stat'ing the resolved path and comparing identities closes that: if the
// tree was swapped, the path now names a different file and the version is
// refused. Inode equality (os.SameFile) alone is not enough — ext4 and
// overlayfs happily hand a freshly created file the inode its deleted
// predecessor just vacated, so a replaced-in-place binary can read as "same
// file" moments later (measured: the pre-fix check accepted exactly that swap
// on Linux, while APFS's monotonic inode numbers masked it on macOS). The
// size and modification time from the ORIGINAL handle's fstat must therefore
// still agree too. It is the same rule the rest of this file follows — a
// value is published only while it can still be tied to the observation it
// came from — and a refusal costs a version string, which is the cheaper
// mistake.
func (s executableSnapshot) stillDescribesTheDigestedImage() bool {
	current, err := os.Stat(s.resolvedPath)
	if err != nil {
		return false
	}
	return os.SameFile(s.info, current) &&
		current.Size() == s.info.Size() &&
		current.ModTime().Equal(s.info.ModTime())
}

// readPackageJSONVersion reads one field out of an npm package manifest.
//
// The path is agent-influenced, so the open is the guarded one and the read is
// bounded. Unopenable, not a regular file, oversized and unparseable all yield
// "": a version this attestor could not read within its bound is a version it
// does not claim, never a guess.
func readPackageJSONVersion(path string) string {
	f, _ := openAgentPath(path)
	if f == nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	b, ok := readBounded(f, npmManifestReadLimit)
	if !ok {
		return ""
	}
	var pkg struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(b, &pkg) != nil {
		return ""
	}
	return pkg.Version
}
