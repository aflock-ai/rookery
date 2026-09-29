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

package secretscan

// This file (own_output.go) decides which of cilock's OWN outputs a scan
// skips, and states why none of them can be a file a push carries.
//
// Two kinds of file, each identified by what it IS, never by its name:
//
//   - The file this process writes its stdout or stderr to, matched by inode
//     (os.SameFile), never followed through a symlink. `cilock run ... 2>
//     .pushgate/secrets.stderr` puts the step's own log in the working tree;
//     it is still being written while it is scanned, so it always "changed
//     between recording and scanning" and its content is cilock's own log
//     lines. Skipped by any route, a recorded product included.
//   - A file whose bytes parse as a signed DSSE envelope over an attestation
//     collection: the --outfile of another run, or its stdout saved with the
//     summary in front. Its base64 payload is full of commit hashes and
//     digests that secret rules match. Skipped ONLY when a diff scope's
//     working-tree walk discovered it, never as a recorded product (what the
//     step publishes) and never by the tree walk: its recognition is by shape,
//     so it gets no route an operator did not already have to hide an
//     untracked file from a diff scope (.git/info/exclude).
//
// Either one is skipped ONLY when git positively says the path is untracked:
// its real path (no symlinked component) is in neither the index nor HEAD,
// is not at or under a gitlink (a submodule keeps its own index), and is
// owned by this same repository. That is the whole security argument. A push
// carries commits, the index is what the next commit will carry, and both
// are read from the object store by scanCommittedBlobs, which never consults
// this filter. So a file skipped here is by construction one no commit in the
// push contains and `git commit` would not add; the moment it is staged it is
// tracked and read again. Anything that cannot be proven untracked (not a git
// work tree, an unborn HEAD, a path outside the work tree, any git failure)
// is scanned.
//
// An envelope is recognised on a line of its own, so a saved stdout with the
// summary in front still counts. The lines OUTSIDE the envelope are not
// cilock's evidence, so before such a file is skipped they are scanned on
// their own: any finding there, or any error scanning them, means the whole
// file is scanned as usual. The skip is all-or-nothing so that a published
// subject is always the digest of the complete bytes read.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// ownOutputSkip records one file skipped as cilock's own output, for the log.
type ownOutputSkip struct {
	Path   string
	Reason string
}

const (
	reasonOwnStream = "it is the file this cilock process is writing its own stdout or stderr to"
	reasonEvidence  = "it is a signed attestation envelope, cilock evidence from another run"
)

// ownStreamFiles is what this process writes its stdout and stderr to.
func (a *Attestor) ownStreamFiles() []*os.File {
	if a.ownStreams != nil {
		return a.ownStreams()
	}
	return []*os.File{os.Stdout, os.Stderr}
}

// isOwnStream reports whether the bytes read from absPath came from this
// process's stdout or stderr. read is the identity (Fstat) of the open file
// those bytes were read from, and it is what is compared with the streams
// (device and inode): a fresh Stat of the path could name a file swapped in
// after the read, and skipping on its identity would drop bytes that never
// came from the stream. Only regular files can match: a terminal or a pipe is
// not in the working tree. The path must also still name that same file and
// not through a symlink: a symlink is never the stream itself, so a link
// placed in the working tree cannot get the bytes behind it skipped under its
// own untracked name.
func (a *Attestor) isOwnStream(absPath string, read os.FileInfo) bool {
	if read == nil || !read.Mode().IsRegular() {
		return false
	}
	info, err := os.Lstat(absPath)
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, read) {
		return false
	}
	for _, f := range a.ownStreamFiles() {
		if f == nil {
			continue
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if os.SameFile(read, fi) {
			return true
		}
	}
	return false
}

// skipRoute is how a file reached the scan: as a product the command
// recorded, or through a scope's working-tree walk.
type skipRoute int

const (
	routeProduct skipRoute = iota
	routeWorkingTree
)

// ownOutputReason says why the bytes read from absPath are cilock's own
// output, or "" if they are not or if that cannot be shown. content is what
// was read and read is the identity of the open file it was read from, so
// the decision is about the bytes that would otherwise be scanned. For evidence,
// residual is every byte outside the envelope, which the caller must find
// clean before it skips the file.
//
// The own stream is identity (the inode this process writes), so it counts by
// any route. An envelope is recognised by SHAPE, so it counts only on the
// route where skipping grants nothing new: a diff scope's working-tree walk,
// which an operator could already narrow with .git/info/exclude. A recorded
// product is what the step publishes, and a tree scope reads the working tree
// on purpose; on both an envelope is scanned.
func (a *Attestor) ownOutputReason(route skipRoute, absPath string, content []byte, read os.FileInfo) (reason string, residual []byte) {
	if a.isOwnStream(absPath, read) {
		return reasonOwnStream, nil
	}
	if route != routeWorkingTree || !strings.HasPrefix(a.scope, diffScopePrefix) {
		return "", nil
	}
	if ok, rest := splitAttestationCollectionEnvelope(content); ok {
		return reasonEvidence, rest
	}
	return "", nil
}

// skipAsOwnOutput decides whether to skip the bytes just read from rel
// (relative to the working directory) as cilock's own output that no commit
// carries. read is the identity of the open file they were read from. It is
// consulted only for bytes read off disk, never for a committed or staged
// blob.
func (a *Attestor) skipAsOwnOutput(ctx *attestation.AttestationContext, route skipRoute, rel, absPath string, content []byte, read os.FileInfo, detector *detect.Detector) bool {
	reason, residual := a.ownOutputReason(route, absPath, content, read)
	if reason == "" {
		return false
	}
	untracked, why := a.provenUntracked(ctx, rel)
	if !untracked {
		log.Debugf("(attestation/secretscan) scanning %s although %s: %s", rel, reason, why)
		return false
	}
	// Text beside an envelope is not evidence. A finding in it, or a scan of
	// it that fails, means the file is scanned whole.
	if len(bytes.TrimSpace(residual)) > 0 {
		found, err := a.scanBytes(residual, absPath, rel, detector, make(map[string]struct{}), 0)
		if err != nil || len(found) > 0 {
			log.Debugf("(attestation/secretscan) scanning %s although %s: the text outside the envelope is not evidence and holds a finding", rel, reason)
			return false
		}
	}
	a.ownOutputSkips = append(a.ownOutputSkips, ownOutputSkip{Path: rel, Reason: reason})
	return true
}

// provenUntracked reports whether git says rel is in neither the index nor
// HEAD. Every failure answers false, with the reason, so the file is scanned.
func (a *Attestor) provenUntracked(ctx *attestation.AttestationContext, rel string) (bool, string) {
	if rel == "" || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") {
		return false, "the path is not inside the working directory"
	}
	if !a.trackedLoaded {
		a.trackedLoaded = true
		a.tracked, a.trackedErr = trackedPaths(ctx)
	}
	if a.trackedErr != nil {
		return false, a.trackedErr.Error()
	}
	if why := realPathMismatch(ctx.WorkingDir(), rel); why != "" {
		return false, why
	}
	if _, ok := a.tracked.paths[rel]; ok {
		return false, "git tracks it"
	}
	for _, g := range a.tracked.gitlinks {
		if rel == g || strings.HasPrefix(rel, g+"/") {
			return false, "it is at or under the submodule " + g + ", whose own index this repository does not read"
		}
	}
	if why := a.tracked.foreignOwner(ctx, rel); why != "" {
		return false, why
	}
	return true, ""
}

// trackedIndex is what the working directory's repository tracks: every path
// in its index or HEAD, the gitlinks (submodules, mode 160000) among them,
// and the repository root, with symlinks resolved.
type trackedIndex struct {
	paths    map[string]struct{}
	gitlinks []string
	root     string
}

// foreignOwner returns "" only when git, asked from the file's own directory,
// names this same repository as the one that owns it. A nested repository
// that is not a submodule owns its files, and this repository's index says
// nothing about them.
func (t *trackedIndex) foreignOwner(ctx *attestation.AttestationContext, rel string) string {
	workingDir := ctx.WorkingDir()
	if workingDir == "" {
		workingDir = "."
	}
	fileDir := filepath.Dir(filepath.Join(workingDir, filepath.FromSlash(rel)))
	out, err := gitOutput(ctx, fileDir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "the repository that owns it cannot be named: " + err.Error()
	}
	owner, err := filepath.EvalSymlinks(strings.TrimSpace(string(out)))
	if err != nil || owner != t.root {
		return "it belongs to another repository (" + strings.TrimSpace(string(out)) + ")"
	}
	return ""
}

// indexEntries parses NUL-separated "<meta>\t<path>" records, where meta is
// `git ls-files --stage` ("mode sha stage") or `git ls-tree` ("mode type
// sha"), into each path and whether its mode is a gitlink.
func indexEntries(out []byte) (paths []string, gitlinks []string, err error) {
	for _, rec := range splitNUL(out) {
		meta, path, ok := strings.Cut(rec, "\t")
		if !ok {
			return nil, nil, fmt.Errorf("unexpected git index record %q", rec)
		}
		paths = append(paths, path)
		if strings.HasPrefix(meta, "160000 ") {
			gitlinks = append(gitlinks, path)
		}
	}
	return paths, gitlinks, nil
}

// realPathMismatch binds the untracked proof to the file itself. git is asked
// about rel as spelled, so rel must BE the real path: if any component under
// the working directory is a symlink (`alias` -> `tracked-dir`), the spelled
// path names a file git knows under another name, and a lookup of the
// spelling would call a tracked file untracked. It returns "" only when the
// resolved path equals the working directory's resolved path joined with rel;
// any difference or resolution failure is a reason to scan.
func realPathMismatch(workingDir, rel string) string {
	if workingDir == "" {
		workingDir = "."
	}
	wdAbs, err := filepath.Abs(workingDir)
	if err != nil {
		return "the working directory cannot be resolved"
	}
	wdReal, err := filepath.EvalSymlinks(wdAbs)
	if err != nil {
		return "the working directory cannot be resolved"
	}
	real, err := filepath.EvalSymlinks(filepath.Join(wdAbs, filepath.FromSlash(rel)))
	if err != nil {
		return "the path cannot be resolved"
	}
	if real != filepath.Join(wdReal, filepath.FromSlash(rel)) {
		return "a component of the path is a symlink, so git would be asked about a name that is not the file"
	}
	return ""
}

// trackedPaths lists every path in the index or in HEAD's tree, relative to
// the working directory, and which of them are gitlinks. Paths outside the
// working directory are dropped: nothing under it can be named by them. (A
// working directory inside a checked-out submodule resolves to that
// submodule's own repository, so its parent's gitlink never applies here.)
func trackedPaths(ctx *attestation.AttestationContext) (*trackedIndex, error) {
	workingDir := ctx.WorkingDir()
	if workingDir == "" {
		workingDir = "."
	}
	rootOut, err := gitOutput(ctx, workingDir, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(strings.TrimSpace(string(rootOut)))
	if err != nil {
		return nil, err
	}
	toWD, err := newRootRelativeMapper(workingDir, root)
	if err != nil {
		return nil, err
	}
	index, err := gitOutput(ctx, workingDir, "ls-files", "--cached", "--stage", "--full-name", "-z")
	if err != nil {
		return nil, err
	}
	// An unborn HEAD fails here, and that failure stands: with no HEAD to
	// compare against, "untracked" cannot be shown.
	head, err := gitOutput(ctx, workingDir, "ls-tree", "-r", "--full-tree", "-z", "HEAD")
	if err != nil {
		return nil, err
	}
	t := &trackedIndex{paths: map[string]struct{}{}, root: root}
	for _, out := range [][]byte{index, head} {
		paths, links, err := indexEntries(out)
		if err != nil {
			return nil, err
		}
		for _, p := range paths {
			if rel, ok := toWD(p); ok {
				t.paths[rel] = struct{}{}
			}
		}
		for _, g := range links {
			if rel, ok := toWD(g); ok {
				t.gitlinks = append(t.gitlinks, rel)
			}
		}
	}
	return t, nil
}

// logOwnOutputSkips says, once per file, what was not scanned and why.
func (a *Attestor) logOwnOutputSkips() {
	logged := map[string]bool{}
	for _, s := range a.ownOutputSkips {
		// A diff or tree scope can reach one file both as a product and as a
		// working-tree file; say it once.
		if logged[s.Path] {
			continue
		}
		logged[s.Path] = true
		log.Infof("(attestation/secretscan) not scanning %s: %s, and git does not track it, so no commit in this push carries it", s.Path, s.Reason)
	}
}

// isAttestationCollectionEnvelope reports whether content is, or contains on
// a line of its own, a signed DSSE envelope whose in-toto payload is an
// attestation collection. That is exactly what `cilock run --outfile` writes,
// and what its stdout carries after the run summary.
func isAttestationCollectionEnvelope(content []byte) bool {
	ok, _ := splitAttestationCollectionEnvelope(content)
	return ok
}

// splitAttestationCollectionEnvelope is isAttestationCollectionEnvelope that
// also returns every line that is NOT an envelope, in order. A whole-content
// envelope (bare or indented) leaves nothing.
func splitAttestationCollectionEnvelope(content []byte) (bool, []byte) {
	if isCollectionEnvelopeJSON(content) {
		return true, nil
	}
	found := false
	var rest bytes.Buffer
	for _, raw := range bytes.Split(content, []byte("\n")) {
		line := bytes.TrimSpace(raw)
		if len(line) > 0 && line[0] == '{' && bytes.Contains(line, []byte(`"payloadType"`)) && isCollectionEnvelopeJSON(line) {
			found = true
			continue
		}
		rest.Write(raw)
		rest.WriteByte('\n')
	}
	if !found {
		return false, nil
	}
	return true, rest.Bytes()
}

func isCollectionEnvelopeJSON(b []byte) bool {
	var env struct {
		Payload     string            `json:"payload"`
		PayloadType string            `json:"payloadType"`
		Signatures  []json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return false
	}
	if env.PayloadType != intoto.PayloadType || env.Payload == "" || len(env.Signatures) == 0 {
		return false
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return false
	}
	var stmt struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return false
	}
	return stmt.PredicateType == attestation.CollectionType || stmt.PredicateType == attestation.LegacyCollectionType
}

// changedProductHint says why a product most likely changed between the
// product snapshot and the scan, and what to do about it.
func changedProductHint(ownStream bool) string {
	if ownStream {
		return "It is this cilock process's own stdout or stderr, which it was still writing, and git could not prove it untracked, so it was scanned anyway; write the step's output outside the repository."
	}
	return "A file changes while the step runs when something is still writing it, most often the step's own log or report redirected inside the repository; write it outside the repository and re-run the step."
}

// maxLoggedLocations bounds the per-location finding summary.
const maxLoggedLocations = 10

// logFindingLocations says where the findings are, one line per location,
// and whether a working-tree file holding them is one git does not track.
// Such a file is in no commit the push carries; it was read because a diff
// or tree scope reads the working tree, and the fix for a report or log is
// to write it elsewhere, not to allowlist it.
func (a *Attestor) logFindingLocations(ctx *attestation.AttestationContext) {
	if len(a.Findings) == 0 {
		return
	}
	counts := map[string]int{}
	for _, f := range a.Findings {
		counts[f.Location]++
	}
	locs := make([]string, 0, len(counts))
	for l := range counts {
		locs = append(locs, l)
	}
	sort.Strings(locs)
	anyUntracked := false
	for i, l := range locs {
		if i == maxLoggedLocations {
			log.Warnf("(attestation/secretscan) ... and findings in %d more location(s)", len(locs)-maxLoggedLocations)
			break
		}
		note := ""
		rel, onDisk := strings.CutPrefix(l, "file:")
		if !onDisk {
			var key string
			if key, onDisk = strings.CutPrefix(l, "product:"); onDisk {
				rel = productScopePath(key, workingDirSpellings(ctx.WorkingDir()))
			}
		}
		if onDisk {
			if untracked, _ := a.provenUntracked(ctx, rel); untracked {
				note = ", in a file git does not track, so no commit in this push carries it"
				anyUntracked = true
			}
		}
		log.Warnf("(attestation/secretscan) %d finding(s) at %s%s", counts[l], l, note)
	}
	if anyUntracked {
		log.Warnf("(attestation/secretscan) an untracked file was read because the %q scope reads the working tree; if it is a report, log or evidence you do not commit, write it outside the repository (or list it in .git/info/exclude, since a diff scope skips ignored files) and re-run the step", a.scope)
	}
}
