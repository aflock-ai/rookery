// jade:ring local
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

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

// These tests pin which of cilock's OWN outputs a scan may skip, and, more
// importantly, which it may not. Measured friction (onbsim run
// mx-hugo-l6-muguxxn1): an agent redirected each step's stdout and stderr into
// the repository. The secrets step then (1) read its own stderr, which it was
// still writing, and reported it as a product that changed between recording
// and scanning, and (2) under a diff scope read an earlier step's saved
// stdout, whose DSSE envelope is full of commit hashes, and reported 103
// findings in it. Neither file was in the push.
//
// The rule that keeps this from hiding a committed secret: a file is skipped
// only when git positively says it is untracked (in neither the index nor
// HEAD), and only when it is identified by what it IS (the inode this process
// writes its stdout or stderr to, or bytes that parse as a signed attestation
// collection), never by its name. Committed and staged blobs are read from
// the object store and never pass through this filter at all.

// evidenceEnvelope is what `cilock run -o /dev/stdout > file` leaves behind: a
// summary line, then a DSSE envelope whose payload is an attestation
// collection. The secret sits inside the base64 payload, where the scanner's
// decoder finds it.
func evidenceEnvelope(t *testing.T, predicateType, secret string) string {
	t.Helper()
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": predicateType,
		"subject":       []any{},
		"predicate": map[string]any{
			"name": "vulns",
			"attestations": []any{map[string]any{
				"type":        "https://aflock.ai/attestations/command-run/v0.2",
				"attestation": map[string]any{"stdout": "token=" + secret},
			}},
		},
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	env, err := json.Marshal(map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(payload),
		"payloadType": "application/vnd.in-toto+json",
		"signatures":  []any{map[string]any{"keyid": "k", "sig": "c2ln"}},
	})
	require.NoError(t, err)
	return "cilock run summary:\n  step:       vulns\n" + string(env) + "\n"
}

// diffRepo is a repository with a base commit and one pushed change, so a
// diff scope against the returned base has something of its own to read.
func diffRepo(t *testing.T) (dir, base string) {
	t.Helper()
	requireGit(t)
	dir = t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"main.go": "package main\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base = gitRun(t, dir, "rev-parse", "HEAD")
	writeFiles(t, dir, map[string]string{"main.go": "package main\n// change\n"})
	gitRun(t, dir, "commit", "-q", "-am", "change")
	return dir, base
}

func hasFindingAt(a *Attestor, rel string) bool {
	for _, f := range a.Findings {
		if strings.HasSuffix(f.Location, ":"+rel) {
			return true
		}
	}
	return false
}

const evidencePath = ".pushgate/run-1/evidence-vulns.stdout"

// The fixture must be one the scanner flags when nothing skips it, or every
// "is not scanned" assertion below passes for the wrong reason.
func TestEvidenceFixtureIsFlaggedWhenScannedAsAnOrdinaryFile(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"evidence.txt": evidenceEnvelope(t, attestation.CollectionType, scopePAT)})
	scan := runScanOnly(t, dir, WithScope(string(ScopeTree)), WithScanAttestations(false))
	require.True(t, hasFindingAt(scan, "evidence.txt"),
		"outside a git repository nothing is proven untracked, so the envelope is scanned; findings=%v", findingLocations(scan))
}

// An untracked cilock evidence file is not part of any commit the push
// carries, so a diff scope does not read it, while an ordinary untracked file
// beside it is read exactly as before.
func TestUntrackedCilockEvidenceIsNotScannedUnderDiffScope(t *testing.T) {
	dir, base := diffRepo(t)
	writeFiles(t, dir, map[string]string{
		evidencePath: evidenceEnvelope(t, attestation.CollectionType, scopePAT),
		"leak.env":   "SECRET=" + scopePAT + "\n",
	})

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))

	require.False(t, hasFindingAt(scan, evidencePath), "findings=%v", findingLocations(scan))
	require.NotContains(t, subjectKeys(scan), "file:"+evidencePath, "a file not read is not a subject")
	require.True(t, hasFindingAt(scan, "leak.env"),
		"an untracked file that is not cilock evidence behaves as before; findings=%v", findingLocations(scan))
}

// The legacy witness collection type is the same evidence under its old name.
func TestUntrackedLegacyCollectionEvidenceIsNotScanned(t *testing.T) {
	dir, base := diffRepo(t)
	writeFiles(t, dir, map[string]string{evidencePath: evidenceEnvelope(t, attestation.LegacyCollectionType, scopePAT)})
	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.False(t, hasFindingAt(scan, evidencePath), "findings=%v", findingLocations(scan))
}

// A DSSE envelope that is NOT an attestation collection is not cilock
// evidence, whatever it is called, and is scanned.
func TestUntrackedEnvelopeOfAnotherKindIsStillScanned(t *testing.T) {
	dir, base := diffRepo(t)
	writeFiles(t, dir, map[string]string{evidencePath: evidenceEnvelope(t, "https://example.test/not-a-collection/v1", scopePAT)})
	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasFindingAt(scan, evidencePath), "findings=%v", findingLocations(scan))
}

// A file with an evidence-looking NAME but ordinary contents is scanned: the
// name is never what decides.
func TestUntrackedFileNamedLikeEvidenceIsStillScanned(t *testing.T) {
	dir, base := diffRepo(t)
	writeFiles(t, dir, map[string]string{evidencePath: "token=" + scopePAT + "\n"})
	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasFindingAt(scan, evidencePath), "findings=%v", findingLocations(scan))
}

// Evidence that is COMMITTED in the push is part of what the push publishes,
// so its secret is found, on disk and in the commit alike.
func TestCommittedCilockEvidenceIsStillScanned(t *testing.T) {
	dir, base := diffRepo(t)
	writeFiles(t, dir, map[string]string{evidencePath: evidenceEnvelope(t, attestation.CollectionType, scopePAT)})
	gitRun(t, dir, "add", evidencePath)
	gitRun(t, dir, "commit", "-q", "-m", "commit the evidence")

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasFindingAt(scan, evidencePath), "findings=%v", findingLocations(scan))
}

// `git rm --cached` after committing leaves the file on disk and out of the
// index, so on disk it looks untracked, while the pushed commit still carries
// it. The commit's blob is read from the object store and is found.
func TestCommittedThenUntrackedEvidenceIsFoundInTheCommit(t *testing.T) {
	dir, base := diffRepo(t)
	writeFiles(t, dir, map[string]string{evidencePath: evidenceEnvelope(t, attestation.CollectionType, scopePAT)})
	gitRun(t, dir, "add", evidencePath)
	gitRun(t, dir, "commit", "-q", "-m", "commit the evidence")
	gitRun(t, dir, "rm", "-q", "--cached", evidencePath)

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasFindingAt(scan, evidencePath), "findings=%v", findingLocations(scan))
}

// Staged evidence is about to be committed; it is found.
func TestStagedCilockEvidenceIsStillScanned(t *testing.T) {
	dir, base := diffRepo(t)
	writeFiles(t, dir, map[string]string{evidencePath: evidenceEnvelope(t, attestation.CollectionType, scopePAT)})
	gitRun(t, dir, "add", evidencePath)

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasFindingAt(scan, evidencePath), "findings=%v", findingLocations(scan))
}

// ownStreamRun records rel as a product with the digest of `early`, then
// appends `later` to it the way a process appends to its own log, and scans
// with rel standing in for this process's stderr.
func ownStreamRun(t *testing.T, dir, rel, early, later string, opts ...Option) *Attestor {
	t.Helper()
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	abs := filepath.Join(dir, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o750))
	require.NoError(t, os.WriteFile(abs, []byte(early), 0o600))
	recorded, err := cryptoutil.CalculateDigestSetFromFile(abs, hashes)
	require.NoError(t, err)

	stream, err := os.OpenFile(abs, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test fixture path
	require.NoError(t, err)
	t.Cleanup(func() { _ = stream.Close() })
	_, err = stream.WriteString(later)
	require.NoError(t, err)

	scan := New(opts...)
	scan.ownStreams = func() []*os.File { return []*os.File{stream} }
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{rel: {MimeType: "text/plain", Digest: recorded}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return scan
}

// The measured case: `cilock run ... 2> .pushgate/secrets.stderr`. The file is
// this process's own stderr, still being written when it is scanned, so it
// always "changed between recording and scanning". Untracked, it is skipped:
// no disagreement, no subject.
func TestOwnStderrRedirectedIntoTheRepoIsNotAChangedProduct(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := ".pushgate/run-1/evidence-secrets.stderr"
	scan := ownStreamRun(t, dir, rel, "level=info msg=\"Starting product attestors stage...\"\n",
		"level=info msg=\"Starting secretscan attestor...\"\n")

	require.Nil(t, scan.Scope, "no disagreement is recorded for this process's own output; scope=%+v", scan.Scope)
	require.NotContains(t, subjectKeys(scan), "product:"+rel)
}

// The same under a diff scope, where the file is also listed as untracked: it
// is read by neither route.
func TestOwnStderrIsNotScannedUnderDiffScopeEither(t *testing.T) {
	dir, base := diffRepo(t)
	rel := ".pushgate/run-1/evidence-secrets.stderr"
	scan := ownStreamRun(t, dir, rel, "early\n", "later\n", WithScope("diff:"+base), WithScanAttestations(false))

	require.NotNil(t, scan.Scope)
	require.Empty(t, scan.Scope.ProductDigestMismatches)
	require.NotContains(t, subjectKeys(scan), "product:"+rel)
	require.NotContains(t, subjectKeys(scan), "file:"+rel)
}

// A tracked file is never skipped, even when it is this process's own
// stream: a committed secret still on disk is found, and the disagreement is
// still recorded.
func TestOwnStreamThatGitTracksIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := "build.log"
	writeFiles(t, dir, map[string]string{rel: "committed\n"})
	gitRun(t, dir, "add", rel)
	gitRun(t, dir, "commit", "-q", "-m", "track the log")

	scan := ownStreamRun(t, dir, rel, "token="+scopePAT+"\n", "more\n")

	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
	require.NotNil(t, scan.Scope)
	require.Len(t, scan.Scope.ProductDigestMismatches, 1)
	require.Equal(t, rel, scan.Scope.ProductDigestMismatches[0].Path)
}

// A staged file is what the next commit carries, so it is tracked: even as
// this process's own stream, its secret is found.
func TestOwnStreamThatIsStagedIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := "staged.log"
	writeFiles(t, dir, map[string]string{rel: "staged\n"})
	gitRun(t, dir, "add", rel)

	scan := ownStreamRun(t, dir, rel, "token="+scopePAT+"\n", "more\n")

	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
}

// Outside a git repository nothing can be proven untracked, so nothing is
// skipped: the scan fails toward reading.
func TestOwnStreamOutsideAGitRepositoryIsStillScanned(t *testing.T) {
	dir := t.TempDir()
	rel := "run.log"
	scan := ownStreamRun(t, dir, rel, "token="+scopePAT+"\n", "more\n")

	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
	require.NotNil(t, scan.Scope)
	require.Len(t, scan.Scope.ProductDigestMismatches, 1)
}

// A file that is NOT this process's stream is not skipped for being
// untracked: an untracked product carrying a secret is found.
func TestUntrackedProductThatIsNotOwnOutputIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := "dist/config.env"
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	writeFiles(t, dir, map[string]string{rel: "SECRET=" + scopePAT + "\n"})
	recorded, err := cryptoutil.CalculateDigestSetFromFile(filepath.Join(dir, rel), hashes)
	require.NoError(t, err)

	other, err := os.CreateTemp(t.TempDir(), "stderr")
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })

	scan := New()
	scan.ownStreams = func() []*os.File { return []*os.File{other} }
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{rel: {MimeType: "text/plain", Digest: recorded}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
}

func TestIsAttestationCollectionEnvelope(t *testing.T) {
	good := evidenceEnvelope(t, attestation.CollectionType, "x")
	require.True(t, isAttestationCollectionEnvelope([]byte(good)), "summary text then an envelope line")
	line := strings.Split(good, "\n")[2]
	require.True(t, isAttestationCollectionEnvelope([]byte(line)), "a bare envelope, as --outfile writes it")

	var pretty map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &pretty))
	indented, err := json.MarshalIndent(pretty, "", "  ")
	require.NoError(t, err)
	require.True(t, isAttestationCollectionEnvelope(indented), "an indented envelope")

	unsigned := strings.Replace(line, `"signatures":[{"keyid":"k","sig":"c2ln"}]`, `"signatures":[]`, 1)
	require.NotEqual(t, line, unsigned)
	require.False(t, isAttestationCollectionEnvelope([]byte(unsigned)), "no signature is not evidence")

	otherType := strings.Replace(line, "application/vnd.in-toto+json", "text/plain", 1)
	require.False(t, isAttestationCollectionEnvelope([]byte(otherType)))

	require.False(t, isAttestationCollectionEnvelope([]byte(`{"payload":"!!not base64","payloadType":"application/vnd.in-toto+json","signatures":[{}]}`)))
	require.False(t, isAttestationCollectionEnvelope([]byte("token="+scopePAT)))
}

// Text beside an envelope is not evidence. A file that carries an envelope
// line AND a secret on another line is scanned whole, so wrapping a leak
// around an envelope cannot hide it, under a diff scope or as a product.
func TestUntrackedEvidenceWithASecretBesideTheEnvelopeIsScanned(t *testing.T) {
	dir, base := diffRepo(t)
	content := "SECRET=" + scopePAT + "\n" + evidenceEnvelope(t, attestation.CollectionType, "x")
	writeFiles(t, dir, map[string]string{evidencePath: content})
	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasFindingAt(scan, evidencePath), "findings=%v", findingLocations(scan))
	require.Contains(t, subjectKeys(scan), "file:"+evidencePath, "a file scanned whole is a subject")
}

func TestUntrackedEvidenceProductWithASecretBesideTheEnvelopeIsScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := "dist/run.out"
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	writeFiles(t, dir, map[string]string{rel: evidenceEnvelope(t, attestation.CollectionType, "x") + "SECRET=" + scopePAT + "\n"})
	recorded, err := cryptoutil.CalculateDigestSetFromFile(filepath.Join(dir, rel), hashes)
	require.NoError(t, err)

	scan := New()
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{rel: {MimeType: "text/plain", Digest: recorded}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
}

// The measured shape, a summary then the envelope, has nothing to find beside
// the envelope and is still skipped.
func TestSplitAttestationCollectionEnvelopeKeepsOnlyTheTextBesideIt(t *testing.T) {
	good := evidenceEnvelope(t, attestation.CollectionType, "x")
	ok, rest := splitAttestationCollectionEnvelope([]byte(good))
	require.True(t, ok)
	require.Equal(t, "cilock run summary:\n  step:       vulns\n\n", string(rest))
	line := strings.Split(good, "\n")[2]
	ok, rest = splitAttestationCollectionEnvelope([]byte(line))
	require.True(t, ok)
	require.Empty(t, rest)
	ok, rest = splitAttestationCollectionEnvelope([]byte("token=" + scopePAT))
	require.False(t, ok)
	require.Nil(t, rest)
}
