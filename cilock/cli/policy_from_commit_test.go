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

package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
)

// fakeCommitFetcher is an in-memory commitFetcher the from-commit tests
// substitute for the real Archivista client. It records the subject digests it
// was queried with and serves a fixed gitoid→envelope map. It mirrors push's
// fakeUploader seam.
type fakeCommitFetcher struct {
	// byGitoid maps a gitoid to the envelope Download returns.
	byGitoid map[string]dsse.Envelope
	// searchErr / downloadErr force error paths.
	searchErr   error
	downloadErr error
	// queriedSubjects records the subject digests SearchGitoidsBySubjects saw.
	queriedSubjects []string
}

func (f *fakeCommitFetcher) SearchGitoidsBySubjects(_ context.Context, subjectDigests, _ []string) ([]string, error) {
	f.queriedSubjects = append(f.queriedSubjects, subjectDigests...)
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	gitoids := make([]string, 0, len(f.byGitoid))
	for g := range f.byGitoid {
		gitoids = append(gitoids, g)
	}
	return gitoids, nil
}

func (f *fakeCommitFetcher) Download(_ context.Context, gitoid string) (dsse.Envelope, error) {
	if f.downloadErr != nil {
		return dsse.Envelope{}, f.downloadErr
	}
	env, ok := f.byGitoid[gitoid]
	if !ok {
		return dsse.Envelope{}, fmt.Errorf("no envelope for gitoid %q", gitoid)
	}
	return env, nil
}

// installFakeCommitFetcher swaps newCommitFetcher for the test and restores it.
func installFakeCommitFetcher(t *testing.T, f *fakeCommitFetcher) {
	t.Helper()
	orig := newCommitFetcher
	newCommitFetcher = func(_, _ string) commitFetcher { return f }
	t.Cleanup(func() { newCommitFetcher = orig })
}

// keylessCollectionEnvelope builds an in-memory dsse.Envelope mirroring the
// keyless (Fulcio) + RFC3161-timestamped collection `cilock run
// --enable-archivista` uploads: a short-lived leaf cert with an email SAN plus a
// real RFC3161 timestamp token, wrapping a collection statement whose
// predicate.name is the witness step name. This is the Archivista-source analog
// of synthKeylessTimestampedBundle (which writes a file); here we return the
// envelope value so the fake fetcher can serve it.
//
// Returns (envelope, signer SAN email).
func keylessCollectionEnvelope(t *testing.T, stepName, signerEmail string, innerTypes []string) (dsse.Envelope, string) {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * time.Minute), // short-lived, like Fulcio
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		EmailAddresses:        []string{signerEmail},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, leafTpl, &leafKey.PublicKey, leafKey)
	require.NoError(t, err)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	keyID, err := cryptoutil.GeneratePublicKeyID(&leafKey.PublicKey, crypto.SHA256)
	require.NoError(t, err)

	atts := make([]map[string]string, 0, len(innerTypes))
	for _, tp := range innerTypes {
		atts = append(atts, map[string]string{"type": tp})
	}
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"subject":       []map[string]any{{"name": "commithash:abc", "digest": map[string]string{"sha1": "abc"}}},
		"predicateType": collectionPredicateURI,
		"predicate":     map[string]any{"name": stepName, "attestations": atts},
	}
	stmtBytes, err := json.Marshal(stmt)
	require.NoError(t, err)

	sigValue := []byte("dummy-signature-bytes")
	tsToken := mintRFC3161Token(t, sigValue) // reused from policy_from_bundles_test.go

	return dsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     stmtBytes, // dsse.Envelope.Payload is []byte; JSON-marshals to base64
		Signatures: []dsse.Signature{
			{
				KeyID:       keyID,
				Signature:   sigValue,
				Certificate: leafPEM,
				Timestamps: []dsse.SignatureTimestamp{
					{Type: dsse.TimestampRFC3161, Data: tsToken},
				},
			},
		},
	}, signerEmail
}

// pubkeyCollectionEnvelope builds a raw-keyid (non-cert) collection envelope —
// the simplest case, used to verify step grouping and the no-cert path.
func pubkeyCollectionEnvelope(t *testing.T, stepName string, innerTypes []string) dsse.Envelope {
	t.Helper()
	atts := make([]map[string]string, 0, len(innerTypes))
	for _, tp := range innerTypes {
		atts = append(atts, map[string]string{"type": tp})
	}
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"subject":       []map[string]any{{"name": "commithash:abc", "digest": map[string]string{"sha1": "abc"}}},
		"predicateType": collectionPredicateURI,
		"predicate":     map[string]any{"name": stepName, "attestations": atts},
	}
	stmtBytes, err := json.Marshal(stmt)
	require.NoError(t, err)
	return dsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     stmtBytes,
		Signatures:  []dsse.Signature{{KeyID: "rawkeyid-1", Signature: []byte("sig")}},
	}
}

const testCommitSHA = "1111111111111111111111111111111111111111" // 40-hex full sha

// TestFromCommit_QueriesByCommitGroupsByStepAndDerivesVerifiablePolicy is the
// core proof: from-commit queries Archivista by the commit subject digest,
// groups the returned DSSEs by their collection name (= step), and derives a
// policy that carries the #5741 verifiable-policy fix (TSA authorities + signer
// email cert constraint) — inherited from the shared derivation core.
func TestFromCommit_QueriesByCommitGroupsByStepAndDerivesVerifiablePolicy(t *testing.T) {
	buildEnv, signerEmail := keylessCollectionEnvelope(t, "build", "ci-signer@example.com",
		[]string{
			"https://aflock.ai/attestations/material/v0.3",
			"https://aflock.ai/attestations/command-run/v0.1",
		})
	testEnv := pubkeyCollectionEnvelope(t, "test",
		[]string{"https://aflock.ai/attestations/product/v0.3"})

	fetcher := &fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{
		"gitoid-build": buildEnv,
		"gitoid-test":  testEnv,
	}}
	installFakeCommitFetcher(t, fetcher)

	var out, errOut bytes.Buffer
	pol, count, err := derivePolicyFromCommit(context.Background(), &errOut,
		policyFromCommitOpts{expiresIn: 365 * 24 * time.Hour},
		testCommitSHA, "https://archivista.example", "bearer-token")
	require.NoError(t, err)
	_ = out

	// (a) It queried by the commit sha as the subject digest value — the join key.
	require.Contains(t, fetcher.queriedSubjects, testCommitSHA,
		"from-commit must query Archivista with the commit sha as the subject digest value")

	// (b) Grouped by step: two distinct collection names → two steps.
	require.Equal(t, 2, count, "two collections → two steps")
	require.Contains(t, pol.Steps, "build")
	require.Contains(t, pol.Steps, "test")

	// (c) #5989: the bundle's own RFC3161 TSA leaf must NOT be auto-embedded as
	//     a trust anchor (evidence cannot vouch for its own signing time). The
	//     operator must add a KNOWN platform TSA root before signing; we warn.
	assert.Empty(t, pol.TimestampAuthorities,
		"#5989: collection-derived TSA leaf must not be registered as a trust anchor")
	assert.Contains(t, errOut.String(), "NOT trusted automatically",
		"operator must be warned the evidence TSA leaf is not auto-trusted")
	//     ...and a non-empty signer-email cert constraint on the keyless functionary
	//     (this collection HAS a SAN email, so the functionary is emitted and pinned).
	build := pol.Steps["build"]
	require.Len(t, build.Functionaries, 1)
	require.Equal(t, "root", build.Functionaries[0].Type)
	assert.Contains(t, build.Functionaries[0].CertConstraint.Emails, signerEmail,
		"keyless functionary must pin the signer SAN email (empty list forbids all)")
}

// TestFromCommit_AuthorOnlyWritesPureJSONToStdout covers the default mode: no
// --product/--tag, so it authors a policy and writes it to stdout. stdout must
// be PURE policy JSON (parseable from byte 0) — the status line goes to stderr,
// so `cilock policy from-commit HEAD > policy.json` produces a valid artifact
// (Codex critical finding on PR #5743).
func TestFromCommit_AuthorOnlyWritesPureJSONToStdout(t *testing.T) {
	env := pubkeyCollectionEnvelope(t, "build", []string{"https://slsa.dev/provenance/v1"})
	installFakeCommitFetcher(t, &fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{"g1": env}})

	srv := newPolicyTestServer(t, func(string, map[string]any, http.ResponseWriter) bool { return true })
	stubSession(t, srv.URL)

	// Separate stdout/stderr buffers — the whole point of this test.
	var stdout, stderr bytes.Buffer
	cmd := PolicyFromCommitCmd()
	cmd.SetArgs([]string{testCommitSHA, "--platform-url", srv.URL})
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	require.NoError(t, cmd.ExecuteContext(context.Background()))

	// stdout is PURE policy JSON: it must parse from the very first byte, with no
	// status-line prefix. This is what redirection (`> policy.json`) captures.
	var pol policy.Policy
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &pol),
		"stdout must be valid policy JSON with no status-line prefix; got:\n%s", stdout.String())
	require.Contains(t, pol.Steps, "build")

	// The human-facing status line goes to stderr, not stdout.
	assert.Contains(t, stderr.String(), "Authored a policy with 1 step")
	assert.NotContains(t, stdout.String(), "Authored a policy",
		"status line must NOT leak into stdout (would corrupt `> policy.json`)")
}

// TestFromCommit_NoAttestationsGivesActionableError covers the empty-result
// case: the user is told CI must have run `cilock run --enable-archivista`.
func TestFromCommit_NoAttestationsGivesActionableError(t *testing.T) {
	installFakeCommitFetcher(t, &fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{}})

	srv := newPolicyTestServer(t, func(string, map[string]any, http.ResponseWriter) bool { return true })
	stubSession(t, srv.URL)

	_, err := runCmd(t, PolicyFromCommitCmd(), testCommitSHA, "--platform-url", srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no attestations found for commit")
	assert.Contains(t, err.Error(), "cilock run --enable-archivista",
		"the error must steer the user to the CI requirement")
}

// TestFromCommit_ProductWithoutTagErrors covers the half-typed one-shot guard.
func TestFromCommit_ProductWithoutTagErrors(t *testing.T) {
	installFakeCommitFetcher(t, &fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{
		"g1": pubkeyCollectionEnvelope(t, "build", []string{"https://slsa.dev/provenance/v1"}),
	}})
	srv := newPolicyTestServer(t, func(string, map[string]any, http.ResponseWriter) bool { return true })
	stubSession(t, srv.URL)

	_, err := runCmd(t, PolicyFromCommitCmd(), testCommitSHA, "--platform-url", srv.URL, "--product", "my-svc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be used together")
}

// TestFromCommit_OneShotSignsPushesAndBinds is the end-to-end one-shot proof: it
// must derive → sign → createDsse(upload)+resolve → createPolicyDefinition(-if-
// missing) → createPolicyRelease → createPolicyBinding, in that order. The sign
// step is stubbed (no real Fulcio in a unit test) but must produce the signed
// file push consumes; the platform mutations are asserted via a recording
// GraphQL server + the fake uploader (reused from the push tests).
func TestFromCommit_OneShotSignsPushesAndBinds(t *testing.T) {
	var ops []string
	defExists := false // becomes true after createDefinition so bind's re-lookup finds it
	srv := newPolicyTestServer(t, func(q string, _ map[string]any, w http.ResponseWriter) bool {
		switch {
		case strings.Contains(q, "CilockDsseByGitoid"):
			ops = append(ops, "resolveDsse")
			_, _ = io.WriteString(w, `{"data":{"dsses":{"edges":[{"node":{"id":"dsse-uuid-1","gitoidSha256":"gitoid-abc"}}]}}}`)
		case strings.Contains(q, "CilockPolicyDefByName"):
			if defExists {
				_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[{"node":{"id":"def-new","name":"my-svc"}}]}}}`)
			} else {
				_, _ = io.WriteString(w, `{"data":{"policyDefinitions":{"edges":[]}}}`) // not found → create
			}
		case strings.Contains(q, "CilockCreatePolicyDef"):
			ops = append(ops, "createDefinition")
			defExists = true
			_, _ = io.WriteString(w, `{"data":{"createPolicyDefinition":{"id":"def-new","name":"my-svc"}}}`)
		case strings.Contains(q, "CilockCreatePolicyRelease"):
			ops = append(ops, "createRelease")
			_, _ = io.WriteString(w, `{"data":{"createPolicyRelease":{"id":"rel-1","tag":"v1"}}}`)
		case strings.Contains(q, "CilockProductByID"):
			_, _ = io.WriteString(w, `{"data":{"products":{"edges":[]}}}`) // miss by id → resolve by name
		case strings.Contains(q, "CilockProductByName"):
			_, _ = io.WriteString(w, `{"data":{"products":{"edges":[{"node":{"id":"prod-1","name":"my-svc"}}]}}}`)
		case strings.Contains(q, "CilockReleaseByTag"):
			_, _ = io.WriteString(w, `{"data":{"policyReleases":{"edges":[{"node":{"id":"rel-1","tag":"v1"}}]}}}`)
		case strings.Contains(q, "CilockCreatePolicyBinding"):
			ops = append(ops, "createBinding")
			_, _ = io.WriteString(w, `{"data":{"createPolicyBinding":{"id":"bind-1","policyDefinition":{"id":"def-new","name":"my-svc"},"policyRelease":{"id":"rel-1","tag":"v1"},"product":{"id":"prod-1","name":"my-svc"}}}}`)
		default:
			return false
		}
		return true
	})
	stubSession(t, srv.URL)

	// Archivista: serve one collection for the commit, and accept the signed
	// policy upload (createDsse). The fake uploader returns the gitoid the
	// resolveDsse op maps to dsse-uuid-1.
	installFakeCommitFetcher(t, &fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{
		"g1": pubkeyCollectionEnvelope(t, "build", []string{"https://slsa.dev/provenance/v1"}),
	}})
	up := &fakeUploader{gitoid: "gitoid-abc"}
	installFakeUploader(t, up)

	// Stub the sign step: instead of a real keyless Fulcio exchange, copy the
	// derived policy into a 1-signature DSSE file at outPath so push accepts it.
	origSign := runSignViaCmd
	var signed bool
	runSignViaCmd = func(_ *cobra.Command, _, inPath, outPath string) error {
		signed = true
		return writeStubSignedEnvelope(t, inPath, outPath)
	}
	t.Cleanup(func() { runSignViaCmd = origSign })

	// #5989: one-shot publish now requires explicit --yes (functionaries are
	// derived solely from evidence). Pass it to exercise the publish path.
	out, err := runCmd(t, PolicyFromCommitCmd(), testCommitSHA,
		"--platform-url", srv.URL, "--product", "my-svc", "--tag", "v1", "--yes")
	require.NoError(t, err, "one-shot output:\n%s", out)

	require.True(t, signed, "the one-shot must invoke the sign step")
	require.True(t, up.stored != nil && len(up.stored.Signatures) == 1,
		"push must upload the signed envelope: %#v", up.stored)

	// The publish ops must occur in order: resolveDsse → createDefinition →
	// createRelease → createBinding (definition lookup/product lookups interleave
	// but the mutating ops must be ordered).
	require.Equal(t, []string{"resolveDsse", "createDefinition", "createRelease", "createBinding"}, ops,
		"one-shot must createDsse(resolve)→createPolicyDefinition→createPolicyRelease→createPolicyBinding in order")
	assert.Contains(t, out, "bound")
}

// writeStubSignedEnvelope reads the unsigned policy at inPath and writes a
// DSSE envelope with one dummy signature to outPath — the minimal shape
// `cilock policy push` requires (it rejects zero-signature files).
func writeStubSignedEnvelope(t *testing.T, inPath, outPath string) error {
	t.Helper()
	raw, err := os.ReadFile(inPath) //nolint:gosec // test-controlled temp path
	if err != nil {
		return err
	}
	env := dsse.Envelope{
		Payload:     raw,
		PayloadType: "https://witness.testifysec.com/policy/v0.1",
		Signatures:  []dsse.Signature{{KeyID: "stub", Signature: []byte("sig")}},
	}
	b, err := json.Marshal(&env)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, b, 0o600)
}

// TestResolveCommitSHA_FullShaPassthrough confirms a full object id is used
// verbatim (no local-repo resolution needed).
func TestResolveCommitSHA_FullShaPassthrough(t *testing.T) {
	got, err := resolveCommitSHA(testCommitSHA)
	require.NoError(t, err)
	assert.Equal(t, testCommitSHA, got)

	// A sha256-length full id also passes through.
	sha256ID := strings.Repeat("a", 64)
	got, err = resolveCommitSHA(sha256ID)
	require.NoError(t, err)
	assert.Equal(t, sha256ID, got)
}

// envSubjectDigestValues is a small guard documenting the join-key assumption:
// the git attestor records the commit subject digest with value == raw commit
// sha (see plugins/attestors/git/git.go Subjects()). If that encoding changes,
// from-commit's query term must change too. This test pins the encoding our
// fixtures use so the assumption is visible.
func TestFromCommit_JoinKeyIsRawCommitSha(t *testing.T) {
	env := pubkeyCollectionEnvelope(t, "build", []string{"https://slsa.dev/provenance/v1"})
	// The fixture subject digest value is the raw sha, matching git.go's
	// `subjects["commithash:<sha>"] = {sha1: <sha>}`.
	var stmt struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	require.NoError(t, json.Unmarshal(env.Payload, &stmt))
	require.NotEmpty(t, stmt.Subject)
	assert.Equal(t, "abc", stmt.Subject[0].Digest["sha1"],
		"git attestor encodes the commit subject digest value as the raw commit sha; "+
			"from-commit queries SearchGitoidsBySubjects with that value")
}
