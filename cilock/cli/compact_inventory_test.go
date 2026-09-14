// jade:ring local

package cli

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/aflock-ai/rookery/attestation/workflow"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const compactInventoryType = "https://aflock.ai/attestations/file-inventory/v0.1"

func TestCompactInventoryVerifyRemoteMultiProduct(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithHash(crypto.SHA256))
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	pub, err := verifier.Bytes()
	require.NoError(t, err)
	digest := manifestTestDigest("artifact")
	other := manifestTestDigest("distinct product")
	ref, body, err := fileinventory.Encode("product", "walk", []fileinventory.Entry{{Path: "a", FileDigest: digest}, {Path: "b", FileDigest: other}})
	require.NoError(t, err)
	side, err := inclusionproof.BuildSidecar("product", map[string]string{"a": digest, "b": other})
	require.NoError(t, err)
	require.Len(t, side.Leaves, 2, "must not exercise the single-leaf shortcut")
	for _, mode := range []string{"remote", "offline", "missing", "tamper", "wrong-root", "unrelated-artifact"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("HOME", dir)
			t.Setenv("XDG_CONFIG_HOME", dir)
			state, err := filepath.EvalSymlinks(dir)
			require.NoError(t, err)
			t.Setenv("CILOCK_STATE_DIR", state)
			t.Setenv("CILOCK_SKIP_VERSION_CHECK", "1")
			t.Setenv("CILOCK_NO_TELEMETRY", "1")
			write := func(name string, data []byte) string {
				path := filepath.Join(dir, name)
				require.NoError(t, os.WriteFile(path, data, 0o600))
				return path
			}
			root := side.MerkleRoot
			if mode == "wrong-root" {
				root = manifestTestDigest("wrong root")
			}
			parent, err := json.Marshal(map[string]any{"predicateType": collectionPredicateURI, "subject": []any{map[string]any{"name": "tree:products", "digest": map[string]string{"sha256": root}}}, "predicate": map[string]any{"name": "build", "attestations": []any{map[string]any{"type": productTreeType, "starttime": "2026-01-01T00:00:00Z", "endtime": "2026-01-01T00:00:01Z", "attestation": map[string]any{"merkleRoot": root, "treeSize": 2, "hashAlgorithm": "sha256", "construction": "RFC6962", "inventory": ref}}}}})
			require.NoError(t, err)
			env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(parent), dsse.SignWithSigners(signer))
			require.NoError(t, err)
			raw, err := json.Marshal(env)
			require.NoError(t, err)
			parentPath := write("parent.json", raw)
			pol := policy.Policy{Expires: metav1.NewTime(time.Now().Add(time.Hour)), PublicKeys: map[string]policy.PublicKey{keyID: {KeyID: keyID, Key: pub}}, Steps: map[string]policy.Step{"build": {Name: "build", Functionaries: []policy.Functionary{{Type: "publickey", PublicKeyID: keyID}}, Attestations: []policy.Attestation{{Type: productTreeType}}}}}
			policyBytes, err := json.Marshal(pol)
			require.NoError(t, err)
			policyEnv, err := dsse.Sign(policy.PolicyPredicate, bytes.NewReader(policyBytes), dsse.SignWithSigners(signer))
			require.NoError(t, err)
			policyRaw, err := json.Marshal(policyEnv)
			require.NoError(t, err)
			remoteBody := body
			if mode == "tamper" {
				remoteBody = bytes.Replace(body, []byte(`"path":"b"`), []byte(`"path":"c"`), 1)
			}
			payload, err := json.Marshal(map[string]any{"predicateType": fileinventory.Type, "subject": []any{map[string]any{"digest": map[string]string{"sha256": ref.Digest}}}, "predicate": json.RawMessage(remoteBody)})
			require.NoError(t, err)
			remoteRaw, err := json.Marshal(dsse.Envelope{PayloadType: intoto.PayloadType, Payload: payload})
			require.NoError(t, err)
			gitoid := manifestTestDigest(fmt.Sprintf("blob %d\x00%s", len(remoteRaw), remoteRaw))
			var requests, lookups, downloads atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				require.Equal(t, "Bearer inventory-test-only", r.Header.Get("Authorization"))
				if r.URL.Path == "/query" {
					query, readErr := io.ReadAll(r.Body)
					require.NoError(t, readErr)
					edges := []any{}
					if bytes.Contains(query, []byte(ref.Digest)) {
						lookups.Add(1)
						if mode != "missing" {
							edges = append(edges, map[string]any{"node": map[string]string{"gitoidSha256": gitoid}})
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"dsses": map[string]any{"edges": edges}}})
					return
				}
				downloads.Add(1)
				_, _ = w.Write(remoteRaw)
			}))
			t.Cleanup(srv.Close)
			artifact := []byte("artifact")
			if mode == "unrelated-artifact" {
				artifact = []byte("not a product")
			}
			vsaPath := filepath.Join(dir, "vsa.json")
			cmd := VerifyCmd()
			cmd.SetArgs([]string{write("artifact", artifact), "-p", write("policy.json", policyRaw), "-k", write("key.pub", pub), "-a", parentPath, "--platform-url", "", "--enable-archivista=" + fmt.Sprint(mode != "offline"), "--archivista-server", srv.URL, "--archivista-headers", "Authorization: Bearer inventory-test-only", "--archivista-oidc=false", "--no-embedded-trust", "--vsa-outfile", vsaPath})
			err = cmd.ExecuteContext(t.Context())
			if mode == "remote" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			if mode == "offline" {
				require.Zero(t, requests.Load(), "offline must not contact Archivista")
			} else {
				require.Equal(t, int64(1), lookups.Load(), "discovery and verification must share the cached lookup")
				if mode != "missing" {
					require.Equal(t, int64(1), downloads.Load())
				}
			}
			if vsaBytes, readErr := os.ReadFile(vsaPath); readErr == nil {
				var stmt intoto.Statement
				require.NoError(t, json.Unmarshal(vsaBytes, &stmt))
				var vsa slsa.VerificationSummary
				require.NoError(t, json.Unmarshal(stmt.Predicate, &vsa))
				require.Equal(t, mode == "remote", vsa.VerificationResult == slsa.PassedVerificationResult, "no false PASSED VSA")
			} else {
				require.NotEqual(t, "remote", mode)
				require.ErrorIs(t, readErr, os.ErrNotExist)
			}
		})
	}
}

func TestCompactInventoryIndexExactBytes(t *testing.T) {
	body := []byte(`{ "schema": "` + compactInventoryType + `", "kind": "product", "entries": [] }`)
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"` + compactInventoryType + `","predicate":` + string(body) + `}`)
	ix := indexMaterialManifests([]dsse.Envelope{{PayloadType: intoto.PayloadType, Payload: payload}})
	got, ok := ix.lookup(manifestTestDigest(string(body)))
	if !ok || !bytes.Equal(got, body) {
		t.Fatalf("inventory not indexed by exact bytes: found=%v body=%s", ok, got)
	}
	var normalized bytes.Buffer
	if err := json.Compact(&normalized, body); err != nil {
		t.Fatal(err)
	}
	if _, ok := ix.lookup(manifestTestDigest(normalized.String())); ok {
		t.Fatal("modern inventory was normalized into a different digest")
	}
}

func TestCompactInventorySignedWorkflow(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithHash(crypto.SHA256))
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	pub, err := verifier.Bytes()
	require.NoError(t, err)
	for _, mode := range []string{"local", "source", "callback", "missing-material", "missing-product", "corrupt", "command-only", "cli", "cli-missing"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name string, value any) string {
				data, err := json.Marshal(value)
				require.NoError(t, err)
				path := filepath.Join(dir, name)
				require.NoError(t, os.WriteFile(path, data, 0o600))
				return path
			}
			mem := source.NewMemorySource()
			manifests := manifestIndex{}
			pol := policy.Policy{Expires: metav1.NewTime(time.Now().Add(time.Hour)), PublicKeys: map[string]policy.PublicKey{keyID: {KeyID: keyID, Key: pub}}, Steps: map[string]policy.Step{}}
			root := ""
			for _, kind := range []string{"product", "material"} {
				ref, body, commitment, _ := compactInventoryFixture(t, kind)
				root = commitment
				name := "build"
				if kind == "material" {
					name = "test"
				}
				tp := "https://aflock.ai/attestations/" + kind + "/v0.3"
				parent, err := json.Marshal(map[string]any{"predicateType": collectionPredicateURI, "subject": []any{map[string]any{"name": "tree:" + kind, "digest": map[string]string{"sha256": root}}}, "predicate": map[string]any{"name": name, "attestations": []any{map[string]any{"type": tp, "starttime": "2026-01-01T00:00:00Z", "endtime": "2026-01-01T00:00:01Z", "attestation": map[string]any{"merkleRoot": root, "treeSize": 1, "hashAlgorithm": "sha256", "construction": "RFC6962", "inventory": ref}}}}})
				require.NoError(t, err)
				env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(parent), dsse.SignWithSigners(signer))
				require.NoError(t, err)
				require.NoError(t, mem.LoadEnvelope(name, env))
				if mode == "cli" || mode == "cli-missing" {
					write(name+".json", env)
					payload, err := json.Marshal(map[string]any{"predicateType": fileinventory.Type, "predicate": json.RawMessage(body)})
					require.NoError(t, err)
					companion, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(signer))
					require.NoError(t, err)
					if mode == "cli" {
						write(name+".json-inventory.json", companion)
					}
				}
				step := policy.Step{Name: name, Functionaries: []policy.Functionary{{Type: "publickey", PublicKeyID: keyID}}, Attestations: []policy.Attestation{{Type: tp}}}
				if kind == "material" && mode != "command-only" && mode != "cli-missing" {
					step.ArtifactsFrom = []string{"build"}
				}
				pol.Steps[name] = step
				if mode == "missing-"+kind || mode == "command-only" {
					continue
				}
				if mode == "corrupt" {
					body = bytes.Replace(body, []byte(`"path":"b"`), []byte(`"path":"c"`), 1)
				}
				if mode != "source" {
					manifests[ref.Digest] = body
				} else {
					payload, err := json.Marshal(map[string]any{"predicateType": fileinventory.Type, "subject": []any{map[string]any{"name": "inventory:" + kind, "digest": map[string]string{"sha256": ref.Digest}}}, "predicate": json.RawMessage(body)})
					require.NoError(t, err)
					require.NoError(t, mem.LoadEnvelope("inventory-"+kind, dsse.Envelope{PayloadType: intoto.PayloadType, Payload: payload}))
				}
				if mode == "local" {
					ce, err := source.EnvelopeToCollectionEnvelope(name, env)
					require.NoError(t, err)
					before, err := json.Marshal(ce.Collection)
					require.NoError(t, err)
					require.NoError(t, ce.Collection.ResolveInventories(manifests.lookup, kind))
					after, err := json.Marshal(ce.Collection)
					require.NoError(t, err)
					require.Equal(t, before, after, "hydration must not rewrite signed compact representation")
					require.Len(t, ce.Collection.Artifacts(), 2, "duplicate-content paths must survive hydration")
				}
			}
			policyBytes, err := json.Marshal(pol)
			require.NoError(t, err)
			policyEnvelope, err := dsse.Sign(policy.PolicyPredicate, bytes.NewReader(policyBytes), dsse.SignWithSigners(signer))
			require.NoError(t, err)
			if mode == "cli" || mode == "cli-missing" {
				t.Setenv("HOME", dir)
				t.Setenv("XDG_CONFIG_HOME", dir)
				state, err := filepath.EvalSymlinks(dir)
				require.NoError(t, err)
				t.Setenv("CILOCK_STATE_DIR", state)
				t.Setenv("CILOCK_SKIP_VERSION_CHECK", "1")
				t.Setenv("CILOCK_NO_TELEMETRY", "1")
				pubPath := filepath.Join(dir, "key.pub")
				require.NoError(t, os.WriteFile(pubPath, pub, 0o600))
				keyDER, err := x509.MarshalECPrivateKey(key)
				require.NoError(t, err)
				keyPath := filepath.Join(dir, "key.pem")
				require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
				cmd := VerifyCmd()
				artifact := filepath.Join(dir, "artifact")
				require.NoError(t, os.WriteFile(artifact, []byte("artifact"), 0o600))
				policyPath := write("policy.json", policyEnvelope)
				bundlePath := filepath.Join(dir, "replay.tar.gz")
				vsaPath := filepath.Join(dir, "verification.dsse.json")
				cmd.SetArgs([]string{"-p", policyPath, "-k", pubPath, "-a", filepath.Join(dir, "build.json"), "-a", filepath.Join(dir, "test.json"), "--artifactfile", artifact, "--platform-url", "", "--enable-archivista=false", "--no-embedded-trust", "--output-bundle", bundlePath, "--vsa-outfile", vsaPath, "--signer-file-key-path", keyPath})
				err = cmd.ExecuteContext(t.Context())
				if mode == "cli" {
					require.NoError(t, err)
					vsaEnvelope, err := loadEnvelopeFromFile(vsaPath)
					require.NoError(t, err)
					_, err = vsaEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
					require.NoError(t, err)
					var stmt intoto.Statement
					require.NoError(t, json.Unmarshal(vsaEnvelope.Payload, &stmt))
					require.Equal(t, slsa.VerificationSummaryPredicate, stmt.PredicateType)
					var vsa slsa.VerificationSummary
					require.NoError(t, json.Unmarshal(stmt.Predicate, &vsa))
					require.Equal(t, slsa.PassedVerificationResult, vsa.VerificationResult)
					envelopes, err := loadEnvelopesFromBundle(bundlePath, source.NewMemorySource())
					require.NoError(t, err)
					require.Equal(t, manifests, indexMaterialManifests(envelopes), "replay must carry exact inventory bytes")
					replay := VerifyCmd()
					replay.SetArgs([]string{"-p", policyPath, "-k", pubPath, "--bundle", bundlePath, "--artifactfile", artifact, "--platform-url", "", "--enable-archivista=false", "--no-embedded-trust"})
					require.NoError(t, replay.ExecuteContext(t.Context()))
				} else {
					require.ErrorContains(t, err, "inventory")
					_, statErr := os.Stat(vsaPath)
					require.ErrorIs(t, statErr, os.ErrNotExist, "structural inventory failure must not export the policy's PASSED VSA")
				}
				return
			}
			opts := []workflow.VerifyOption{workflow.VerifyWithCollectionSource(mem), workflow.VerifyWithSubjectDigests([]cryptoutil.DigestSet{{{Hash: crypto.SHA256}: root}})}
			if mode == "callback" {
				opts = append(opts, workflow.VerifyWithInventoryLookup(manifests.lookup))
			} else {
				opts = append(opts, workflow.VerifyWithMaterialManifests(manifests))
			}
			result, err := workflow.Verify(context.Background(), policyEnvelope, []cryptoutil.Verifier{verifier}, opts...)
			if mode == "local" || mode == "source" || mode == "callback" || mode == "command-only" {
				require.NoError(t, err, "%+v", result.StepResults)
			} else {
				require.Error(t, err)
				require.NotEmpty(t, result.StepResults["test"].Rejected)
				require.Contains(t, result.StepResults["test"].Rejected[0].Reason.Error(), "inventory")
			}
		})
	}
}

func compactInventoryFixture(t *testing.T, kind string) (*fileinventory.Reference, []byte, string, string) {
	t.Helper()
	digest := manifestTestDigest("artifact")
	ref, body, err := fileinventory.Encode(kind, "walk", []fileinventory.Entry{{Path: "a", FileDigest: digest}, {Path: "b", FileDigest: digest}})
	require.NoError(t, err)
	side, err := inclusionproof.BuildSidecar(kind, map[string]string{"a": digest, "b": digest})
	require.NoError(t, err)
	return ref, body, side.MerkleRoot, digest
}

func TestCompactInventoryLocalInferenceAndInclusion(t *testing.T) {
	for _, tc := range []struct{ kind, prefix string }{
		{"material", "https://aflock.ai/attestations/"},
		{"product", "https://aflock.ai/attestations/"},
		{"material", "https://witness.dev/attestations/"},
		{"product", "https://witness.dev/attestations/"},
	} {
		kind, tp := tc.kind, tc.prefix+tc.kind+"/v0.3"
		t.Run(tp, func(t *testing.T) {
			ref, body, root, digest := compactInventoryFixture(t, kind)
			parent := map[string]any{"predicateType": collectionPredicateURI, "predicate": map[string]any{"name": "build", "attestations": []any{map[string]any{"type": tp, "attestation": map[string]any{"merkleRoot": root, "treeSize": 1, "hashAlgorithm": "sha256", "construction": "RFC6962", "inventory": ref}}}}}
			path := filepath.Join(t.TempDir(), "build.bundle.json")
			writeEnvelope(t, path, parent)
			writeEnvelope(t, path+"-inventory.json", map[string]any{"predicateType": fileinventory.Type, "predicate": json.RawMessage(body)})
			summary, err := summarizeOneBundle(io.Discard, path, "")
			require.NoError(t, err)
			companionSummary := bundleSummary{outerPredicateType: fileinventory.Type, stepName: "inventory", signingKeyIDs: []string{"unrelated-companion-signer"}}
			starter, err := buildStarterPolicy(io.Discard, []bundleSummary{summary, companionSummary}, nil, time.Hour)
			require.NoError(t, err)
			require.Empty(t, starter.ExternalAttestations, "explicit companion inputs must not gain independent authority")
			require.NotContains(t, starter.PublicKeys, "unrelated-companion-signer")
			_, err = buildStarterPolicy(io.Discard, []bundleSummary{companionSummary}, nil, time.Hour)
			require.Error(t, err, "an inventory without parent evidence cannot define a policy")
			if kind == "product" {
				require.Contains(t, summary.productDigests, digest)
			} else {
				require.Contains(t, summary.materialDigests, digest)
			}
			parentBytes, err := json.Marshal(parent)
			require.NoError(t, err)
			originalParent := bytes.Clone(parentBytes)
			companionBytes, err := json.Marshal(map[string]any{"predicateType": fileinventory.Type, "predicate": json.RawMessage(body)})
			require.NoError(t, err)
			subjects := []cryptoutil.DigestSet{{{Hash: crypto.SHA256}: digest}}
			envs := []dsse.Envelope{{PayloadType: intoto.PayloadType, Payload: parentBytes}, {PayloadType: intoto.PayloadType, Payload: companionBytes}}
			expanded := expandSubjectsWithInclusionProofs(subjects, envs, "", "")
			require.Equal(t, originalParent, envs[0].Payload, "inclusion must not rewrite signed bytes")
			require.Len(t, expanded, 2, "local-only inventory must prove inclusion")
			require.Equal(t, root, expanded[1][cryptoutil.DigestValue{Hash: crypto.SHA256}])
			envs[1].Payload = bytes.Replace(companionBytes, []byte(`"path":"b"`), []byte(`"path":"c"`), 1)
			require.Len(t, expandSubjectsWithInclusionProofs(subjects, envs, "", ""), 1, "same content root cannot authenticate substituted paths")
		})
	}
}

func TestCompactInventoryInferenceLegacyFilenames(t *testing.T) {
	for _, version := range []string{"material/v0.1", "product/v0.1", "product/v0.2"} {
		for _, filename := range []string{"inventory", "Inventory", "treeSize"} {
			t.Run(version+"/"+filename, func(t *testing.T) {
				digests := cryptoutil.DigestSet{{Hash: crypto.SHA256}: manifestTestDigest("legacy file")}
				var file any = digests
				if strings.HasPrefix(version, "product/") {
					file = attestation.Product{Digest: digests, MimeType: "text/plain"}
				}
				predicate, err := json.Marshal(map[string]any{filename: file})
				require.NoError(t, err)
				tp := "https://aflock.ai/attestations/" + version
				factory, ok := attestation.FactoryByType(tp)
				require.True(t, ok)
				require.NoError(t, json.Unmarshal(predicate, factory()), "fixture must be valid legacy evidence")
				parent := map[string]any{"predicateType": collectionPredicateURI, "predicate": map[string]any{"name": "build", "attestations": []any{map[string]any{"type": tp, "attestation": json.RawMessage(predicate)}}}}
				path := filepath.Join(t.TempDir(), "build.bundle.json")
				writeEnvelope(t, path, parent)
				t.Run("from-bundles", func(t *testing.T) {
					summary, err := summarizeOneBundle(io.Discard, path, "")
					require.NoError(t, err)
					require.Contains(t, summary.predicateTypes, tp)
					require.Empty(t, summary.materialDigests)
					require.Empty(t, summary.productDigests)
				})
				t.Run("from-commit", func(t *testing.T) {
					payload, err := json.Marshal(parent)
					require.NoError(t, err)
					f := &inventoryCommitFetcher{fakeCommitFetcher: fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{"build": {PayloadType: intoto.PayloadType, Payload: payload, Signatures: []dsse.Signature{{KeyID: "test", Signature: []byte("summary-only")}}}}}, bySubject: map[string][]string{gitSHA1Hex: {"build"}}}
					original := newCommitFetcher
					newCommitFetcher = func(_, _ string) commitFetcher { return f }
					t.Cleanup(func() { newCommitFetcher = original })
					pol, count, err := derivePolicyFromCommit(t.Context(), io.Discard, policyFromCommitOpts{expiresIn: time.Hour}, gitSHA1Hex, "https://configured.invalid", "")
					require.NoError(t, err)
					require.Equal(t, 1, count)
					require.Empty(t, pol.Steps["build"].ArtifactsFrom)
					require.Equal(t, []string{gitSHA1Hex}, f.queriedSubjects, "legacy filenames must not trigger inventory lookups")
				})
			})
		}
	}
}

func TestCompactInventoryInferenceExactTypes(t *testing.T) {
	for _, kind := range []string{"material", "product"} {
		for _, tp := range []string{
			"https://aflock.ai/attestations/" + kind + "/v0.3",
			"https://witness.dev/attestations/" + kind + "/v0.3",
			"https://aflock.ai/attestations/" + kind + "/v0.30",
			"https://witness.dev/attestations/" + kind + "/v0.30",
			"https://witness.testifysec.com/attestations/" + kind + "/v0.3",
			"https://other.invalid/attestations/" + kind + "/v0.3",
		} {
			t.Run(tp, func(t *testing.T) {
				data, err := json.Marshal(map[string]any{"type": tp, "attestation": map[string]any{"inventory": map[string]string{"sha256": manifestTestDigest("file")}}})
				require.NoError(t, err)
				var inner bundleInnerAttestation
				err = json.Unmarshal(data, &inner)
				if tp == materialTreeType || tp == productTreeType || tp == "https://witness.dev/attestations/"+kind+"/v0.3" {
					require.Equal(t, "https://aflock.ai/attestations/"+kind+"/v0.3", attestation.ResolveLegacyType(tp))
					_, registered := attestation.FactoryByType(tp)
					require.True(t, registered, "supported aliases must share the attestor registry")
					require.Error(t, err, "malformed modern descriptors must still fail closed")
				} else {
					require.NoError(t, err)
					require.Nil(t, inner.Attestation.Inventory, "only supported exact types may decode descriptors")
				}
				require.Equal(t, tp, inner.Type, "classification must not rewrite the signed type")
			})
		}
	}
}

func TestCompactInventoryInferenceRefusesUnknownEdges(t *testing.T) {
	for _, kind := range []string{"material", "product"} {
		for _, state := range []string{"omitted", "detached"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				ref := map[string]any{"schema": compactInventoryType, "kind": kind, "state": state, "fileCount": 1, "captureMode": "walk", "captureScope": "working-directory"}
				if state == "detached" {
					ref["digest"] = manifestTestDigest("missing")
					ref["bytes"] = 123
				}
				path := filepath.Join(t.TempDir(), "build.bundle.json")
				writeEnvelope(t, path, map[string]any{
					"predicateType": collectionPredicateURI,
					"predicate": map[string]any{"name": "build", "attestations": []any{map[string]any{
						"type":        "https://aflock.ai/attestations/" + kind + "/v0.3",
						"attestation": map[string]any{"merkleRoot": manifestTestDigest("root"), "treeSize": 1, "inventory": ref},
					}}},
				})
				if _, err := summarizeOneBundle(io.Discard, path, ""); err == nil {
					t.Fatal("policy inference silently omitted unknown inventory edges")
				}
			})
		}
	}
}

type inventoryCommitFetcher struct {
	fakeCommitFetcher
	bySubject      map[string][]string
	downloads      []string
	downloadLimits []int64
}

func (f *inventoryCommitFetcher) DownloadBounded(ctx context.Context, id string, limit int64) (dsse.Envelope, error) {
	f.downloadLimits = append(f.downloadLimits, limit)
	return f.Download(ctx, id)
}

func (f *inventoryCommitFetcher) Download(ctx context.Context, id string) (dsse.Envelope, error) {
	f.downloads = append(f.downloads, id)
	return f.fakeCommitFetcher.Download(ctx, id)
}

func (f *inventoryCommitFetcher) SearchGitoidsBySubjects(_ context.Context, subjects, _ []string) ([]string, error) {
	f.queriedSubjects = append(f.queriedSubjects, subjects...)
	if len(subjects) != 1 {
		return nil, nil
	}
	return f.bySubject[subjects[0]], nil
}

func TestCompactInventoryFromCommitInference(t *testing.T) {
	for _, productHost := range []string{"aflock.ai", "witness.dev"} {
		for _, materialHost := range []string{"aflock.ai", "witness.dev"} {
			for _, failure := range []string{"", "missing-product", "missing-material", "corrupt-product", "corrupt-material"} {
				t.Run(productHost+"/"+materialHost+"/"+failure, func(t *testing.T) {
					f := &inventoryCommitFetcher{fakeCommitFetcher: fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{}}, bySubject: map[string][]string{gitSHA1Hex: {"build", "test"}}}
					original := newCommitFetcher
					newCommitFetcher = func(_, _ string) commitFetcher { return f }
					t.Cleanup(func() { newCommitFetcher = original })
					paths := make([]string, 0, 2)
					for _, kind := range []string{"product", "material"} {
						ref, body, root, _ := compactInventoryFixture(t, kind)
						step, host := "build", productHost
						if kind == "material" {
							step, host = "test", materialHost
						}
						tp := "https://" + host + "/attestations/" + kind + "/v0.3"
						parent := map[string]any{"predicateType": collectionPredicateURI, "predicate": map[string]any{"name": step, "attestations": []any{map[string]any{"type": tp, "attestation": map[string]any{"merkleRoot": root, "treeSize": 1, "hashAlgorithm": "sha256", "construction": "RFC6962", "inventory": ref}}}}}
						payload, err := json.Marshal(parent)
						require.NoError(t, err)
						originalPayload := bytes.Clone(payload)
						f.byGitoid[step] = dsse.Envelope{PayloadType: intoto.PayloadType, Payload: payload, Signatures: []dsse.Signature{{KeyID: "test", Signature: []byte("summary-only")}}}
						t.Cleanup(func() {
							require.Equal(t, originalPayload, f.byGitoid[step].Payload, "inference must not rewrite signed bytes")
						})
						path := filepath.Join(t.TempDir(), step+".bundle.json")
						paths = append(paths, path)
						writeEnvelope(t, path, parent)
						if failure == "missing-"+kind {
							continue
						}
						if failure == "corrupt-"+kind {
							body = bytes.Replace(body, []byte(`"path":"b"`), []byte(`"path":"c"`), 1)
						}
						companion := map[string]any{"predicateType": fileinventory.Type, "subject": []any{map[string]any{"name": "inventory:" + kind, "digest": map[string]string{"sha256": ref.Digest}}}, "predicate": json.RawMessage(body)}
						companionBytes, err := json.Marshal(companion)
						require.NoError(t, err)
						f.byGitoid[ref.Digest] = dsse.Envelope{PayloadType: intoto.PayloadType, Payload: companionBytes}
						f.bySubject[ref.Digest] = []string{ref.Digest}
						writeEnvelope(t, path+"-inventory.json", companion)
					}
					t.Run("from-bundles", func(t *testing.T) {
						summaries := make([]bundleSummary, 0, 2)
						for _, path := range paths {
							summary, err := summarizeOneBundle(io.Discard, path, "")
							if err != nil && failure != "" {
								require.ErrorContains(t, err, "inventory")
								return
							}
							require.NoError(t, err)
							summaries = append(summaries, summary)
						}
						require.Empty(t, failure, "unavailable inventory must not erase inferred edges")
						pol, err := buildStarterPolicy(io.Discard, summaries, nil, time.Hour)
						require.NoError(t, err)
						require.Equal(t, []string{"build"}, pol.Steps["test"].ArtifactsFrom)
						require.Equal(t, "https://"+productHost+"/attestations/product/v0.3", pol.Steps["build"].Attestations[0].Type)
						require.Equal(t, "https://"+materialHost+"/attestations/material/v0.3", pol.Steps["test"].Attestations[0].Type)
					})
					t.Run("from-commit", func(t *testing.T) {
						pol, count, err := derivePolicyFromCommit(t.Context(), io.Discard, policyFromCommitOpts{expiresIn: time.Hour}, gitSHA1Hex, "https://configured.invalid", "")
						if failure != "" {
							require.ErrorContains(t, err, "inventory", "unavailable inventory must not erase inferred edges")
							return
						}
						require.NoError(t, err)
						require.Equal(t, 2, count)
						require.Equal(t, []string{"build"}, pol.Steps["test"].ArtifactsFrom)
						require.Equal(t, "https://"+productHost+"/attestations/product/v0.3", pol.Steps["build"].Attestations[0].Type)
						require.Equal(t, "https://"+materialHost+"/attestations/material/v0.3", pol.Steps["test"].Attestations[0].Type)
						require.Len(t, f.queriedSubjects, 3, "one commit lookup and one digest lookup per inventory")
						require.Empty(t, pol.ExternalAttestations, "inventory signer is not an independent policy authority")
					})
				})
			}
		}
	}
}

func TestCompactInventoryFromCommitDuplicateCandidates(t *testing.T) {
	ref, body, _, _ := compactInventoryFixture(t, "product")
	payload, err := json.Marshal(map[string]any{"predicateType": fileinventory.Type, "subject": []any{map[string]any{"digest": map[string]string{"sha256": ref.Digest}}}, "predicate": json.RawMessage(body)})
	require.NoError(t, err)
	for _, tc := range []struct {
		name          string
		invalidPrefix int
		want          bool
		downloads     int
	}{
		{"seventeen-identical-bodies", 0, true, 1},
		{"invalid-before-valid", 1, true, 2},
		{"valid-at-inspection-bound", 15, true, 16},
		{"no-match-within-bound", 16, false, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &inventoryCommitFetcher{fakeCommitFetcher: fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{}}, bySubject: map[string][]string{}}
			for i := 0; i < 17; i++ {
				id := fmt.Sprintf("wrapper-%02d", i)
				env := dsse.Envelope{PayloadType: intoto.PayloadType, Payload: payload, Signatures: []dsse.Signature{{KeyID: id, Signature: []byte{byte(i)}}}}
				if i < tc.invalidPrefix {
					env.Payload = []byte(`{"predicateType":"` + fileinventory.Type + `","predicate":{}}`)
				}
				f.byGitoid[id] = env
				f.bySubject[ref.Digest] = append(f.bySubject[ref.Digest], id)
			}
			got, ok := source.InventoryLookup(t.Context(), commitInventorySource{fetcher: f})(ref.Digest)
			require.Equal(t, tc.want, ok)
			if ok {
				require.Equal(t, body, got)
			}
			require.Len(t, f.downloads, tc.downloads, "stop on the first proven body, never fetch the full duplicate set")
			require.Len(t, f.downloadLimits, tc.downloads, "inventory downloads must use the tighter transport cap")
			for _, limit := range f.downloadLimits {
				require.Equal(t, source.MaxInventoryEnvelopeBytes, limit)
			}
		})
	}
}

func TestCompactInventorySharedLookupBudgets(t *testing.T) {
	t.Run("128-lookups-including-misses", func(t *testing.T) {
		f := &inventoryCommitFetcher{bySubject: map[string][]string{}}
		lookup := source.InventoryLookup(t.Context(), commitInventorySource{fetcher: f})
		for i := range 129 {
			digest := fmt.Sprintf("%064x", i)
			_, found := lookup(digest)
			require.False(t, found)
			_, found = lookup(digest)
			require.False(t, found)
		}
		require.Len(t, f.queriedSubjects, 128, "misses are cached and cannot reset the shared budget")
	})
	t.Run("64-MiB-cache", func(t *testing.T) {
		f := &inventoryCommitFetcher{fakeCommitFetcher: fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{}}, bySubject: map[string][]string{}}
		lookup := source.InventoryLookup(t.Context(), commitInventorySource{fetcher: f})
		for i := range 2 {
			// Individually valid, below the predicate limit; together over the
			// retained-byte cap. Schema validation remains the consumer's job.
			body := append([]byte(fmt.Sprintf(`{"case":%d,"padding":"`, i)), bytes.Repeat([]byte("x"), fileinventory.MaxBytes/2)...)
			body = append(body, []byte(`"}`)...)
			digest := manifestTestDigest(string(body))
			payload := []byte(`{"predicateType":"` + fileinventory.Type + `","subject":[{"digest":{"sha256":"` + digest + `"}}],"predicate":` + string(body) + `}`)
			f.byGitoid[digest] = dsse.Envelope{PayloadType: intoto.PayloadType, Payload: payload}
			f.bySubject[digest] = []string{digest}
			got, found := lookup(digest)
			require.Equal(t, i == 0, found)
			if found {
				require.Equal(t, body, got)
			}
			_, cached := lookup(digest)
			require.Equal(t, found, cached)
		}
		require.Len(t, f.downloads, 2, "accepted and over-budget results are both cached")
	})
}

func TestCompactInventoryFromCommitHTTPTransportBound(t *testing.T) {
	ref, _, _, _ := compactInventoryFixture(t, "product")
	var downloads atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer inventory-test-only" {
			t.Error("from-commit lost scoped auth")
		}
		if r.URL.Path == "/query" {
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"dsses": map[string]any{"edges": []any{map[string]any{"node": map[string]string{"gitoidSha256": "oversized"}}}}}})
			return
		}
		downloads.Add(1)
		w.Header().Set("Content-Length", fmt.Sprint(source.MaxInventoryEnvelopeBytes+1))
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err := (commitInventorySource{fetcher: newCommitFetcher(srv.URL, "inventory-test-only")}).SearchByPredicateType(ctx, []string{fileinventory.Type}, []string{ref.Digest})
	require.Error(t, err)
	require.NoError(t, ctx.Err(), "oversized inventory must be refused before reading, not after a deadline")
	require.Equal(t, int64(1), downloads.Load())
}
