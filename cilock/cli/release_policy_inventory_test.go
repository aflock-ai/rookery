// jade:ring local

package cli

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/require"
)

var releaseInventoryPolicies = []struct {
	file  string
	steps []string
	chain bool
}{
	{"release-policy-platform.json", []string{"source-git", "build"}, false},
	{"release-policy-signed-binary.json", []string{"source-git", "build", "sign"}, true},
	{"self-host-minimal.policy.json", []string{"clone", "frontend-build", "embed-frontend", "binary-build"}, true},
}

func readReleaseInventoryPolicy(t *testing.T, name string) policy.Policy {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "dist", name))
	require.NoError(t, err)
	// Self-host roots are render-time placeholders, not base64 PEMs. The
	// fixture installs its ephemeral trust below; never render platform trust.
	var document map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &document))
	delete(document, "roots")
	delete(document, "timestampauthorities")
	body, err = json.Marshal(document)
	require.NoError(t, err)
	var p policy.Policy
	require.NoError(t, json.Unmarshal(body, &p))
	return p
}

// Capture real before/after sets, rather than manufacturing Merkle roots or leaves.
func captureReleaseInventory(t *testing.T, mode string, budget int, input, output string) (*material.Attestor, *product.Attestor) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	if input != "" {
		require.NoError(t, os.WriteFile(path, []byte(input), 0o600))
	}
	opts := []material.Option{}
	if mode != "legacy" {
		opts = append(opts, material.WithCompactInventory(mode == "detached"))
	}
	m := material.New(opts...)
	ctx, err := attestation.NewContext("release-fixture", []attestation.Attestor{m}, attestation.WithWorkingDir(dir), attestation.WithCaptureMode(attestation.CaptureWalk))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	if output != "" {
		require.NoError(t, os.WriteFile(path, []byte(output), 0o600))
	}
	p := product.New(product.WithCompactInventory(budget))
	require.NoError(t, p.Attest(ctx))
	return m, p
}

func TestReleasePolicyInventoryRules(t *testing.T) {
	detached, detachedProduct := captureReleaseInventory(t, "detached", 0, "source", "binary")
	omitted, inlineProduct := captureReleaseInventory(t, "omitted", 131072, "source", "binary")
	legacy, _ := captureReleaseInventory(t, "legacy", 131072, "source", "binary")
	empty, emptyProduct := captureReleaseInventory(t, "detached", 0, "", "")
	for _, spec := range releaseInventoryPolicies {
		t.Run(spec.file, func(t *testing.T) {
			p := readReleaseInventoryPolicy(t, spec.file)
			for i, name := range spec.steps {
				step := p.Steps[name]
				var edges []string
				if name == "sign" || spec.steps[0] == "clone" && i > 0 {
					edges = []string{spec.steps[i-1]}
				}
				require.Equal(t, edges, step.ArtifactsFrom, "preserve every existing artifact edge")
				if name == "clone" {
					found := false
					for _, a := range step.Attestations {
						found = found || a.Type == material.Type
					}
					require.True(t, found, "clone must commit its upstream materials")
				}
				for _, a := range step.Attestations {
					if a.Type != material.Type && a.Type != product.Type {
						continue
					}
					t.Run(name+"/"+a.Type, func(t *testing.T) {
						require.NotEmpty(t, a.RegoPolicies, "v0.3 alone does not require the compact representation")
						good := []attestation.Attestor{detached, empty}
						bad := []attestation.Attestor{legacy}
						if a.Type == product.Type {
							good = []attestation.Attestor{detachedProduct, inlineProduct, emptyProduct}
							bad = nil
						} else if spec.chain {
							bad = append(bad, omitted)
						} else {
							good = append(good, omitted)
						}
						for _, v := range good {
							require.NoError(t, policy.EvaluateRegoPolicy(v, a.RegoPolicies))
							require.NoError(t, policy.EvaluateRegoPolicy(v, a.RegoPolicies, map[string]interface{}{}), "wrapped input must enforce the same rule")
						}
						for _, v := range bad {
							require.ErrorContains(t, policy.EvaluateRegoPolicy(v, a.RegoPolicies), "compact")
						}
						base := good[0]
						for _, mutation := range []string{"missing-inventory", "schema", "kind", "state", "count", "empty-root", "empty-without-leaves", "oversized-inline"} {
							if a.Type == product.Type && mutation == "empty-without-leaves" {
								continue // The established empty product encoding omits leaves.
							}
							if a.Type == material.Type && mutation == "oversized-inline" {
								continue
							}
							t.Run(mutation, func(t *testing.T) {
								body, err := json.Marshal(base)
								require.NoError(t, err)
								var value map[string]any
								require.NoError(t, json.Unmarshal(body, &value))
								ref := value["inventory"].(map[string]any)
								switch mutation {
								case "missing-inventory":
									delete(value, "inventory")
								case "schema", "kind", "state":
									ref[mutation] = "invalid"
								case "count":
									ref["fileCount"] = 0
								case "empty-root", "empty-without-leaves":
									delete(value, "inventory")
									value["treeSize"], value["leaves"] = 0, []any{}
									if mutation == "empty-without-leaves" {
										value["merkleRoot"] = manifestTestDigest("")
										delete(value, "leaves")
									}
								case "oversized-inline":
									delete(value, "inventory")
									value["leaves"] = []any{map[string]string{"path": strings.Repeat("x", 131072)}}
								}
								body, err = json.Marshal(value)
								require.NoError(t, err)
								require.ErrorContains(t, policy.EvaluateRegoPolicy(attestation.NewRawAttestation(a.Type, body), a.RegoPolicies), "compact")
							})
						}
					})
				}
			}
		})
	}
}

func TestReleasePolicyInventoryResolution(t *testing.T) {
	m, p := captureReleaseInventory(t, "detached", 0, "source", "binary")
	for _, producer := range []attestation.Attestor{m, p} {
		for _, mutation := range []string{"valid", "digest", "bytes", "fileCount", "merkleRoot", "path", "legacy-upload-claim"} {
			t.Run(producer.Name()+"/"+mutation, func(t *testing.T) {
				exporter := producer.(attestation.InventoryExporter)
				body, err := exporter.InventoryBytes()
				require.NoError(t, err)
				predicate, err := json.Marshal(producer)
				require.NoError(t, err)
				var value map[string]any
				require.NoError(t, json.Unmarshal(predicate, &value))
				ref := value["inventory"].(map[string]any)
				digest := ref["digest"].(string)
				switch mutation {
				case "digest":
					ref["digest"] = manifestTestDigest("other inventory")
				case "bytes", "fileCount":
					ref[mutation] = ref[mutation].(float64) + 1
				case "merkleRoot":
					value["merkleRoot"] = manifestTestDigest("other root")
				case "path":
					body = bytes.Replace(body, []byte(`"path":"artifact"`), []byte(`"path":"replaced"`), 1)
				case "legacy-upload-claim":
					value["manifestUploaded"] = true
				}
				predicate, err = json.Marshal(value)
				require.NoError(t, err)
				collection := attestation.NewCollection("binding", []attestation.CompletedAttestor{{Attestor: attestation.NewRawAttestation(producer.Type(), predicate)}})
				wire, err := json.Marshal(collection)
				require.NoError(t, err)
				var decoded attestation.Collection
				err = json.Unmarshal(wire, &decoded)
				if err == nil {
					err = decoded.ResolveInventories(manifestIndex{digest: body}.lookup, "all")
				}
				if mutation == "valid" {
					require.NoError(t, err)
					require.Len(t, decoded.Artifacts(), 1)
				} else {
					require.ErrorContains(t, err, "inventory", "signed descriptors cannot substitute for verified inventory bytes")
				}
			})
		}
	}
}

func TestReleasePolicyInventoryWorkflow(t *testing.T) {
	// Only an in-memory test principal signs fixtures. No platform credentials,
	// authoritative policy signatures, publication, or activation are involved.
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
	sign := func(typ string, value any) dsse.Envelope {
		body, err := json.Marshal(value)
		require.NoError(t, err)
		env, err := dsse.Sign(typ, bytes.NewReader(body), dsse.SignWithSigners(signer))
		require.NoError(t, err)
		return env
	}
	for _, spec := range releaseInventoryPolicies {
		for _, mode := range []string{"inline-product", "detached-product", "empty-material", "omitted-material", "legacy-material", "missing-material", "tampered-material", "missing-product", "tampered-product", "chain-mismatch", "binary-mismatch", "missing-clone-material", "bad-keyguard"} {
			if !spec.chain && (mode == "missing-material" || mode == "tampered-material" || mode == "chain-mismatch") || mode == "missing-clone-material" && spec.steps[0] != "clone" {
				continue
			}
			// Verification follows only what the seed matches; relationship
			// edges are no longer followed. Seeded with the binary alone, the
			// earlier steps hang off the shared workflow digest only through a
			// BackRef, so EVERY mode fails. Seeding the shared digest as well
			// (the release gates' second seed, `-s sha1:<commit>`) reaches
			// them and restores each mode's own expectation.
			check := func(t *testing.T, seeded bool) {
				p := readReleaseInventoryPolicy(t, spec.file)
				// Replace trust only in this fixture; keep every type, Rego rule,
				// expiry and artifactsFrom edge from the unsigned template.
				p.PublicKeys = map[string]policy.PublicKey{keyID: {KeyID: keyID, Key: pub}}
				mem := source.NewMemorySource()
				envs := []dsse.Envelope{}
				input, final := "source", ""
				for i, name := range spec.steps {
					step := p.Steps[name]
					step.Functionaries = []policy.Functionary{{Type: "publickey", PublicKeyID: keyID}}
					// The real requiredArtifacts name the release path
					// (/tmp/build/cilock); the fixture records its binary as
					// "artifact". Map the requirement onto the fixture path so it
					// stays enforced here (#9946).
					if len(step.RequiredArtifacts) > 0 {
						step.RequiredArtifacts = []string{"artifact"}
					}
					p.Steps[name] = step
					materialMode, budget := "detached", 0
					if mode == "inline-product" {
						budget = 131072
					}
					if mode == "legacy-material" {
						materialMode = "legacy"
					} else if mode == "omitted-material" {
						materialMode = "omitted"
					}
					output := name + "-output"
					if i == 0 {
						output = "" // The checkout step captures existing materials.
					}
					if mode == "chain-mismatch" && i == len(spec.steps)-1 {
						input = "substituted-binary"
					}
					if mode == "empty-material" && i == len(spec.steps)-1 {
						input = ""
					}
					m, prod := captureReleaseInventory(t, materialMode, budget, input, output)
					if output != "" {
						input, final = output, output
					}
					captured := []attestation.Attestor{m, prod}
					if mode == "missing-clone-material" && name == "clone" {
						captured = []attestation.Attestor{prod}
					}
					for _, required := range step.Attestations {
						if required.Type == material.Type || required.Type == product.Type {
							continue
						}
						body := []byte(`{}`)
						if strings.Contains(required.Type, "/command-run/") {
							body = []byte(`{"_meta":{"version":"v0.2","keyGuard":{"applied":true,"dumpable":false}},"exitcode":0}`)
							if mode == "bad-keyguard" {
								body = bytes.Replace(body, []byte(`"applied":true`), []byte(`"applied":false`), 1)
							}
						}
						captured = append(captured, attestation.NewRawAttestation(required.Type, body))
					}
					completed := []attestation.CompletedAttestor{}
					for _, a := range captured {
						completed = append(completed, attestation.CompletedAttestor{Attestor: a, StartTime: time.Now(), EndTime: time.Now()})
						if exporter, ok := a.(attestation.CompanionExporter); ok {
							for _, companion := range exporter.Companions() {
								kind := a.Name()
								if mode == "missing-"+kind {
									continue
								}
								body, err := json.Marshal(companion)
								require.NoError(t, err)
								if mode == "tampered-"+kind {
									body = bytes.Replace(body, []byte(`"path":"artifact"`), []byte(`"path":"replaced"`), 1)
								}
								stmt, err := intoto.NewStatement(fileinventory.Type, body, companion.(attestation.Subjecter).Subjects())
								require.NoError(t, err)
								envs = append(envs, sign(intoto.PayloadType, stmt))
							}
						}
					}
					collection := attestation.NewCollection(name, completed)
					// Model the shared workflow context used for release discovery.
					shared := cryptoutil.DigestSet{{Hash: crypto.SHA256}: manifestTestDigest("fixture-workflow")}
					if collection.RecordedBackRefs == nil {
						collection.RecordedBackRefs = map[string]cryptoutil.DigestSet{}
					}
					collection.RecordedBackRefs["fixture-workflow"] = shared
					subjects := collection.Subjects()
					subjects["fixture-workflow"] = shared
					body, err := json.Marshal(collection)
					require.NoError(t, err)
					stmt, err := intoto.NewStatement(attestation.CollectionType, body, subjects)
					require.NoError(t, err)
					env := sign(intoto.PayloadType, stmt)
					require.NoError(t, mem.LoadEnvelope(name, env))
					envs = append(envs, env)
				}
				digest := manifestTestDigest(final)
				if mode == "binary-mismatch" {
					digest = manifestTestDigest("unrelated binary")
				}
				subjects := expandSubjectsWithInclusionProofs([]cryptoutil.DigestSet{{{Hash: crypto.SHA256}: digest}}, envs, "artifact", digest)
				if seeded {
					subjects = append(subjects, cryptoutil.DigestSet{{Hash: crypto.SHA256}: manifestTestDigest("fixture-workflow")})
				}
				inventories := indexMaterialManifests(envs)
				result, verifyErr := workflow.Verify(t.Context(), sign(policy.PolicyPredicate, p), []cryptoutil.Verifier{verifier}, workflow.VerifyWithCollectionSource(mem), workflow.VerifyWithSubjectDigests(subjects), workflow.VerifyWithMaterialManifests(inventories))
				if verifyErr == nil {
					verifyErr = requireInventoryArtifactBinding(digest, result.StepResults, inventories, inventories.lookup)
				}
				if !seeded {
					require.Error(t, verifyErr, "seeded with the binary alone, steps reachable only through the shared BackRef must not be found")
					require.Empty(t, result.StepResults[spec.steps[0]].Passed, "the first step is reachable only through the shared BackRef, which is no longer followed")
					return
				}
				// A step whose policy pins requiredArtifacts cannot be satisfied by
				// an empty material set: it consumed nothing, so it did not
				// consume the artifact (#9946).
				requires := len(p.Steps[spec.steps[len(spec.steps)-1]].RequiredArtifacts) > 0
				if mode == "empty-material" && requires {
					require.Error(t, verifyErr)
					reasons := verifyErr.Error()
					for _, step := range result.StepResults {
						for _, rejected := range step.Rejected {
							reasons += "\n" + rejected.Reason.Error()
						}
					}
					require.Contains(t, reasons, "requiredArtifacts")
					return
				}
				if mode == "inline-product" || mode == "detached-product" || mode == "empty-material" || mode == "omitted-material" && !spec.chain {
					require.NoError(t, verifyErr, "%+v", result.StepResults)
				} else {
					require.Error(t, verifyErr, "missing details must not erase compact requirements or artifact edges")
					reasons := verifyErr.Error()
					for _, step := range result.StepResults {
						for _, rejected := range step.Rejected {
							reasons += "\n" + rejected.Reason.Error()
						}
					}
					switch mode {
					case "legacy-material", "omitted-material":
						require.Contains(t, reasons, "compact")
					case "missing-material", "tampered-material", "missing-product", "tampered-product":
						require.Contains(t, reasons, "inventory")
					case "chain-mismatch":
						require.Contains(t, reasons, "mismatched digests")
					case "bad-keyguard":
						require.Contains(t, reasons, "keyGuard")
					}
				}
			}
			t.Run(spec.file+"/"+mode+"/unseeded", func(t *testing.T) { check(t, false) })
			t.Run(spec.file+"/"+mode+"/seeded", func(t *testing.T) { check(t, true) })
		}
	}
}
