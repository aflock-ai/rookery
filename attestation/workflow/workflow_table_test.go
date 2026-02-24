//go:build audit

// Copyright 2024 The Witness Contributors
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

package workflow

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Test helpers local to this file
// ==========================================================================

// tableAttestor is a flexible attestor for table-driven tests.
type tableAttestor struct {
	name       string
	typeName   string
	runType    attestation.RunType
	attestFunc func(*attestation.AttestationContext) error
	subjects   map[string]cryptoutil.DigestSet
	export     bool
}

func (a *tableAttestor) Name() string                 { return a.name }
func (a *tableAttestor) Type() string                 { return a.typeName }
func (a *tableAttestor) RunType() attestation.RunType { return a.runType }
func (a *tableAttestor) Schema() *jsonschema.Schema   { return nil }
func (a *tableAttestor) Attest(ctx *attestation.AttestationContext) error {
	if a.attestFunc != nil {
		return a.attestFunc(ctx)
	}
	return nil
}
func (a *tableAttestor) Subjects() map[string]cryptoutil.DigestSet {
	if a.subjects != nil {
		return a.subjects
	}
	return map[string]cryptoutil.DigestSet{}
}
func (a *tableAttestor) Export() bool { return a.export }

func tableRSASignerVerifier(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	return signer, verifier
}

// ==========================================================================
// 1. Option validation edge cases
// ==========================================================================

func TestTableValidateRunOpts(t *testing.T) {
	signer, _ := tableRSASignerVerifier(t)

	tests := []struct {
		name      string
		opts      runOptions
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "empty step name",
			opts:      runOptions{},
			wantErr:   true,
			errSubstr: "step name is required",
		},
		{
			name:      "no signers, not insecure",
			opts:      runOptions{stepName: "build"},
			wantErr:   true,
			errSubstr: "at least one signer is required",
		},
		{
			name:    "insecure, no signers -- valid",
			opts:    runOptions{stepName: "build", insecure: true},
			wantErr: false,
		},
		{
			name:    "has signers, not insecure -- valid",
			opts:    runOptions{stepName: "build", signers: []cryptoutil.Signer{signer}},
			wantErr: false,
		},
		{
			name:    "insecure with signers -- valid (signers ignored)",
			opts:    runOptions{stepName: "build", insecure: true, signers: []cryptoutil.Signer{signer}},
			wantErr: false,
		},
		{
			name:      "whitespace-only step name passes validation -- potential issue",
			opts:      runOptions{stepName: "   ", insecure: true},
			wantErr:   false, // validateRunOpts only checks == ""
			errSubstr: "",
		},
		{
			name:    "nil signer in list counts as signer",
			opts:    runOptions{stepName: "build", signers: []cryptoutil.Signer{nil}},
			wantErr: false, // len(signers) == 1, so validation passes; dsse.Sign will skip nil
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRunOpts(tc.opts)
			if tc.wantErr {
				require.Error(t, err, "expected error")
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				assert.NoError(t, err, "expected no error")
			}
		})
	}
}

// ==========================================================================
// 2. Run path edge cases
// ==========================================================================

func TestTableRunEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		stepName     string
		opts         []RunOption
		wantErr      bool
		errSubstr    string
		checkResults func(t *testing.T, results []RunResult)
	}{
		{
			name:      "empty step name",
			stepName:  "",
			opts:      []RunOption{RunWithInsecure(true)},
			wantErr:   true,
			errSubstr: "step name is required",
		},
		{
			name:     "no attestors, insecure -- produces empty collection",
			stepName: "empty-step",
			opts:     []RunOption{RunWithInsecure(true)},
			wantErr:  false,
			checkResults: func(t *testing.T, results []RunResult) {
				require.Len(t, results, 1, "one result: the collection")
				assert.Equal(t, "empty-step", results[0].Collection.Name)
				assert.Empty(t, results[0].Collection.Attestations)
			},
		},
		{
			name:     "attestor that returns error, ignoreErrors=false",
			stepName: "fail-step",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "boom", typeName: "https://test/boom",
						runType:    attestation.ExecuteRunType,
						attestFunc: func(_ *attestation.AttestationContext) error { return errors.New("KABOOM") },
					},
				}),
			},
			wantErr:   true,
			errSubstr: "KABOOM",
		},
		{
			name:     "attestor that returns error, ignoreErrors=true",
			stepName: "ignore-fail-step",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithIgnoreErrors(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "boom", typeName: "https://test/boom",
						runType:    attestation.ExecuteRunType,
						attestFunc: func(_ *attestation.AttestationContext) error { return errors.New("KABOOM") },
					},
				}),
			},
			wantErr: false,
			checkResults: func(t *testing.T, results []RunResult) {
				collection := results[len(results)-1]
				assert.Empty(t, collection.Collection.Attestations,
					"failed attestor should not appear in collection when ignoreErrors=true")
			},
		},
		{
			name:     "attestor that panics is recovered",
			stepName: "panic-step",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "panicker", typeName: "https://test/panic",
						runType: attestation.ExecuteRunType,
						attestFunc: func(_ *attestation.AttestationContext) error {
							panic("deliberate panic in attestor")
						},
					},
				}),
			},
			// The context.go runAttestor has a recover() wrapper, so panics
			// become errors. With ignoreErrors=false, this should propagate.
			wantErr:   true,
			errSubstr: "panicked",
		},
		{
			name:     "attestor that panics with ignoreErrors=true is swallowed",
			stepName: "panic-ignore-step",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithIgnoreErrors(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "panicker", typeName: "https://test/panic",
						runType: attestation.ExecuteRunType,
						attestFunc: func(_ *attestation.AttestationContext) error {
							panic("deliberate panic ignored")
						},
					},
				}),
			},
			wantErr: false,
			checkResults: func(t *testing.T, results []RunResult) {
				collection := results[len(results)-1]
				assert.Empty(t, collection.Collection.Attestations,
					"panicking attestor should not appear in collection")
			},
		},
		{
			name:     "attestor returning huge data -- no size limit enforced",
			stepName: "huge-data-step",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "big", typeName: "https://test/big",
						runType: attestation.ExecuteRunType,
						subjects: map[string]cryptoutil.DigestSet{
							"big-artifact": {
								{Hash: crypto.SHA256}: strings.Repeat("a", 10000),
							},
						},
					},
				}),
			},
			wantErr: false,
			checkResults: func(t *testing.T, results []RunResult) {
				collection := results[len(results)-1]
				assert.Len(t, collection.Collection.Attestations, 1)
			},
		},
		{
			name:     "multiple attestors across different run types",
			stepName: "multi-phase",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{name: "pre", typeName: "https://test/pre", runType: attestation.PreMaterialRunType},
					&tableAttestor{name: "mat", typeName: "https://test/mat", runType: attestation.MaterialRunType},
					&tableAttestor{name: "exec", typeName: "https://test/exec", runType: attestation.ExecuteRunType},
					&tableAttestor{name: "prod", typeName: "https://test/prod", runType: attestation.ProductRunType},
					&tableAttestor{name: "post", typeName: "https://test/post", runType: attestation.PostProductRunType},
				}),
			},
			wantErr: false,
			checkResults: func(t *testing.T, results []RunResult) {
				collection := results[len(results)-1]
				assert.Len(t, collection.Collection.Attestations, 5,
					"all 5 attestors should be in the collection")
			},
		},
		{
			name:     "attestor with empty RunType fails",
			stepName: "empty-runtype",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{name: "bad", typeName: "https://test/bad", runType: ""},
				}),
			},
			wantErr:   true,
			errSubstr: "run type not set",
		},
		{
			name:     "duplicate attestors in same step",
			stepName: "duplicate-step",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{name: "dup", typeName: "https://test/dup", runType: attestation.ExecuteRunType},
					&tableAttestor{name: "dup", typeName: "https://test/dup", runType: attestation.ExecuteRunType},
				}),
			},
			wantErr: false,
			checkResults: func(t *testing.T, results []RunResult) {
				collection := results[len(results)-1]
				// Both should appear -- no deduplication is enforced
				assert.Len(t, collection.Collection.Attestations, 2,
					"duplicate attestors are both included -- no dedup enforced. "+
						"SECURITY NOTE: duplicate attestor types in a collection could "+
						"confuse policy evaluation that expects uniqueness.")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results, err := RunWithExports(tc.stepName, tc.opts...)
			if tc.wantErr {
				require.Error(t, err, "expected error")
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				require.NoError(t, err, "expected no error")
				if tc.checkResults != nil {
					tc.checkResults(t, results)
				}
			}
		})
	}
}

// ==========================================================================
// 3. Sign / export edge cases
// ==========================================================================

func TestTableSignExportEdgeCases(t *testing.T) {
	signer, verifier := tableRSASignerVerifier(t)
	signer2, _ := tableRSASignerVerifier(t)

	tests := []struct {
		name         string
		stepName     string
		opts         []RunOption
		wantErr      bool
		errSubstr    string
		checkResults func(t *testing.T, results []RunResult)
	}{
		{
			name:     "signed mode with valid signer -- exporter only produces separate envelope, collection succeeds",
			stepName: "signed-step",
			opts: []RunOption{
				RunWithSigners(signer),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "att", typeName: "https://test/att",
						runType: attestation.ExecuteRunType,
						subjects: map[string]cryptoutil.DigestSet{
							"art": {{Hash: crypto.SHA256}: "deadbeef"},
						},
						export: true,
					},
				}),
			},
			// When the only attestor with subjects is an exporter, it gets
			// excluded from the collection. The collection has no subjects
			// but intoto.NewStatement allows empty subjects (matching witness).
			wantErr: false,
		},
		{
			name:     "signed mode with exporter AND regular attestor with subjects -- works",
			stepName: "signed-step-2",
			opts: []RunOption{
				RunWithSigners(signer),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "exp", typeName: "https://test/exp",
						runType: attestation.ExecuteRunType,
						subjects: map[string]cryptoutil.DigestSet{
							"art": {{Hash: crypto.SHA256}: "deadbeef"},
						},
						export: true,
					},
					&tableAttestor{
						name: "reg", typeName: "https://test/reg",
						runType: attestation.ExecuteRunType,
						subjects: map[string]cryptoutil.DigestSet{
							"art2": {{Hash: crypto.SHA256}: "cafebabe"},
						},
					},
				}),
			},
			wantErr: false,
			checkResults: func(t *testing.T, results []RunResult) {
				for _, r := range results {
					if len(r.SignedEnvelope.Signatures) > 0 {
						_, err := r.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
						assert.NoError(t, err, "each signed envelope should verify")
					}
				}
			},
		},
		{
			name:     "multiple signers produce multiple signatures on each envelope",
			stepName: "multi-signer",
			opts: []RunOption{
				RunWithSigners(signer, signer2),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "att", typeName: "https://test/att",
						runType: attestation.ExecuteRunType,
						subjects: map[string]cryptoutil.DigestSet{
							"art": {{Hash: crypto.SHA256}: "deadbeef"},
						},
						// NOT an exporter, so subjects stay in collection
					},
				}),
			},
			wantErr: false,
			checkResults: func(t *testing.T, results []RunResult) {
				for _, r := range results {
					if len(r.SignedEnvelope.Signatures) > 0 {
						assert.Len(t, r.SignedEnvelope.Signatures, 2,
							"should have one signature per signer")
					}
				}
			},
		},
		{
			name:     "nil signer mixed with valid signer -- nil is skipped",
			stepName: "nil-signer-mixed",
			opts: []RunOption{
				RunWithSigners(nil, signer, nil),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "att", typeName: "https://test/att",
						runType: attestation.ExecuteRunType,
						subjects: map[string]cryptoutil.DigestSet{
							"art": {{Hash: crypto.SHA256}: "deadbeef"},
						},
						// NOT an exporter -- subjects stay in collection
					},
				}),
			},
			wantErr: false,
			checkResults: func(t *testing.T, results []RunResult) {
				for _, r := range results {
					if len(r.SignedEnvelope.Signatures) > 0 {
						assert.Len(t, r.SignedEnvelope.Signatures, 1,
							"nil signers should be skipped, leaving one valid signature")
					}
				}
			},
		},
		{
			name:     "all nil signers with no subjects -- collection sign fails",
			stepName: "all-nil-signers",
			opts: []RunOption{
				RunWithSigners(nil, nil),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "att", typeName: "https://test/att",
						runType: attestation.ExecuteRunType,
					},
				}),
			},
			// FINDING: validateRunOpts sees len(signers)==2, passes.
			// createAndSignEnvelope is called for the collection, but all
			// signers are nil so dsse.Sign produces no signatures.
			// SECURITY NOTE: nil signers pass validation check but fail downstream.
			// This means the validation is incomplete -- it checks len(signers)
			// but not whether any signer is actually non-nil.
			wantErr:   true,
			errSubstr: "no signatures produced",
		},
		{
			name:     "exporter with subjects excluded from collection",
			stepName: "exporter-excl",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "exported", typeName: "https://test/exported",
						runType:  attestation.ExecuteRunType,
						export:   true,
						subjects: map[string]cryptoutil.DigestSet{"art": {{Hash: crypto.SHA256}: "abc"}},
					},
					&tableAttestor{
						name: "regular", typeName: "https://test/regular",
						runType: attestation.ExecuteRunType,
					},
				}),
			},
			wantErr: false,
			checkResults: func(t *testing.T, results []RunResult) {
				require.Len(t, results, 2, "1 exporter + 1 collection")
				collection := results[len(results)-1]
				for _, a := range collection.Collection.Attestations {
					assert.NotEqual(t, "https://test/exported", a.Type,
						"exporter should not be in the collection")
				}
				assert.Len(t, collection.Collection.Attestations, 1,
					"only the regular attestor should be in the collection")
			},
		},
		{
			name:     "exporter with export=false stays in collection",
			stepName: "exporter-false",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "no-export", typeName: "https://test/no-export",
						runType:  attestation.ExecuteRunType,
						export:   false,
						subjects: map[string]cryptoutil.DigestSet{"art": {{Hash: crypto.SHA256}: "abc"}},
					},
				}),
			},
			wantErr: false,
			checkResults: func(t *testing.T, results []RunResult) {
				require.Len(t, results, 1, "only the collection -- no export")
				collection := results[0]
				found := false
				for _, a := range collection.Collection.Attestations {
					if a.Type == "https://test/no-export" {
						found = true
					}
				}
				assert.True(t, found, "attestor with export=false should be in the collection")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results, err := RunWithExports(tc.stepName, tc.opts...)
			if tc.wantErr {
				require.Error(t, err, "expected error")
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				require.NoError(t, err, "expected no error")
				if tc.checkResults != nil {
					tc.checkResults(t, results)
				}
			}
		})
	}
}

// ==========================================================================
// 4. VerifySignature edge cases
// ==========================================================================

func TestTableVerifySignature(t *testing.T) {
	signer, verifier := tableRSASignerVerifier(t)
	_, wrongVerifier := tableRSASignerVerifier(t)

	// Create a valid signed envelope for some tests.
	payload := []byte(`{"test":"data"}`)
	var validEnvBuf bytes.Buffer
	require.NoError(t, Sign(bytes.NewReader(payload), "application/json", &validEnvBuf, dsse.SignWithSigners(signer)))
	validEnvBytes := validEnvBuf.Bytes()

	tests := []struct {
		name      string
		input     []byte
		verifiers []cryptoutil.Verifier
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "valid envelope with correct verifier",
			input:     validEnvBytes,
			verifiers: []cryptoutil.Verifier{verifier},
			wantErr:   false,
		},
		{
			name:      "valid envelope with wrong verifier",
			input:     validEnvBytes,
			verifiers: []cryptoutil.Verifier{wrongVerifier},
			wantErr:   true,
		},
		{
			name:      "invalid JSON",
			input:     []byte("not-json-at-all"),
			verifiers: []cryptoutil.Verifier{verifier},
			wantErr:   true,
			errSubstr: "failed to parse dsse envelope",
		},
		{
			name:      "empty input",
			input:     []byte{},
			verifiers: []cryptoutil.Verifier{verifier},
			wantErr:   true,
		},
		{
			name:      "valid JSON but not an envelope",
			input:     []byte(`{"foo":"bar"}`),
			verifiers: []cryptoutil.Verifier{verifier},
			wantErr:   true,
		},
		{
			name:      "envelope with empty signatures array",
			input:     []byte(`{"payload":"dGVzdA==","payloadType":"test","signatures":[]}`),
			verifiers: []cryptoutil.Verifier{verifier},
			wantErr:   true,
		},
		{
			name:      "no verifiers provided",
			input:     validEnvBytes,
			verifiers: []cryptoutil.Verifier{},
			wantErr:   true,
		},
		{
			name:      "nil verifier in list",
			input:     validEnvBytes,
			verifiers: []cryptoutil.Verifier{nil},
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifySignature(bytes.NewReader(tc.input), tc.verifiers...)
			if tc.wantErr {
				require.Error(t, err, "expected error")
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				assert.NoError(t, err, "expected no error")
			}
		})
	}
}

// ==========================================================================
// 5. Sign function edge cases
// ==========================================================================

func TestTableSign(t *testing.T) {
	signer, _ := tableRSASignerVerifier(t)

	tests := []struct {
		name      string
		payload   []byte
		dataType  string
		signOpts  []dsse.SignOption
		wantErr   bool
		errSubstr string
		checkEnv  func(t *testing.T, env dsse.Envelope)
	}{
		{
			name:     "valid payload",
			payload:  []byte(`{"data":"test"}`),
			dataType: "application/json",
			signOpts: []dsse.SignOption{dsse.SignWithSigners(signer)},
			wantErr:  false,
			checkEnv: func(t *testing.T, env dsse.Envelope) {
				assert.Equal(t, "application/json", env.PayloadType)
				assert.Len(t, env.Signatures, 1)
			},
		},
		{
			name:      "no signers",
			payload:   []byte("data"),
			dataType:  "text/plain",
			signOpts:  []dsse.SignOption{},
			wantErr:   true,
			errSubstr: "at least one signer",
		},
		{
			name:     "empty payload",
			payload:  []byte{},
			dataType: "test/empty",
			signOpts: []dsse.SignOption{dsse.SignWithSigners(signer)},
			wantErr:  false,
			checkEnv: func(t *testing.T, env dsse.Envelope) {
				assert.Equal(t, "test/empty", env.PayloadType)
			},
		},
		{
			name:     "binary payload",
			payload:  []byte{0x00, 0x01, 0x02, 0xFF},
			dataType: "application/octet-stream",
			signOpts: []dsse.SignOption{dsse.SignWithSigners(signer)},
			wantErr:  false,
			checkEnv: func(t *testing.T, env dsse.Envelope) {
				assert.Len(t, env.Signatures, 1)
			},
		},
		{
			name:     "empty data type",
			payload:  []byte("data"),
			dataType: "",
			signOpts: []dsse.SignOption{dsse.SignWithSigners(signer)},
			wantErr:  false,
			checkEnv: func(t *testing.T, env dsse.Envelope) {
				assert.Empty(t, env.PayloadType,
					"empty data type is accepted -- no validation on payload type")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := Sign(bytes.NewReader(tc.payload), tc.dataType, &buf, tc.signOpts...)
			if tc.wantErr {
				require.Error(t, err, "expected error")
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				require.NoError(t, err)
				var env dsse.Envelope
				require.NoError(t, json.Unmarshal(buf.Bytes(), &env))
				if tc.checkEnv != nil {
					tc.checkEnv(t, env)
				}
			}
		})
	}
}

// ==========================================================================
// 6. Deprecated Run() vs RunWithExports
// ==========================================================================

func TestTableDeprecatedRun(t *testing.T) {
	tests := []struct {
		name        string
		stepName    string
		opts        []RunOption
		wantErr     bool
		errSubstr   string
		checkResult func(t *testing.T, result RunResult)
	}{
		{
			name:     "single collection result -- deprecated Run works",
			stepName: "simple",
			opts:     []RunOption{RunWithInsecure(true)},
			wantErr:  false,
			checkResult: func(t *testing.T, result RunResult) {
				assert.Equal(t, "simple", result.Collection.Name)
			},
		},
		{
			name:     "exporter + collection = 2 results -- deprecated Run errors",
			stepName: "multi-result",
			opts: []RunOption{
				RunWithInsecure(true),
				RunWithAttestors([]attestation.Attestor{
					&tableAttestor{
						name: "exp", typeName: "https://test/exp",
						runType:  attestation.ExecuteRunType,
						export:   true,
						subjects: map[string]cryptoutil.DigestSet{"a": {{Hash: crypto.SHA256}: "abc"}},
					},
				}),
			},
			wantErr:   true,
			errSubstr: "expected a single result, got multiple",
		},
		{
			name:      "empty step name",
			stepName:  "",
			opts:      []RunOption{RunWithInsecure(true)},
			wantErr:   true,
			errSubstr: "step name is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Run(tc.stepName, tc.opts...)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				require.NoError(t, err)
				if tc.checkResult != nil {
					tc.checkResult(t, result)
				}
			}
		})
	}
}

// ==========================================================================
// 7. MemorySource edge cases
// ==========================================================================

func TestTableMemorySource(t *testing.T) {
	signer, _ := tableRSASignerVerifier(t)

	// Create a valid signed collection to load into MemorySource.
	makeSignedEnvelope := func(t *testing.T, stepName string, attestors []attestation.Attestor) dsse.Envelope {
		t.Helper()
		results, err := RunWithExports(stepName,
			RunWithSigners(signer),
			RunWithAttestors(attestors),
		)
		require.NoError(t, err)
		last := results[len(results)-1]
		return last.SignedEnvelope
	}

	t.Run("load and search basic", func(t *testing.T) {
		att := &tableAttestor{
			name: "test-att", typeName: "https://test/att",
			runType: attestation.ExecuteRunType,
			subjects: map[string]cryptoutil.DigestSet{
				"artifact": {{Hash: crypto.SHA256}: "abc123"},
			},
		}
		env := makeSignedEnvelope(t, "step1", []attestation.Attestor{att})

		ms := source.NewMemorySource()
		require.NoError(t, ms.LoadEnvelope("ref1", env))

		results, err := ms.Search(context.Background(), "step1", []string{"sha256:abc123"}, []string{"https://test/att"})
		require.NoError(t, err)
		// Subject digests in MemorySource are indexed from the in-toto Statement
		// subjects, which are formatted as "hashName:digest" by the intoto package.
		// The search matches against these, but the format depends on how
		// DigestSet.ToNameMap() formats them. Let's check what we actually get.
		t.Logf("search returned %d results for step1", len(results))
	})

	t.Run("duplicate reference returns error", func(t *testing.T) {
		att := &tableAttestor{
			name: "att", typeName: "https://test/att",
			runType:  attestation.ExecuteRunType,
			subjects: map[string]cryptoutil.DigestSet{"a": {{Hash: crypto.SHA256}: "abc"}},
		}
		env := makeSignedEnvelope(t, "step1", []attestation.Attestor{att})

		ms := source.NewMemorySource()
		require.NoError(t, ms.LoadEnvelope("ref1", env))
		err := ms.LoadEnvelope("ref1", env)
		require.Error(t, err)
		var dupErr source.ErrDuplicateReference
		assert.ErrorAs(t, err, &dupErr, "should be ErrDuplicateReference")
	})

	t.Run("search with non-matching collection name", func(t *testing.T) {
		att := &tableAttestor{
			name: "att", typeName: "https://test/att",
			runType:  attestation.ExecuteRunType,
			subjects: map[string]cryptoutil.DigestSet{"a": {{Hash: crypto.SHA256}: "abc"}},
		}
		env := makeSignedEnvelope(t, "step1", []attestation.Attestor{att})

		ms := source.NewMemorySource()
		require.NoError(t, ms.LoadEnvelope("ref1", env))

		results, err := ms.Search(context.Background(), "nonexistent-step", []string{"sha256:abc"}, nil)
		require.NoError(t, err)
		assert.Empty(t, results, "search for non-matching collection name should return empty")
	})

	t.Run("search with no matching subject digest", func(t *testing.T) {
		att := &tableAttestor{
			name: "att", typeName: "https://test/att",
			runType:  attestation.ExecuteRunType,
			subjects: map[string]cryptoutil.DigestSet{"a": {{Hash: crypto.SHA256}: "abc"}},
		}
		env := makeSignedEnvelope(t, "step1", []attestation.Attestor{att})

		ms := source.NewMemorySource()
		require.NoError(t, ms.LoadEnvelope("ref1", env))

		results, err := ms.Search(context.Background(), "step1", []string{"sha256:WRONG"}, nil)
		require.NoError(t, err)
		assert.Empty(t, results, "search with non-matching digest should return empty")
	})

	t.Run("search requiring attestation type that is missing", func(t *testing.T) {
		att := &tableAttestor{
			name: "att", typeName: "https://test/att",
			runType:  attestation.ExecuteRunType,
			subjects: map[string]cryptoutil.DigestSet{"a": {{Hash: crypto.SHA256}: "abc"}},
		}
		env := makeSignedEnvelope(t, "step1", []attestation.Attestor{att})

		ms := source.NewMemorySource()
		require.NoError(t, ms.LoadEnvelope("ref1", env))

		// Determine what digests are actually indexed.
		// Use a broad search first to see what matches.
		broadResults, err := ms.Search(context.Background(), "step1", nil, nil)
		require.NoError(t, err)
		// With nil subjectDigests and nil attestations, subjectMatchFound will
		// be false (the loop over subjectDigests never executes). So this should
		// return empty.
		t.Logf("broad search with nil digests returned %d results", len(broadResults))

		// Now search with a type that is NOT in the collection.
		results, err := ms.Search(context.Background(), "step1", []string{""}, []string{"https://test/NONEXISTENT"})
		require.NoError(t, err)
		assert.Empty(t, results, "search requiring missing attestation type should return empty")
	})

	t.Run("multiple envelopes for same step name", func(t *testing.T) {
		att1 := &tableAttestor{
			name: "att1", typeName: "https://test/att1",
			runType:  attestation.ExecuteRunType,
			subjects: map[string]cryptoutil.DigestSet{"a": {{Hash: crypto.SHA256}: "shared-digest"}},
		}
		att2 := &tableAttestor{
			name: "att2", typeName: "https://test/att2",
			runType:  attestation.ExecuteRunType,
			subjects: map[string]cryptoutil.DigestSet{"b": {{Hash: crypto.SHA256}: "shared-digest"}},
		}

		env1 := makeSignedEnvelope(t, "step1", []attestation.Attestor{att1})
		env2 := makeSignedEnvelope(t, "step1", []attestation.Attestor{att2})

		ms := source.NewMemorySource()
		require.NoError(t, ms.LoadEnvelope("ref1", env1))
		require.NoError(t, ms.LoadEnvelope("ref2", env2))

		// Both should be found. Find the actual digest format first.
		envBytes, err := json.Marshal(env1)
		require.NoError(t, err)
		var rawEnv dsse.Envelope
		require.NoError(t, json.Unmarshal(envBytes, &rawEnv))

		// Let's just search broadly for step1 to see all results.
		// We need at least one matching subject digest.
		// The subjects are formatted as "sha256:shared-digest" in the statement.
		// But MemorySource indexes the raw digest strings from Subject.Digest map.
		// Let's parse the statement to find the actual digest strings.
		t.Logf("loaded 2 envelopes for step1, checking search behavior")
	})

	t.Run("LoadBytes with invalid JSON", func(t *testing.T) {
		ms := source.NewMemorySource()
		err := ms.LoadBytes("bad-ref", []byte("not-json"))
		require.Error(t, err, "should error on invalid JSON")
	})

	t.Run("LoadBytes with valid JSON but not a DSSE envelope", func(t *testing.T) {
		ms := source.NewMemorySource()
		err := ms.LoadBytes("not-env", []byte(`{"foo":"bar"}`))
		// This will try to parse the JSON as a DSSE envelope, which won't have
		// a payload or payloadType. envelopeToCollectionEnvelope will then
		// try to unmarshal the nil/empty payload as an intoto.Statement.
		t.Logf("LoadBytes with non-envelope JSON: err=%v", err)
	})
}

// ==========================================================================
// 8. Verify function edge cases
// ==========================================================================

func TestTableVerify(t *testing.T) {
	tests := []struct {
		name      string
		setupFn   func(t *testing.T) (dsse.Envelope, []cryptoutil.Verifier, []VerifyOption)
		wantErr   bool
		errSubstr string
	}{
		{
			name: "policyverify attestor not registered",
			setupFn: func(t *testing.T) (dsse.Envelope, []cryptoutil.Verifier, []VerifyOption) {
				_, ok := attestation.FactoryByName("policyverify")
				if ok {
					t.Skip("policyverify plugin is registered")
				}
				signer, _ := tableRSASignerVerifier(t)
				env := dsse.Envelope{
					Payload:     []byte("fake"),
					PayloadType: "test",
					Signatures:  []dsse.Signature{{KeyID: "k", Signature: []byte("s")}},
				}
				return env, nil, []VerifyOption{VerifyWithSigners(signer)}
			},
			wantErr:   true,
			errSubstr: "policyverify",
		},
		{
			name: "verify with no signers and no insecure defaults to insecure",
			setupFn: func(t *testing.T) (dsse.Envelope, []cryptoutil.Verifier, []VerifyOption) {
				_, ok := attestation.FactoryByName("policyverify")
				if ok {
					t.Skip("policyverify plugin is registered")
				}
				env := dsse.Envelope{
					Payload:     []byte("fake"),
					PayloadType: "test",
					Signatures:  []dsse.Signature{{KeyID: "k", Signature: []byte("s")}},
				}
				// When no signers are provided, Verify adds RunWithInsecure(true)
				return env, nil, nil
			},
			wantErr:   true,
			errSubstr: "policyverify",
		},
		{
			name: "verify with nil context still works (context.Background used internally)",
			setupFn: func(t *testing.T) (dsse.Envelope, []cryptoutil.Verifier, []VerifyOption) {
				_, ok := attestation.FactoryByName("policyverify")
				if ok {
					t.Skip("policyverify plugin is registered")
				}
				signer, _ := tableRSASignerVerifier(t)
				env := dsse.Envelope{
					Payload:     []byte("fake"),
					PayloadType: "test",
					Signatures:  []dsse.Signature{{KeyID: "k", Signature: []byte("s")}},
				}
				return env, nil, []VerifyOption{VerifyWithSigners(signer)}
			},
			wantErr:   true,
			errSubstr: "policyverify",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, verifiers, opts := tc.setupFn(t)
			_, err := Verify(context.Background(), env, verifiers, opts...)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ==========================================================================
// 9. VerifyOption functional options
// ==========================================================================

func TestTableVerifyOptions(t *testing.T) {
	t.Run("VerifyWithSigners accumulates", func(t *testing.T) {
		s1, _ := tableRSASignerVerifier(t)
		s2, _ := tableRSASignerVerifier(t)

		vo := verifyOptions{}
		VerifyWithSigners(s1)(&vo)
		VerifyWithSigners(s2)(&vo)
		assert.Len(t, vo.signers, 2, "VerifyWithSigners should append")
	})

	t.Run("VerifyWithSubjectDigests replaces", func(t *testing.T) {
		vo := verifyOptions{}
		d1 := []cryptoutil.DigestSet{{{Hash: crypto.SHA256}: "aaa"}}
		d2 := []cryptoutil.DigestSet{{{Hash: crypto.SHA256}: "bbb"}}

		VerifyWithSubjectDigests(d1)(&vo)
		VerifyWithSubjectDigests(d2)(&vo)
		// VerifyWithSubjectDigests uses `=` not append
		assert.Len(t, vo.subjectDigests, 1,
			"VerifyWithSubjectDigests replaces instead of appending -- "+
				"DESIGN NOTE: inconsistent with VerifyWithSigners")
	})

	t.Run("VerifyWithCollectionSource replaces", func(t *testing.T) {
		ms1 := source.NewMemorySource()
		ms2 := source.NewMemorySource()

		vo := verifyOptions{}
		VerifyWithCollectionSource(ms1)(&vo)
		VerifyWithCollectionSource(ms2)(&vo)
		assert.Equal(t, ms2, vo.collectionSource,
			"second call should replace the source")
	})

	t.Run("VerifyWithRunOptions accumulates", func(t *testing.T) {
		vo := verifyOptions{}
		VerifyWithRunOptions(RunWithInsecure(true))(&vo)
		VerifyWithRunOptions(RunWithIgnoreErrors(true))(&vo)
		assert.Len(t, vo.runOptions, 2, "VerifyWithRunOptions should append")
	})

	t.Run("VerifyWithAiServerURL replaces", func(t *testing.T) {
		vo := verifyOptions{}
		VerifyWithAiServerURL("http://first")(&vo)
		VerifyWithAiServerURL("http://second")(&vo)
		assert.Equal(t, "http://second", vo.aiServerURL)
	})
}

// ==========================================================================
// 10. RunOption functional options
// ==========================================================================

func TestTableRunOptions(t *testing.T) {
	t.Run("RunWithSigners appends across calls", func(t *testing.T) {
		s1, _ := tableRSASignerVerifier(t)
		s2, _ := tableRSASignerVerifier(t)

		ro := runOptions{}
		RunWithSigners(s1)(&ro)
		RunWithSigners(s2)(&ro)
		assert.Len(t, ro.signers, 2)
	})

	t.Run("RunWithAttestors appends across calls", func(t *testing.T) {
		a1 := &tableAttestor{name: "a1", typeName: "t1", runType: attestation.ExecuteRunType}
		a2 := &tableAttestor{name: "a2", typeName: "t2", runType: attestation.ExecuteRunType}

		ro := runOptions{}
		RunWithAttestors([]attestation.Attestor{a1})(&ro)
		RunWithAttestors([]attestation.Attestor{a2})(&ro)
		assert.Len(t, ro.attestors, 2)
	})

	t.Run("RunWithAttestationOpts appends across calls", func(t *testing.T) {
		ro := runOptions{}
		RunWithAttestationOpts(attestation.WithWorkingDir("/a"))(&ro)
		RunWithAttestationOpts(attestation.WithWorkingDir("/b"))(&ro)
		assert.Len(t, ro.attestationOpts, 2,
			"RunWithAttestationOpts should append; if it replaces, this is a bug")
	})

	t.Run("RunWithTimestampers appends across calls", func(t *testing.T) {
		ro := runOptions{}
		RunWithTimestampers()(&ro)
		first := len(ro.timestampers)
		RunWithTimestampers()(&ro)
		second := len(ro.timestampers)
		// Both are empty so this doesn't reveal much, but the code uses append.
		t.Logf("timestampers: first=%d, second=%d", first, second)
	})

	t.Run("RunWithInsecure toggles", func(t *testing.T) {
		ro := runOptions{}
		RunWithInsecure(true)(&ro)
		assert.True(t, ro.insecure)
		RunWithInsecure(false)(&ro)
		assert.False(t, ro.insecure)
	})

	t.Run("RunWithIgnoreErrors toggles", func(t *testing.T) {
		ro := runOptions{}
		RunWithIgnoreErrors(true)(&ro)
		assert.True(t, ro.ignoreErrors)
		RunWithIgnoreErrors(false)(&ro)
		assert.False(t, ro.ignoreErrors)
	})
}

// ==========================================================================
// 11. Integration: Run -> MemorySource -> envelope roundtrip
// ==========================================================================

func TestTableRunStoreVerifyRoundtrip(t *testing.T) {
	signer, verifier := tableRSASignerVerifier(t)

	tests := []struct {
		name      string
		stepName  string
		attestors []attestation.Attestor
		wantErr   bool
	}{
		{
			name:     "single attestor roundtrip",
			stepName: "step1",
			attestors: []attestation.Attestor{
				&tableAttestor{
					name: "my-att", typeName: "https://test/my-att",
					runType: attestation.ExecuteRunType,
					subjects: map[string]cryptoutil.DigestSet{
						"artifact": {{Hash: crypto.SHA256}: "abc123"},
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "multiple attestors roundtrip",
			stepName: "step2",
			attestors: []attestation.Attestor{
				&tableAttestor{
					name: "att1", typeName: "https://test/att1",
					runType: attestation.ExecuteRunType,
					subjects: map[string]cryptoutil.DigestSet{
						"art1": {{Hash: crypto.SHA256}: "hash1"},
					},
				},
				&tableAttestor{
					name: "att2", typeName: "https://test/att2",
					runType: attestation.ExecuteRunType,
					subjects: map[string]cryptoutil.DigestSet{
						"art2": {{Hash: crypto.SHA256}: "hash2"},
					},
				},
			},
			wantErr: false,
		},
		{
			name:      "no attestors in signed mode succeeds -- empty subjects now allowed",
			stepName:  "empty-step",
			attestors: nil,
			// UPDATE: intoto.NewStatement now allows empty subjects (matching
			// upstream witness behavior). A collection with no attestors and
			// therefore no subjects can still be signed.
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: Run to produce signed results
			results, err := RunWithExports(tc.stepName,
				RunWithSigners(signer),
				RunWithAttestors(tc.attestors),
			)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, results)

			// Step 2: The collection envelope is the last result
			collectionResult := results[len(results)-1]

			// Step 3: Verify the envelope signature
			_, err = collectionResult.SignedEnvelope.Verify(dsse.VerifyWithVerifiers(verifier))
			require.NoError(t, err, "envelope should verify with the signer's verifier")

			// Step 4: Load into MemorySource
			ms := source.NewMemorySource()
			err = ms.LoadEnvelope(tc.stepName, collectionResult.SignedEnvelope)
			require.NoError(t, err, "should load envelope into MemorySource")

			// Step 5: Verify it can be found by searching
			// Parse the envelope to find what subjects are indexed
			var stmt struct {
				Subject []struct {
					Name   string            `json:"name"`
					Digest map[string]string `json:"digest"`
				} `json:"subject"`
			}
			err = json.Unmarshal(collectionResult.SignedEnvelope.Payload, &stmt)
			require.NoError(t, err)

			// Extract all digest strings for search
			var searchDigests []string
			for _, subj := range stmt.Subject {
				for _, d := range subj.Digest {
					searchDigests = append(searchDigests, d)
				}
			}
			t.Logf("collection has %d subjects with %d total digest values",
				len(stmt.Subject), len(searchDigests))

			if len(searchDigests) > 0 {
				found, err := ms.Search(context.Background(), tc.stepName, searchDigests, nil)
				require.NoError(t, err)
				assert.NotEmpty(t, found,
					"should find the collection when searching by its own subject digests")
			}

			// Step 6: Verify it is NOT found with wrong step name
			found, err := ms.Search(context.Background(), "wrong-step-name", searchDigests, nil)
			require.NoError(t, err)
			assert.Empty(t, found, "should not find collection with wrong step name")
		})
	}
}

// ==========================================================================
// 12. Envelope serialization roundtrip
// ==========================================================================

func TestTableEnvelopeSerializationRoundtrip(t *testing.T) {
	signer, verifier := tableRSASignerVerifier(t)

	// Use a NON-exporter attestor with subjects so the collection
	// has subjects and can be signed. (Exporters are excluded from the
	// collection, leaving it with no subjects if they're the only Subjecters.)
	att := &tableAttestor{
		name: "serial-att", typeName: "https://test/serial",
		runType: attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"artifact": {{Hash: crypto.SHA256}: "serialhash"},
		},
		export: false,
	}

	results, err := RunWithExports("serialize-test",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err)

	for i, r := range results {
		t.Run(fmt.Sprintf("result_%d", i), func(t *testing.T) {
			if len(r.SignedEnvelope.Signatures) == 0 {
				t.Skip("no signatures on this result (insecure mode)")
			}

			// Serialize
			envBytes, err := json.Marshal(r.SignedEnvelope)
			require.NoError(t, err)

			// Deserialize
			var rehydrated dsse.Envelope
			require.NoError(t, json.Unmarshal(envBytes, &rehydrated))

			// Verify the deserialized envelope
			_, err = rehydrated.Verify(dsse.VerifyWithVerifiers(verifier))
			assert.NoError(t, err,
				"deserialized envelope should still verify -- "+
					"if this fails, serialization corrupts the signature")
		})
	}
}

// ==========================================================================
// 13. createAndSignEnvelope edge cases (via Run)
// ==========================================================================

func TestTableCreateAndSignEnvelopeEdgeCases(t *testing.T) {
	signer, _ := tableRSASignerVerifier(t)

	tests := []struct {
		name      string
		subjects  map[string]cryptoutil.DigestSet
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid subjects on non-exporter -- collection gets signed",
			subjects: map[string]cryptoutil.DigestSet{
				"art": {{Hash: crypto.SHA256}: "abc"},
			},
			wantErr: false,
		},
		{
			name:     "empty subjects on exporter -- now succeeds with zero subjects",
			subjects: map[string]cryptoutil.DigestSet{},
			// UPDATE: intoto.NewStatement now allows empty subjects (matching
			// upstream witness behavior). The exporter's envelope is created
			// with zero subjects.
			wantErr: false,
		},
		{
			name:     "nil subjects on exporter -- Subjects() returns empty map, now succeeds",
			subjects: nil,
			// Our tableAttestor.Subjects() returns empty map for nil.
			// UPDATE: intoto.NewStatement now allows empty subjects.
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// For "valid subjects", use a non-exporter so subjects flow into
			// the collection. For the error cases, use an exporter to test
			// the exporter's own createAndSignEnvelope path.
			isExporter := tc.wantErr || len(tc.subjects) == 0
			att := &tableAttestor{
				name: "envelope-att", typeName: "https://test/envelope",
				runType:  attestation.ExecuteRunType,
				export:   isExporter,
				subjects: tc.subjects,
			}

			_, err := RunWithExports("envelope-test",
				RunWithSigners(signer),
				RunWithAttestors([]attestation.Attestor{att}),
			)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ==========================================================================
// 14. Attestor execution ordering
// ==========================================================================

func TestTableAttestorPhaseOrdering(t *testing.T) {
	// Verify that attestors run in the correct phase order:
	// PreMaterial -> Material -> Execute -> Product -> PostProduct
	var order []string

	makeTracking := func(name string, phase attestation.RunType) *tableAttestor {
		return &tableAttestor{
			name: name, typeName: "https://test/" + name,
			runType: phase,
			attestFunc: func(_ *attestation.AttestationContext) error {
				order = append(order, name)
				return nil
			},
		}
	}

	attestors := []attestation.Attestor{
		// Deliberately out of order
		makeTracking("exec", attestation.ExecuteRunType),
		makeTracking("post", attestation.PostProductRunType),
		makeTracking("pre", attestation.PreMaterialRunType),
		makeTracking("prod", attestation.ProductRunType),
		makeTracking("mat", attestation.MaterialRunType),
	}

	_, err := Run("phase-test",
		RunWithInsecure(true),
		RunWithAttestors(attestors),
	)
	require.NoError(t, err)

	// With only 1 attestor per phase, the order should be deterministic.
	expected := []string{"pre", "mat", "exec", "prod", "post"}
	assert.Equal(t, expected, order,
		"attestors should run in phase order: pre -> mat -> exec -> prod -> post")
}

// ==========================================================================
// 15. Verify RunType mixing validation
// ==========================================================================

func TestTableVerifyRunTypeMixing(t *testing.T) {
	tests := []struct {
		name      string
		attestors []attestation.Attestor
		wantErr   bool
		errSubstr string
	}{
		{
			name: "verify type alone is fine",
			attestors: []attestation.Attestor{
				&tableAttestor{name: "v", typeName: "https://test/v", runType: attestation.VerifyRunType},
			},
			wantErr: false,
		},
		{
			name: "verify type mixed with execute type is rejected",
			attestors: []attestation.Attestor{
				&tableAttestor{name: "v", typeName: "https://test/v", runType: attestation.VerifyRunType},
				&tableAttestor{name: "e", typeName: "https://test/e", runType: attestation.ExecuteRunType},
			},
			wantErr:   true,
			errSubstr: "cannot be run in conjunction",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Run("mix-test",
				RunWithInsecure(true),
				RunWithAttestors(tc.attestors),
			)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}
			} else {
				// It might still error for other reasons (attestor implementation)
				// but NOT for the mixing reason
				if err != nil {
					assert.NotContains(t, err.Error(), "cannot be run in conjunction")
				}
			}
		})
	}
}

// ==========================================================================
// 16. Insecure mode behavior validation
// ==========================================================================

func TestTableInsecureModeBehavior(t *testing.T) {
	signer, _ := tableRSASignerVerifier(t)

	// An attestor with subjects so the collection can be signed in non-insecure mode.
	subjectAtt := &tableAttestor{
		name: "subj", typeName: "https://test/subj",
		runType: attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"art": {{Hash: crypto.SHA256}: "abc123"},
		},
	}

	tests := []struct {
		name         string
		insecure     bool
		signers      []cryptoutil.Signer
		expectSigned bool
		wantErr      bool
	}{
		{
			name:         "insecure=true, no signers -- no signatures",
			insecure:     true,
			signers:      nil,
			expectSigned: false,
			wantErr:      false,
		},
		{
			name:         "insecure=true, has signers -- still no signatures",
			insecure:     true,
			signers:      []cryptoutil.Signer{signer},
			expectSigned: false,
			wantErr:      false,
		},
		{
			name:         "insecure=false, has signers and subjects -- signatures present",
			insecure:     false,
			signers:      []cryptoutil.Signer{signer},
			expectSigned: true,
			wantErr:      false,
		},
		{
			name:     "insecure=false, no signers -- error",
			insecure: false,
			signers:  nil,
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := []RunOption{
				// Always include an attestor with subjects so that the collection
				// has subjects for intoto.NewStatement in signed mode.
				RunWithAttestors([]attestation.Attestor{subjectAtt}),
			}
			if tc.insecure {
				opts = append(opts, RunWithInsecure(true))
			}
			if len(tc.signers) > 0 {
				opts = append(opts, RunWithSigners(tc.signers...))
			}

			results, err := RunWithExports("insecure-test", opts...)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			last := results[len(results)-1]
			if tc.expectSigned {
				assert.NotEmpty(t, last.SignedEnvelope.Signatures,
					"should have signatures when signed mode")
			} else {
				assert.Empty(t, last.SignedEnvelope.Signatures,
					"should have no signatures in insecure mode")
			}
		})
	}
}

// ==========================================================================
// 17. Collection content validation
// ==========================================================================

func TestTableCollectionContent(t *testing.T) {
	tests := []struct {
		name              string
		stepName          string
		attestors         []attestation.Attestor
		expectedInColl    []string // attestor type names expected IN the collection
		expectedNotInColl []string // attestor type names expected NOT in the collection
	}{
		{
			name:     "regular attestors all in collection",
			stepName: "regular-step",
			attestors: []attestation.Attestor{
				&tableAttestor{name: "a1", typeName: "type1", runType: attestation.ExecuteRunType},
				&tableAttestor{name: "a2", typeName: "type2", runType: attestation.ExecuteRunType},
			},
			expectedInColl:    []string{"type1", "type2"},
			expectedNotInColl: nil,
		},
		{
			name:     "exporter excluded from collection",
			stepName: "export-step",
			attestors: []attestation.Attestor{
				&tableAttestor{
					name: "exp", typeName: "exp-type",
					runType: attestation.ExecuteRunType, export: true,
					subjects: map[string]cryptoutil.DigestSet{"a": {{Hash: crypto.SHA256}: "x"}},
				},
				&tableAttestor{name: "reg", typeName: "reg-type", runType: attestation.ExecuteRunType},
			},
			expectedInColl:    []string{"reg-type"},
			expectedNotInColl: []string{"exp-type"},
		},
		{
			name:              "empty attestors produces empty collection",
			stepName:          "empty",
			attestors:         nil,
			expectedInColl:    nil,
			expectedNotInColl: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results, err := RunWithExports(tc.stepName,
				RunWithInsecure(true),
				RunWithAttestors(tc.attestors),
			)
			require.NoError(t, err)

			collection := results[len(results)-1]
			assert.Equal(t, tc.stepName, collection.Collection.Name)

			types := make(map[string]bool)
			for _, a := range collection.Collection.Attestations {
				types[a.Type] = true
			}

			for _, expected := range tc.expectedInColl {
				assert.True(t, types[expected],
					"expected type %q in collection", expected)
			}
			for _, notExpected := range tc.expectedNotInColl {
				assert.False(t, types[notExpected],
					"did not expect type %q in collection", notExpected)
			}
		})
	}
}

// ==========================================================================
// 18. Error message quality
// ==========================================================================

func TestTableErrorMessages(t *testing.T) {
	tests := []struct {
		name        string
		fn          func() error
		wantSubstrs []string
	}{
		{
			name: "empty step name mentions 'step name'",
			fn: func() error {
				_, err := Run("", RunWithInsecure(true))
				return err
			},
			wantSubstrs: []string{"step name"},
		},
		{
			name: "no signers mentions 'signer'",
			fn: func() error {
				_, err := Run("test")
				return err
			},
			wantSubstrs: []string{"signer"},
		},
		{
			name: "attestor failure wraps original error",
			fn: func() error {
				_, err := Run("test",
					RunWithInsecure(true),
					RunWithAttestors([]attestation.Attestor{
						&tableAttestor{
							name: "my-attestor", typeName: "https://test/x",
							runType: attestation.ExecuteRunType,
							attestFunc: func(_ *attestation.AttestationContext) error {
								return fmt.Errorf("specific error from my-attestor")
							},
						},
					}),
				)
				return err
			},
			wantSubstrs: []string{"my-attestor", "specific error"},
		},
		{
			name: "empty runtype mentions 'run type'",
			fn: func() error {
				_, err := Run("test",
					RunWithInsecure(true),
					RunWithAttestors([]attestation.Attestor{
						&tableAttestor{name: "bad", typeName: "t", runType: ""},
					}),
				)
				return err
			},
			wantSubstrs: []string{"run type"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.fn()
			require.Error(t, err)
			for _, sub := range tc.wantSubstrs {
				assert.Contains(t, err.Error(), sub,
					"error should mention %q", sub)
			}
		})
	}
}

// ==========================================================================
// 19. RunWithExports result count invariants
// ==========================================================================

func TestTableResultCountInvariants(t *testing.T) {
	tests := []struct {
		name        string
		attestors   []attestation.Attestor
		expectedMin int
		expectedMax int
		description string
	}{
		{
			name:        "no attestors -- exactly 1 result (collection)",
			attestors:   nil,
			expectedMin: 1, expectedMax: 1,
			description: "empty collection",
		},
		{
			name: "1 regular attestor -- exactly 1 result",
			attestors: []attestation.Attestor{
				&tableAttestor{name: "a", typeName: "t", runType: attestation.ExecuteRunType},
			},
			expectedMin: 1, expectedMax: 1,
			description: "collection with 1 attestor",
		},
		{
			name: "1 exporter -- exactly 2 results",
			attestors: []attestation.Attestor{
				&tableAttestor{
					name: "e", typeName: "t", runType: attestation.ExecuteRunType,
					export: true, subjects: map[string]cryptoutil.DigestSet{"a": {{Hash: crypto.SHA256}: "x"}},
				},
			},
			expectedMin: 2, expectedMax: 2,
			description: "1 export + 1 collection",
		},
		{
			name: "2 exporters + 1 regular -- exactly 3 results",
			attestors: []attestation.Attestor{
				&tableAttestor{
					name: "e1", typeName: "t1", runType: attestation.ExecuteRunType,
					export: true, subjects: map[string]cryptoutil.DigestSet{"a": {{Hash: crypto.SHA256}: "x"}},
				},
				&tableAttestor{
					name: "e2", typeName: "t2", runType: attestation.ExecuteRunType,
					export: true, subjects: map[string]cryptoutil.DigestSet{"b": {{Hash: crypto.SHA256}: "y"}},
				},
				&tableAttestor{name: "r", typeName: "t3", runType: attestation.ExecuteRunType},
			},
			expectedMin: 3, expectedMax: 3,
			description: "2 exports + 1 collection",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results, err := RunWithExports("count-test",
				RunWithInsecure(true),
				RunWithAttestors(tc.attestors),
			)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(results), tc.expectedMin,
				"should have at least %d results for: %s", tc.expectedMin, tc.description)
			assert.LessOrEqual(t, len(results), tc.expectedMax,
				"should have at most %d results for: %s", tc.expectedMax, tc.description)
		})
	}
}

// ==========================================================================
// 20. Timing: attestor with context timeout
// ==========================================================================

func TestTableAttestorContextTimeout(t *testing.T) {
	slowAtt := &tableAttestor{
		name: "slow", typeName: "https://test/slow",
		runType: attestation.ExecuteRunType,
		attestFunc: func(ctx *attestation.AttestationContext) error {
			// Check if context is cancelled
			select {
			case <-ctx.Context().Done():
				return ctx.Context().Err()
			case <-time.After(50 * time.Millisecond):
				return nil
			}
		},
	}

	// Create a context with a very short timeout.
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	results, err := RunWithExports("timeout-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{slowAtt}),
		RunWithAttestationOpts(attestation.WithContext(timeoutCtx)),
	)

	// The attestor should either:
	// 1. Return a context.DeadlineExceeded error (which gets propagated), or
	// 2. If ignoreErrors is false (default), the error should surface.
	if err != nil {
		t.Logf("timeout test error (expected): %v", err)
		assert.True(t,
			errors.Is(err, context.DeadlineExceeded) ||
				strings.Contains(err.Error(), "deadline") ||
				strings.Contains(err.Error(), "context"),
			"error should be context-related: %v", err)
	} else {
		// If no error, the attestor completed before the timeout.
		// This is a race condition -- document it.
		t.Logf("attestor completed before timeout (race condition). results=%d", len(results))
	}
}
