//go:build integration

// Copyright 2025 The Aflock Authors
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

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestArchivistaIntegration_SearchByPredicateTypeE2E validates the full
// external-attestation pipeline end-to-end against the public
// archivista.testifysec.io instance:
//
//  1. Discover a real SLSA-v1 DSSE and extract one of its subject digests.
//  2. Configure ArchivistaSource → VerifiedSource with a permissive DSSE
//     verification option (we cannot control Sigstore public-good signers
//     deterministically, so signature verification is not asserted here).
//  3. Wrap in a Policy that declares externalAttestations.slsa-prov with
//     required=true and a permissive rego ("accept any buildType") and a
//     wildcard certConstraint.
//  4. Verify against the discovered subject digest and assert the external
//     attestation was found + its statement downloaded + its predicateType
//     matched — the proof that SearchByPredicateType works E2E.
//
// The test is marked integration and skipped when:
//   - ARCHIVISTA_URL is unset AND archivista.testifysec.io is unreachable
//     (CI without internet)
//   - ROOKERY_SKIP_INTEGRATION is set (explicit opt-out)
//
// Run with: go test -tags=integration -count=1 -v ./attestation/policy/...
func TestArchivistaIntegration_SearchByPredicateTypeE2E(t *testing.T) {
	if os.Getenv("ROOKERY_SKIP_INTEGRATION") != "" {
		t.Skip("ROOKERY_SKIP_INTEGRATION set — skipping archivista integration test")
	}

	archivistaURL := os.Getenv("ARCHIVISTA_URL")
	if archivistaURL == "" {
		archivistaURL = "https://archivista.testifysec.io"
	}

	// Sanity check reachability before doing real work. If the test
	// infrastructure is offline we skip rather than fail — the test is
	// environmental, not a regression.
	healthy, healthErr := probeReachable(t, archivistaURL+"/query")
	if !healthy {
		t.Skipf("archivista at %s not reachable (network/flaky): %v", archivistaURL, healthErr)
	}

	// Step 1: discover a subject digest for a real SLSA v1 envelope.
	gitoid, subjectDigest, err := discoverSLSAv1Subject(t, archivistaURL)
	if err != nil {
		t.Skipf("could not discover a real SLSA v1 subject on %s: %v", archivistaURL, err)
	}
	t.Logf("discovered gitoid=%s subject=%s", truncate(gitoid, 12), truncate(subjectDigest, 16))

	// Step 2: build the ArchivistaSource pipeline. Use a fresh source
	// for the direct call so the seenGitoids cache doesn't shadow the
	// subsequent VerifyWithExternals call (which instantiates its own).
	client := archivista.New(archivistaURL)
	rawProbe := source.NewArchivistaSource(client)

	// Step 3: call SearchByPredicateType directly to prove the E2E
	// plumbing works (GraphQL → Download → Statement parse → Attestor
	// factory / RawAttestation fallback).
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	envelopes, err := rawProbe.SearchByPredicateType(ctx, []string{"https://slsa.dev/provenance/v1"}, []string{subjectDigest})
	require.NoError(t, err, "SearchByPredicateType against real archivista must not error")
	require.NotEmpty(t, envelopes, "expected at least one envelope back for the discovered subject digest")

	// At least one envelope must have the correct predicate type and a
	// non-nil Attestor (RawAttestation fallback or typed SLSA v1 factory).
	var matchedEnv source.StatementEnvelope
	found := false
	for _, env := range envelopes {
		if env.Statement.PredicateType == "https://slsa.dev/provenance/v1" {
			matchedEnv = env
			found = true
			break
		}
	}
	require.True(t, found, "at least one envelope should have predicateType=https://slsa.dev/provenance/v1")
	assert.NotNil(t, matchedEnv.Attestor, "envelope must carry an Attestor (typed or RawAttestation fallback)")
	assert.NotEmpty(t, matchedEnv.Reference, "envelope must carry a gitoid reference")

	// Step 4: Attempt a full Policy.VerifyWithExternals with a wildcard
	// CertConstraint. Signature verification against Sigstore public-good
	// Fulcio is non-deterministic for arbitrary SLSA v1 envelopes, so we
	// use a permissive rego and do not assert overall pass. What we DO
	// assert: verifyExternalAttestations runs to completion and reports
	// the envelope in either Passed or Rejected (never silent drop).
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		// Wildcard roots so any Fulcio-issued cert is accepted on the
		// constraint side (signature-level verification is still performed
		// by the DSSE layer, which this test does not gate on).
		Roots: map[string]Root{},
		Steps: map[string]Step{
			// A dummy step is required because Verify() errors on "policy
			// has no steps to verify". The step has no functionaries —
			// this will fail at the step level, which is fine, since we
			// only assert external-attestation behavior here.
			"_no_op": {Name: "_no_op", Functionaries: []Functionary{{CertConstraint: CertConstraint{CommonName: "*", Roots: []string{"*"}}}}},
		},
		ExternalAttestations: map[string]ExternalAttestation{
			"slsa-prov": {
				Name:          "slsa-prov",
				PredicateType: "https://slsa.dev/provenance/v1",
				Required:      false, // optional so we see it attempted even if sig check fails
				Functionaries: []Functionary{
					{CertConstraint: CertConstraint{CommonName: "*", Roots: []string{"*"}}},
				},
				RegoPolicies: []RegoPolicy{
					{Module: []byte("package test\ndeny[msg] { false; msg := \"never\" }"), Name: "accept.rego"},
				},
			},
		},
	}

	// Fresh source for the verify pass so seenGitoids is empty.
	verified := source.NewVerifiedSource(source.NewArchivistaSource(archivista.New(archivistaURL)))
	_, _, extResults, verifyErr := p.VerifyWithExternals(context.Background(),
		WithVerifiedSource(verified),
		WithSubjectDigests([]string{subjectDigest}),
	)

	// The step will fail (no real functionaries). The EXTERNAL must have
	// been evaluated — either Passed or Rejected, not absent.
	require.Contains(t, extResults, "slsa-prov")
	er := extResults["slsa-prov"]
	t.Logf("external slsa-prov: passed=%d rejected=%d skipped=%v",
		len(er.Passed), len(er.Rejected), er.Skipped)
	assert.False(t, er.Skipped, "external should have been evaluated, not skipped (we discovered a real subject)")
	assert.True(t, len(er.Passed)+len(er.Rejected) > 0, "at least one envelope should be recorded in Passed or Rejected")

	// verifyErr is allowed — the step without real functionaries will
	// produce a failure, but the external-attestation path must have run
	// to completion. The presence of er.Passed or er.Rejected already
	// proves that.
	_ = verifyErr
}

// discoverSLSAv1Subject queries archivista for the first SLSA v1 envelope
// and returns its gitoid + one of its subject digests.
func discoverSLSAv1Subject(t *testing.T, archivistaURL string) (gitoid, subjectDigest string, err error) {
	t.Helper()

	query := map[string]string{
		"query": `{
			dsses(first:1, where:{hasStatementWith:{predicateIn:["https://slsa.dev/provenance/v1"]}}) {
				edges { node { gitoidSha256 statement { subjects { edges { node { subjectDigests { value } } } } } } }
			}
		}`,
	}
	body, _ := json.Marshal(query)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, archivistaURL+"/query", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("archivista query: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read body: %w", err)
	}

	var parsed struct {
		Data struct {
			Dsses struct {
				Edges []struct {
					Node struct {
						GitoidSHA256 string `json:"gitoidSha256"`
						Statement    struct {
							Subjects struct {
								Edges []struct {
									Node struct {
										SubjectDigests []struct {
											Value string `json:"value"`
										} `json:"subjectDigests"`
									} `json:"node"`
								} `json:"edges"`
							} `json:"subjects"`
						} `json:"statement"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"dsses"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", "", fmt.Errorf("decode response (%d bytes): %w", len(raw), err)
	}
	if len(parsed.Data.Dsses.Edges) == 0 {
		return "", "", fmt.Errorf("archivista returned no SLSA v1 envelopes")
	}
	node := parsed.Data.Dsses.Edges[0].Node
	if len(node.Statement.Subjects.Edges) == 0 {
		return "", "", fmt.Errorf("SLSA v1 envelope %s has no subjects", node.GitoidSHA256)
	}
	for _, se := range node.Statement.Subjects.Edges {
		for _, d := range se.Node.SubjectDigests {
			if d.Value != "" {
				return node.GitoidSHA256, d.Value, nil
			}
		}
	}
	return "", "", fmt.Errorf("no non-empty subject digest found on gitoid %s", node.GitoidSHA256)
}

// probeReachable does a short HEAD/POST probe to see if the host answers.
func probeReachable(t *testing.T, url string) (bool, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(`{"query":"{ __typename }"}`))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode < 500, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
