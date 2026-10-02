// jade:ring local

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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #7709: an authored keyless policy can be made verify-ready without leaving
// the CLI. --trust-platform-tsa anchors the TSA root THE NAMED PLATFORM
// publishes. The TSA certificates inside the evidence are never anchored,
// with or without the flag (#5989): evidence cannot vouch for its own time.

func trustTSAKeylessBundle(t *testing.T) string {
	t.Helper()
	path, _, _ := synthKeylessTimestampedBundle(t, t.TempDir(), "build", "ci-signer@example.com",
		[]string{"https://aflock.ai/attestations/command-run/v0.1"})
	return path
}

func readAuthoredPolicy(t *testing.T, path string) policy.Policy {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	require.NoError(t, err)
	var pol policy.Policy
	require.NoError(t, json.Unmarshal(raw, &pol))
	return pol
}

func TestTrustPlatformTSA_FromBundlesAnchorsTheDiscoveryRootOnly(t *testing.T) {
	p := newDraftHydratePlatform(t, nil)
	draftHydrateIsolateHome(t)
	bundle := trustTSAKeylessBundle(t)
	out := filepath.Join(t.TempDir(), "policy.json")

	log, err := runCmd(t, PolicyFromBundlesCmd(), bundle, "-o", out, "--"+trustPlatformTSAFlag, "--platform-url", p.URL)
	require.NoError(t, err, log)

	pol := readAuthoredPolicy(t, out)
	require.Len(t, pol.TimestampAuthorities, 1, "exactly the one platform slot, nothing from the evidence")
	got, ok := pol.TimestampAuthorities[localHydrateTSAID]
	require.True(t, ok)
	assert.Equal(t, p.tsaRoot.pem, string(got.Certificate), "the anchor is the platform's self-signed TSA root")
	require.Len(t, got.Intermediates, 1)
	assert.Equal(t, p.tsaInter.pem, string(got.Intermediates[0]))
	assert.Equal(t, int32(1), p.chainHits.Load())
	assert.Contains(t, log, p.tsaRoot.fingerprint(), "the placed root's fingerprint is printed for review")
	assert.NotContains(t, log, "NOT trusted automatically", "no missing-TSA warning once anchored")
}

func TestTrustPlatformTSA_DefaultIsUnchangedAndTouchesNoNetwork(t *testing.T) {
	p := newDraftHydratePlatform(t, nil)
	draftHydrateIsolateHome(t)
	bundle := trustTSAKeylessBundle(t)
	out := filepath.Join(t.TempDir(), "policy.json")

	log, err := runCmd(t, PolicyFromBundlesCmd(), bundle, "-o", out)
	require.NoError(t, err, log)

	pol := readAuthoredPolicy(t, out)
	assert.Empty(t, pol.TimestampAuthorities, "#5989: nothing is anchored without the flag")
	assert.Contains(t, log, "NOT trusted automatically")
	assert.Contains(t, log, "--"+trustPlatformTSAFlag, "the warning names the in-CLI recovery")
	assert.Zero(t, p.discoveryHits.Load()+p.chainHits.Load())
}

func TestTrustPlatformTSA_PlatformURLWithoutTheFlagIsRefused(t *testing.T) {
	draftHydrateIsolateHome(t)
	_, err := runCmd(t, PolicyFromBundlesCmd(), trustTSAKeylessBundle(t), "-o", filepath.Join(t.TempDir(), "p.json"),
		"--platform-url", "https://platform.example")
	require.Error(t, err)
	assert.Contains(t, err.Error(), trustPlatformTSAFlag)
}

func TestTrustPlatformTSA_RefusesATrustBundleThatChangedSinceItWasPinned(t *testing.T) {
	p := newDraftHydratePlatform(t, nil)
	stubSession(t, p.URL)
	_, err := auth.SetTrustBundleSPKI(p.URL, strings.Repeat("ab", 32))
	require.NoError(t, err)
	out := filepath.Join(t.TempDir(), "policy.json")

	_, err = runCmd(t, PolicyFromBundlesCmd(), trustTSAKeylessBundle(t), "-o", out, "--"+trustPlatformTSAFlag, "--platform-url", p.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pinned")
	_, statErr := os.Stat(out)
	assert.True(t, os.IsNotExist(statErr), "no policy is written when the anchor is refused")
}

func TestTrustPlatformTSA_RefusesACrossOriginTSAChain(t *testing.T) {
	p := newDraftHydratePlatform(t, func(p *draftHydratePlatform) {
		p.tsaChainURL = "https://attacker.example/certchain"
	})
	draftHydrateIsolateHome(t)
	out := filepath.Join(t.TempDir(), "policy.json")

	_, err := runCmd(t, PolicyFromBundlesCmd(), trustTSAKeylessBundle(t), "-o", out, "--"+trustPlatformTSAFlag, "--platform-url", p.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on the platform origin")
	assert.Zero(t, p.chainHits.Load())
}

func TestTrustPlatformTSA_FromCommitAnchorsTheSessionPlatform(t *testing.T) {
	p := newDraftHydratePlatform(t, nil)
	draftHydrateIsolateHome(t)
	buildEnv, _ := keylessCollectionEnvelope(t, "build", "ci-signer@example.com",
		[]string{"https://aflock.ai/attestations/command-run/v0.1"})
	installFakeCommitFetcher(t, &fakeCommitFetcher{byGitoid: map[string]dsse.Envelope{"gitoid-build": buildEnv}})

	var errOut bytes.Buffer
	pol, _, err := derivePolicyFromCommit(context.Background(), &errOut,
		policyFromCommitOpts{expiresIn: time.Hour, trustPlatformTSA: true, tsaPlatformURL: p.URL},
		testCommitSHA, "https://archivista.example", "bearer-token")
	require.NoError(t, err, errOut.String())

	require.Len(t, pol.TimestampAuthorities, 1)
	assert.Equal(t, p.tsaRoot.pem, string(pol.TimestampAuthorities[localHydrateTSAID].Certificate))
	assert.NotContains(t, errOut.String(), "NOT trusted automatically")
}
