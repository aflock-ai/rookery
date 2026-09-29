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

// jade:ring local

package cli

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The attacker holds one genuinely signed collection: the build of commit C,
// whose subjects are the commit and the artifact that build produced. They
// hand the gate a DIFFERENT artifact alongside the real commit. The commit
// satisfies the policy on its own, so before #10648 verify exited 0 and only
// printed a "did NOT match" note. The file the operator asked about must be
// bound, or the verdict is a refusal.
func TestVerifyCmd_RefusesArtifactNoStepBinds(t *testing.T) {
	f := newOfflineVerifyFixture(t)
	const gitType = "https://aflock.ai/attestations/git/v0.1"

	genuine := filepath.Join(f.dir, "genuine.bin")
	require.NoError(t, os.WriteFile(genuine, []byte("the artifact the build produced\n"), 0o600))
	genuineHex := artifactSHA256Hex(t, genuine)

	forged := filepath.Join(f.dir, "forged.bin")
	require.NoError(t, os.WriteFile(forged, []byte("an artifact nobody attested\n"), 0o600))

	genuineDir := filepath.Join(f.dir, "genuine-dir")
	require.NoError(t, os.MkdirAll(genuineDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(genuineDir, "payload"), []byte("attested tree\n"), 0o600))
	dirSet, err := cryptoutil.CalculateDigestSetFromDir(genuineDir, nil)
	require.NoError(t, err)
	dirNames, err := dirSet.ToNameMap()
	require.NoError(t, err)
	genuineDirHash := dirNames["dirHash"]
	require.NotEmpty(t, genuineDirHash)

	forgedDir := filepath.Join(f.dir, "forged-dir")
	require.NoError(t, os.MkdirAll(forgedDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(forgedDir, "payload"), []byte("unattested tree\n"), 0o600))

	evidence := f.collection(t, "build.dsse.json", "source", []string{gitType}, fmt.Sprintf(
		`{"name": "%s/commithash:%s", "digest": {"sha1": "%s"}}, {"name": "genuine.bin", "digest": {"sha256": "%s"}}, {"name": "genuine-dir", "digest": {"dirHash": %q}}`,
		gitType, gitSHA1Hex, gitSHA1Hex, genuineHex, genuineDirHash))
	policyPath := f.policy(t, "policy.dsse.json", map[string][]string{"source": {gitType}})
	commit := "sha1:" + gitSHA1Hex

	for _, tc := range []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"genuine artifact binds", []string{genuine, "--subjects", commit}, false},
		{"genuine directory binds", []string{"--directory-path", genuineDir, "--subjects", commit}, false},
		{"forged file rides the commit", []string{forged, "--subjects", commit}, true},
		{"forged file via flag rides the commit", []string{"--artifactfile", forged, "--subjects", commit}, true},
		{"forged directory rides the commit", []string{"--directory-path", forgedDir, "--subjects", commit}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-a", evidence}, tc.args...)
			stdout, stderr, err := f.verify(t, policyPath, args...)
			var verdict VerifyVerdict
			if !tc.wantErr {
				require.NoError(t, err, "%s", stderr)
				require.NoError(t, json.Unmarshal([]byte(stdout), &verdict), "%s", stdout)
				assert.True(t, verdict.Passed)
				assert.NotContains(t, stderr, "did NOT match")
				return
			}
			require.Error(t, err, "an unbound artifact must never produce a passing verdict; stderr:\n%s", stderr)
			assert.Contains(t, err.Error(), "not bound")
			if stdout != "" {
				require.NoError(t, json.Unmarshal([]byte(stdout), &verdict), "%s", stdout)
				assert.False(t, verdict.Passed, "JSON verdict must not report a pass")
			}
			assert.NotContains(t, stderr, "Verification succeeded")
		})
	}
}

func artifactSHA256Hex(t *testing.T, path string) string {
	t.Helper()
	ds, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)
	return ds[cryptoutil.DigestValue{Hash: crypto.SHA256}]
}
