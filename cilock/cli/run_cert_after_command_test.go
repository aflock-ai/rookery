// Copyright 2026 The Aflock Authors
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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFulcioCertificateIsRequestedAfterTheWrappedCommand is the outage-class
// regression at the level that matters: the whole `cilock run` pipeline from
// loadSigners through runRun, against the real fulcio provider and a fake CA.
//
// The 2026-08-27 Pushgate evaluation outage was cilock taking its 10-minute
// Fulcio certificate at the START of a run and producing the signature at the
// END; any gate longer than the certificate's lifetime signed with an expired
// certificate. Unit tests on deferredTrustSigner prove the signer is lazy; this
// test proves nothing between loading the signer and the end of the wrapped
// command touches it. The wrapped command leaves a marker file the instant it
// finishes, and the fake Fulcio records, at the moment of the certificate
// request, whether that marker already existed -- a causal check, not a timing
// threshold. The command sleeps so an eager mint has a wide window to land in.
func TestFulcioCertificateIsRequestedAfterTheWrappedCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses sh; the ordering property is platform-independent")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "command-finished")
	fulcio := newFakeFulcio(t, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	})
	token := unverifiedJWT(t, map[string]any{"email": "alice@acme.com", "exp": time.Now().Add(time.Hour).Unix()})

	signers, err := loadSigners(context.Background(), staticFulcioSignerOptions(fulcio.URL, &token),
		options.KMSSignerProviderOptions{}, onlyFulcio)
	require.NoError(t, err)
	require.Empty(t, fulcio.Requests(), "loading the signers requested a certificate before the command ran")

	outFile := filepath.Join(dir, "probe.json")
	ro := options.RunOptions{
		StepName:    "probe",
		OutFilePath: outFile,
		// The product attestor walks the working tree; it has nothing to do
		// with signing order and only slows the test down.
		NoDefaultAttestors: []string{"product"},
	}
	err = runRun(context.Background(), ro, []string{"sh", "-c", `sleep 1 && touch "$0"`, marker}, nil, onlyFulcio, signers...)
	require.NoError(t, err)

	requests := fulcio.Requests()
	require.Len(t, requests, 1, "exactly one certificate per run")
	assert.True(t, requests[0].Observed,
		"Fulcio was asked for the signing certificate BEFORE the wrapped command had finished; "+
			"a command longer than the certificate lifetime would sign with an expired certificate")

	raw, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var envelope struct {
		Signatures []struct {
			Sig         string `json:"sig"`
			Certificate string `json:"certificate"`
		} `json:"signatures"`
	}
	require.NoError(t, json.Unmarshal(raw, &envelope))
	require.Len(t, envelope.Signatures, 1)
	assert.NotEmpty(t, envelope.Signatures[0].Sig)
	assert.NotEmpty(t, envelope.Signatures[0].Certificate, "the envelope must carry the certificate that was minted after the command")
}
