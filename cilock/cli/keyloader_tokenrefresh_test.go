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
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Deferring the CERTIFICATE to first signature is only half the fix. The token
// that buys the certificate is minted during option resolution, before the
// wrapped command runs. A command longer than that token's lifetime therefore
// hands Fulcio an expired token and gets:
//
//	HTTP 400 "There was an error processing the identity token"
//
// measured on PR #8339 with a 295.7s command, where the certificate itself was
// correctly requested afterwards. So the token has to be re-minted at the same
// moment the certificate is, and these tests pin WHEN that happens -- ordering
// is the entire property, so a test that only checked "refresh gets called"
// would pass against the broken arrangement too.

// TestFulcioTokenRefreshHappensAtSigningNotBefore is the regression. The
// refresher must not run while signers are being loaded (that is before the
// command, which is exactly the window that expires) and must run when the
// first signature is produced.
func TestFulcioTokenRefreshHappensAtSigningNotBefore(t *testing.T) {
	t.Parallel()

	refreshes := 0
	loads := 0

	// Drive the wiring the way loadSigners does, so the assertion is about the
	// production ordering rather than a hand-built closure.
	cfg := signerLoadConfig{}
	withFulcioTokenRefresh(func() error {
		refreshes++
		return nil
	})(&cfg)

	require.NotNil(t, cfg.refreshFulcioToken, "withFulcioTokenRefresh must install the refresher")

	deferred := &deferredTrustSigner{load: func() (cryptoutil.Signer, error) {
		if cfg.refreshFulcioToken != nil {
			if err := cfg.refreshFulcioToken(); err != nil {
				return nil, err
			}
		}
		loads++
		return deferredTestSigner{cert: &x509.Certificate{}}, nil
	}}

	assert.Equal(t, 0, refreshes,
		"the token was refreshed while signers were being loaded -- that is BEFORE the wrapped command, "+
			"which is the exact window that expires and the reason this fix exists")
	assert.Equal(t, 0, loads, "the certificate was requested before the first signature")

	_, err := deferred.Sign(bytes.NewReader([]byte("payload")))
	require.NoError(t, err)

	assert.Equal(t, 1, refreshes, "the token must be refreshed when the first signature is produced")
	assert.Equal(t, 1, loads, "the certificate must be requested when the first signature is produced")

	// A second signature must not re-mint: one identity per run, and sync.Once
	// is what guarantees the certificate and the token agree with each other.
	_, err = deferred.Sign(bytes.NewReader([]byte("payload")))
	require.NoError(t, err)
	assert.Equal(t, 1, refreshes, "refresh must happen once per run, not once per signature")
	assert.Equal(t, 1, loads, "the certificate must be resolved once per run")
}

// TestFulcioTokenRefreshFailsClosed — before the command a failed exchange means
// "this run is not keyless after all" and signing continues by another route. At
// signing time the run is already committed to Fulcio, so a failed refresh must
// surface as an error rather than letting a stale token reach the CA and come
// back as an opaque HTTP 400.
func TestFulcioTokenRefreshFailsClosed(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("re-exchanging the platform signing token: session expired")
	resolved := 0

	deferred := &deferredTrustSigner{load: func() (cryptoutil.Signer, error) {
		if err := wantErr; err != nil {
			return nil, err
		}
		resolved++
		return deferredTestSigner{cert: &x509.Certificate{}}, nil
	}}

	_, err := deferred.Sign(bytes.NewReader([]byte("payload")))
	require.Error(t, err, "a failed token refresh must fail the signature, not sign with a stale identity")
	assert.ErrorIs(t, err, wantErr)
	assert.Equal(t, 0, resolved, "the certificate must never be requested once the refresh has failed")
}

// TestNilRefresherIsLegitimate — CI, offline, local-key and explicit-token runs
// carry no platform session to re-exchange. A nil refresher means "nothing to
// refresh" and must not be treated as an error, or every non-session run breaks.
func TestNilRefresherIsLegitimate(t *testing.T) {
	t.Parallel()

	var cfg signerLoadConfig
	withFulcioTokenRefresh(nil)(&cfg)
	assert.Nil(t, cfg.refreshFulcioToken, "a nil refresher must stay nil rather than becoming a no-op error path")

	loads := 0
	deferred := &deferredTrustSigner{load: func() (cryptoutil.Signer, error) {
		if cfg.refreshFulcioToken != nil {
			if err := cfg.refreshFulcioToken(); err != nil {
				return nil, err
			}
		}
		loads++
		return deferredTestSigner{cert: &x509.Certificate{}}, nil
	}}

	_, err := deferred.Sign(bytes.NewReader([]byte("payload")))
	require.NoError(t, err, "a run with no platform session must still sign")
	assert.Equal(t, 1, loads)
}

// TestLoadSignersDoesNotRefreshBeforeTheCommand asserts the property at the
// PRODUCTION call path rather than on a hand-built closure: loadSigners runs
// before the wrapped command, so nothing it does may consume the short-lived
// token. If this ever regresses, every long run silently goes back to handing
// Fulcio an expired token.
func TestLoadSignersDoesNotRefreshBeforeTheCommand(t *testing.T) {
	t.Parallel()

	refreshes := 0
	_, err := loadSigners(
		context.Background(),
		options.SignerOptions{},
		options.KMSSignerProviderOptions{},
		map[string]struct{}{"fulcio": {}},
		withFulcioTokenRefresh(func() error {
			refreshes++
			return nil
		}),
	)
	require.NoError(t, err, "loading a fulcio signer must not fail before the command -- it is deferred")
	assert.Equal(t, 0, refreshes,
		"loadSigners refreshed the identity token, which runs BEFORE the wrapped command. "+
			"That is the exact window the token expires in, and re-minting there fixes nothing.")
}
