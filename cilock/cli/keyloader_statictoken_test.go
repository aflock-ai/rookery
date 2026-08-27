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
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/signer"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	fulciosigner "github.com/aflock-ai/rookery/plugins/signers/fulcio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Deferring the Fulcio certificate to first signature is right for every token
// source cilock re-mints at that moment (platform session, workflow OIDC,
// ambient CI, interactive issuer). An explicit --signer-fulcio-token is the one
// source nobody re-mints: it is whatever the operator passed before the
// command. These tests pin what happens to it on either side of its exp.
//
// The clock is injected (withFulcioClock) so a "12-minute build" is a clock
// move, not a sleep; every test here drives the REAL fulcio provider against a
// fake CA, so a refusal is proven by Fulcio never being asked.

func TestExpiredStaticFulcioTokenIsRefusedBeforeTheCommand(t *testing.T) {
	t.Parallel()

	fulcio := newFakeFulcio(t, nil)
	now := time.Now()
	token := unverifiedJWT(t, map[string]any{"email": "alice@acme.com", "exp": now.Add(-time.Minute).Unix()})

	_, err := loadSigners(context.Background(), staticFulcioSignerOptions(fulcio.URL, &token),
		options.KMSSignerProviderOptions{}, onlyFulcio, withFulcioClock(func() time.Time { return now }))
	require.Error(t, err, "a token that is already expired must fail BEFORE the command, not after a long build")
	assert.Contains(t, err.Error(), fulcioTokenFlag, "the error must name the flag the dead token came from")
	assert.Contains(t, err.Error(), "already expired")
	assert.Empty(t, fulcio.Requests(), "an expired token must never reach Fulcio")
}

func TestStaticFulcioTokenThatExpiresDuringTheCommandIsRefusedAtSigning(t *testing.T) {
	t.Parallel()

	fulcio := newFakeFulcio(t, nil)
	start := time.Now()
	clock := start
	// A 5-minute token, which is what a typical CI OIDC token looks like.
	token := unverifiedJWT(t, map[string]any{"email": "alice@acme.com", "exp": start.Add(5 * time.Minute).Unix()})

	signers, err := loadSigners(context.Background(), staticFulcioSignerOptions(fulcio.URL, &token),
		options.KMSSignerProviderOptions{}, onlyFulcio, withFulcioClock(func() time.Time { return clock }))
	require.NoError(t, err, "the token is valid before the command; loading must not refuse it")
	require.Len(t, signers, 1)

	// The wrapped command runs for 12 minutes.
	clock = start.Add(12 * time.Minute)

	_, err = signers[0].Sign(bytes.NewBufferString("payload"))
	require.Error(t, err, "signing with a token that expired during the command must fail, not mint a dead signature")
	assert.Contains(t, err.Error(), fulcioTokenFlag, "the error must name the flag the dead token came from")
	assert.Contains(t, err.Error(), "cannot be refreshed", "the error must explain why cilock could not recover and what would")
	assert.Contains(t, err.Error(), "cilock login")
	assert.Empty(t, fulcio.Requests(), "an expired static token must never be presented to Fulcio")
}

func TestStaticFulcioTokenPathIsNamedWhenItExpires(t *testing.T) {
	t.Parallel()

	fulcio := newFakeFulcio(t, nil)
	start := time.Now()
	clock := start
	tokenPath := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenPath,
		[]byte(unverifiedJWT(t, map[string]any{"email": "alice@acme.com", "exp": start.Add(5 * time.Minute).Unix()})+"\n"), 0o600))

	signers, err := loadSigners(context.Background(), staticFulcioTokenPathOptions(fulcio.URL, tokenPath),
		options.KMSSignerProviderOptions{}, onlyFulcio, withFulcioClock(func() time.Time { return clock }))
	require.NoError(t, err)

	clock = start.Add(12 * time.Minute)
	_, err = signers[0].Sign(bytes.NewBufferString("payload"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), fulcioTokenPathFlag, "a token read from a file must be blamed on --signer-fulcio-token-path")
	assert.Empty(t, fulcio.Requests())
}

// TestStaticFulcioTokenStillValidAtSigningOutlivesTheOldCertificate is the
// win the deferral buys a static token: a 12-minute build under a 15-minute
// token would have signed with a 10-minute certificate minted before the build
// -- the outage class -- and now signs with one minted after it.
func TestStaticFulcioTokenStillValidAtSigningOutlivesTheOldCertificate(t *testing.T) {
	t.Parallel()

	fulcio := newFakeFulcio(t, nil)
	start := time.Now()
	clock := start
	token := unverifiedJWT(t, map[string]any{"email": "alice@acme.com", "exp": start.Add(15 * time.Minute).Unix()})

	signers, err := loadSigners(context.Background(), staticFulcioSignerOptions(fulcio.URL, &token),
		options.KMSSignerProviderOptions{}, onlyFulcio, withFulcioClock(func() time.Time { return clock }))
	require.NoError(t, err)
	assert.Empty(t, fulcio.Requests(), "loading the signer must not mint the certificate")

	clock = start.Add(12 * time.Minute)
	_, err = signers[0].Sign(bytes.NewBufferString("payload"))
	require.NoError(t, err)
	assert.Len(t, fulcio.Requests(), 1, "the certificate is minted once, at signing")
	cert := signers[0].(*deferredTrustSigner).Certificate()
	require.NotNil(t, cert)
	assert.True(t, time.Now().Before(cert.NotAfter), "the certificate that signed is the fresh one, still inside its validity window")
}

// TestRefreshedFulcioTokenIsTheOneCheckedAtSigning: with a refresher the
// lifetime check must look at the token the refresher just installed, not the
// pre-command one -- otherwise a valid re-exchange would be refused because the
// token it replaced had expired.
func TestRefreshedFulcioTokenIsTheOneCheckedAtSigning(t *testing.T) {
	t.Parallel()

	fulcio := newFakeFulcio(t, nil)
	start := time.Now()
	clock := start
	token := unverifiedJWT(t, map[string]any{"email": "alice@acme.com", "exp": start.Add(5 * time.Minute).Unix()})
	refreshes := 0
	refresh := func() error {
		refreshes++
		token = unverifiedJWT(t, map[string]any{"email": "alice@acme.com", "exp": clock.Add(5 * time.Minute).Unix()})
		return nil
	}

	signers, err := loadSigners(context.Background(), staticFulcioSignerOptions(fulcio.URL, &token),
		options.KMSSignerProviderOptions{}, onlyFulcio,
		withFulcioTokenRefresh(refresh), withFulcioClock(func() time.Time { return clock }))
	require.NoError(t, err)
	require.Equal(t, 0, refreshes, "no refresh before the command")

	clock = start.Add(12 * time.Minute)
	_, err = signers[0].Sign(bytes.NewBufferString("payload"))
	require.NoError(t, err, "the refreshed token is valid at signing; the stale pre-command one must not be what is checked")
	assert.Equal(t, 1, refreshes)
	assert.Len(t, fulcio.Requests(), 1)
}

// TestFulcioTokenWithoutExpIsLeftToFulcio: the lifetime check refuses only a
// legible, elapsed exp. A token with none is forwarded and Fulcio decides,
// exactly as before this check existed.
func TestFulcioTokenWithoutExpIsLeftToFulcio(t *testing.T) {
	t.Parallel()

	fulcio := newFakeFulcio(t, nil)
	token := unverifiedJWT(t, map[string]any{"email": "alice@acme.com"})

	signers, err := loadSigners(context.Background(), staticFulcioSignerOptions(fulcio.URL, &token),
		options.KMSSignerProviderOptions{}, onlyFulcio)
	require.NoError(t, err)
	_, err = signers[0].Sign(bytes.NewBufferString("payload"))
	require.NoError(t, err)
	assert.Len(t, fulcio.Requests(), 1)
}

func TestJWTExpiry(t *testing.T) {
	t.Parallel()

	exp := time.Unix(1_800_000_000, 0)
	got, ok := jwtExpiry(unverifiedJWT(t, map[string]any{"exp": exp.Unix()}))
	require.True(t, ok)
	assert.True(t, got.Equal(exp))

	for name, raw := range map[string]string{
		"not a jwt":     "opaque-token",
		"bad base64":    "a.!!!.c",
		"not json":      "a." + "bm90IGpzb24" + ".c",
		"no exp":        unverifiedJWT(t, map[string]any{"sub": "x"}),
		"zero exp":      unverifiedJWT(t, map[string]any{"exp": 0}),
		"empty payload": "a..c",
	} {
		_, ok := jwtExpiry(raw)
		assert.False(t, ok, name)
	}
}

// TestRefuseExpiredFulcioTokenAssertsTheRealProviderType pins the type
// assertion inside refuseExpiredFulcioToken against what the signer registry
// actually returns for "fulcio".
//
// This test exists because of HOW that check fails. refuseExpiredFulcioToken
// asserts a VALUE type; if the provider ever becomes a *FulcioSignerProvider or
// gets wrapped, the assertion stops matching, the check returns nil for every
// input, and the expiry refusal is silently gone. No other test in this package
// would catch it: they all construct the provider exactly as production does,
// so they would degrade WITH the check rather than against it -- a control that
// stops running while its suite stays green.
//
// So this asserts against the registry directly, one layer beneath the check.
// It must keep naming the concrete type: rewriting it to go through
// refuseExpiredFulcioToken would reintroduce the blind spot it exists to close.
func TestRefuseExpiredFulcioTokenAssertsTheRealProviderType(t *testing.T) {
	t.Parallel()

	want := reflect.TypeOf(fulciosigner.FulcioSignerProvider{})

	// Both shapes loadSigners builds: bare, and with the --signer-fulcio-*
	// setters applied (a setter returns the provider, so it can change the type).
	bare, err := signer.NewSignerProvider("fulcio")
	require.NoError(t, err)

	token := unverifiedJWT(t, map[string]any{"email": "alice@acme.com", "exp": time.Now().Add(time.Hour).Unix()})
	configured, err := signer.NewSignerProvider("fulcio", staticFulcioSignerOptions("https://fulcio.example", &token)["fulcio"]...)
	require.NoError(t, err)

	for name, sp := range map[string]signer.SignerProvider{"bare": bare, "with setters": configured} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, want, reflect.TypeOf(sp),
				"the fulcio signer provider is no longer a %s. refuseExpiredFulcioToken type-asserts to "+
					"that value type, so it now matches nothing and the expired-static-token refusal is "+
					"INERT -- long runs will mint signatures under an expired certificate again. Point the "+
					"assertion in keyloader_statictoken.go at the new type (and this pin with it); do NOT "+
					"just delete this test", want)

			_, ok := sp.(fulciosigner.FulcioSignerProvider)
			assert.True(t, ok, "the exact assertion refuseExpiredFulcioToken performs must succeed")
		})
	}
}

// TestRefuseExpiredFulcioTokenIgnoresOtherProviders is the other half of the
// contract that assertion carries: a non-fulcio provider passes through with no
// verdict, so third-party signer plugins keep working.
func TestRefuseExpiredFulcioTokenIgnoresOtherProviders(t *testing.T) {
	t.Parallel()

	assert.NoError(t, refuseExpiredFulcioToken(notAFulcioProvider{}, time.Now()))
}

type notAFulcioProvider struct{}

func (notAFulcioProvider) Signer(context.Context) (cryptoutil.Signer, error) { return nil, nil }
