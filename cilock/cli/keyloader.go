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

package cli

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/signer"
	"github.com/aflock-ai/rookery/attestation/signer/kms"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/pflag"
)

// signerLoadConfig carries the optional wiring loadSigners needs for the
// deferred keyless path. It is a struct rather than a parameter because only one
// of six call sites has anything to pass.
type signerLoadConfig struct {
	refreshFulcioToken func() error
	// now is the clock the static-token lifetime check reads
	// (refuseExpiredFulcioToken). nil means time.Now; tests move it past a
	// token's exp between loading and signing instead of sleeping.
	now func() time.Time
}

func (c signerLoadConfig) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

type signerLoadOption func(*signerLoadConfig)

// withFulcioTokenRefresh supplies the signing-time token re-exchange. A nil
// refresher is legitimate and means "no platform session to refresh".
func withFulcioTokenRefresh(refresh func() error) signerLoadOption {
	return func(c *signerLoadConfig) { c.refreshFulcioToken = refresh }
}

// withFulcioClock overrides the clock the static-token lifetime check reads.
// Test-only in practice; production takes the time.Now default.
func withFulcioClock(now func() time.Time) signerLoadOption {
	return func(c *signerLoadConfig) { c.now = now }
}

// deferredTrustSigner delays construction of a short-lived certificate signer
// until the first signature is actually produced. A cilock run can legitimately
// take longer than Fulcio's certificate lifetime; obtaining the certificate
// before the wrapped command would then create an envelope whose trusted
// timestamp falls after the certificate expired.
//
// The wrapper implements TrustBundler because Fulcio signers do. dsse.Sign calls
// Sign before reading the key ID and certificate chain, so a successful signature
// guarantees the delegate is available to the remaining methods.
type deferredTrustSigner struct {
	once   sync.Once
	load   func() (cryptoutil.Signer, error)
	signer cryptoutil.Signer
	err    error
}

func (s *deferredTrustSigner) resolve() (cryptoutil.Signer, error) {
	s.once.Do(func() {
		s.signer, s.err = s.load()
		if s.err == nil && s.signer == nil {
			s.err = fmt.Errorf("deferred signer loader returned nil signer")
		}
		if s.err == nil {
			bundler, ok := s.signer.(cryptoutil.TrustBundler)
			if !ok || bundler.Certificate() == nil {
				s.err = fmt.Errorf("deferred certificate signer returned no certificate trust bundle")
			}
		}
	})
	return s.signer, s.err
}

func (s *deferredTrustSigner) Sign(r io.Reader) ([]byte, error) {
	resolved, err := s.resolve()
	if err != nil {
		return nil, err
	}
	return resolved.Sign(r)
}

func (s *deferredTrustSigner) KeyID() (string, error) {
	resolved, err := s.resolve()
	if err != nil {
		return "", err
	}
	return resolved.KeyID()
}

func (s *deferredTrustSigner) Verifier() (cryptoutil.Verifier, error) {
	resolved, err := s.resolve()
	if err != nil {
		return nil, err
	}
	return resolved.Verifier()
}

func (s *deferredTrustSigner) Certificate() *x509.Certificate {
	resolved, err := s.resolve()
	if err != nil {
		return nil
	}
	bundler, ok := resolved.(cryptoutil.TrustBundler)
	if !ok {
		return nil
	}
	return bundler.Certificate()
}

func (s *deferredTrustSigner) Intermediates() []*x509.Certificate {
	resolved, err := s.resolve()
	if err != nil {
		return nil
	}
	bundler, ok := resolved.(cryptoutil.TrustBundler)
	if !ok {
		return nil
	}
	return bundler.Intermediates()
}

func (s *deferredTrustSigner) Roots() []*x509.Certificate {
	resolved, err := s.resolve()
	if err != nil {
		return nil
	}
	bundler, ok := resolved.(cryptoutil.TrustBundler)
	if !ok {
		return nil
	}
	return bundler.Roots()
}

func providersFromFlags(prefix string, flags *pflag.FlagSet) map[string]struct{} {
	providers := make(map[string]struct{})
	flags.Visit(func(flag *pflag.Flag) {
		if !strings.HasPrefix(flag.Name, fmt.Sprintf("%s-", prefix)) {
			return
		}

		parts := strings.Split(flag.Name, "-")
		if len(parts) < 2 {
			return
		}

		providers[parts[1]] = struct{}{}
	})

	return providers
}

// loadSigners creates signers from the provided flags. Configuration and every
// long-lived signer fail immediately rather than silently continuing. Fulcio's
// short-lived certificate is the exception: its provider is configured now, but
// applyKMSOptions runs the per-provider KMS setters over a signer provider, and
// is a no-op for every provider that is not a KMS one. Extracted from
// loadSigners only to keep that function under the cognitive-complexity limit —
// the doubly-nested loop was the largest single contributor and reads better
// named than inline.
func applyKMSOptions(sp signer.SignerProvider, ko options.KMSSignerProviderOptions, providerName string) (signer.SignerProvider, error) {
	ksp, ok := sp.(*kms.KMSSignerProvider)
	if !ok {
		return sp, nil
	}
	for _, opt := range ksp.Options {
		for _, setter := range ko[opt.ProviderName()] {
			configured, err := setter(ksp)
			if err != nil {
				return nil, fmt.Errorf("failed to configure KMS signer provider %v: %w", providerName, err)
			}
			sp = configured
		}
	}
	return sp, nil
}

// newDeferredFulcioSigner builds the keyless signer whose certificate — and the
// identity token that buys it — are both obtained at FIRST SIGNATURE rather than
// before the wrapped command.
//
// Extracted from loadSigners rather than inlined: keeping it there put the
// function over the cognitive-complexity limit, and this is the one branch with
// ordering worth reading on its own.
//
// ORDERING IS THE WHOLE POINT, and it is not obvious:
//
//  1. Refresh the identity token. Deferring the certificate alone is not enough —
//     the token that buys it is minted during option resolution, BEFORE the
//     command, so a command longer than the token's lifetime presents an expired
//     one and Fulcio answers HTTP 400 "error processing the identity token".
//  2. Build the provider HERE, not before the command. Each setter closes over a
//     POINTER to its flag's storage and dereferences it when APPLIED
//     (internal/options addFlags), so constructing the provider now is precisely
//     what picks up the token step 1 just installed. loadSigners still constructs
//     one eagerly, so a malformed flag fails fast before the command runs.
//  3. Refuse a STATIC token that has expired in the meantime. A nil refresh is
//     legitimate and means "no platform session to re-exchange" -- CI ambient
//     OIDC and the interactive issuer flow mint their own fresh token inside
//     the provider, so deferring them is strictly right; but an explicit
//     --signer-fulcio-token / -token-path is whatever the operator passed
//     before the command, and if the command outlived its exp the only honest
//     outcome is an error that names the flag, not a certificate request
//     Fulcio answers with an opaque HTTP 400 (refuseExpiredFulcioToken).
//  4. Only then ask Fulcio for the certificate.
func newDeferredFulcioSigner(
	ctx context.Context,
	name string,
	setters []func(signer.SignerProvider) (signer.SignerProvider, error),
	cfg signerLoadConfig,
) *deferredTrustSigner {
	return &deferredTrustSigner{load: func() (cryptoutil.Signer, error) {
		if cfg.refreshFulcioToken != nil {
			if err := cfg.refreshFulcioToken(); err != nil {
				return nil, fmt.Errorf("failed to refresh the platform signing token before requesting a certificate: %w", err)
			}
		}
		provider, err := signer.NewSignerProvider(name, setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v signer provider: %w", name, err)
		}
		if err := refuseExpiredFulcioToken(provider, cfg.clock()); err != nil {
			if cfg.refreshFulcioToken == nil {
				return nil, fmt.Errorf("refusing to request a signing certificate after the wrapped command: %w; "+
					"a static token cannot be refreshed once the command has run, so pass a longer-lived one, "+
					"or sign with a platform session (cilock login) or the ambient CI workflow identity, "+
					"which cilock re-mints at signing time", err)
			}
			return nil, fmt.Errorf("refusing to request a signing certificate: the freshly re-minted token is already expired: %w", err)
		}
		resolved, err := provider.Signer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v signer: %w", name, err)
		}
		return resolved, nil
	}}
}

// certificate acquisition is deferred until signing so a long wrapped command
// cannot outlive the certificate. Every failure still fails the overall operation.
func loadSigners(ctx context.Context, so options.SignerOptions, ko options.KMSSignerProviderOptions, signerProviders map[string]struct{}, opts ...signerLoadOption) ([]cryptoutil.Signer, error) {
	var cfg signerLoadConfig
	for _, o := range opts {
		o(&cfg)
	}
	signers := make([]cryptoutil.Signer, 0)
	for signerProvider := range signerProviders {
		setters := so[signerProvider]
		sp, err := signer.NewSignerProvider(signerProvider, setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v signer provider: %w", signerProvider, err)
		}

		sp, err = applyKMSOptions(sp, ko, signerProvider)
		if err != nil {
			return nil, err
		}

		// Fulcio certificates are intentionally short lived. Resolve this one
		// signer at signing time, after the wrapped command and attestors have
		// finished, so long builds cannot outlive their signing certificate.
		// Other providers retain fail-fast construction before command execution.
		if signerProvider == "fulcio" {
			// Fail fast on a static token that is ALREADY expired: deferring
			// the certificate must not turn "refused before the build" into
			// "refused after a 30-minute build". The same check runs again at
			// signing time for a token that expires while the command runs.
			if err := refuseExpiredFulcioToken(sp, cfg.clock()); err != nil {
				return nil, fmt.Errorf("refusing to run the command with an identity token that is already expired: %w", err)
			}
			signers = append(signers, newDeferredFulcioSigner(ctx, signerProvider, setters, cfg))
			continue
		}

		s, err := sp.Signer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v signer: %w", signerProvider, err)
		}

		signers = append(signers, s)
	}

	if len(signers) == 0 {
		return signers, fmt.Errorf("failed to load any signers")
	}

	return signers, nil
}

// loadVerifiers creates verifiers from the provided flags. Returns an error immediately
// on any failure rather than silently continuing, preventing verification from proceeding
// with an incomplete trust set. (Security: silent verifier loading failures could allow
// artifacts signed by an expected-but-missing verifier to bypass policy checks.)
func loadVerifiers(ctx context.Context, so options.VerifierOptions, ko options.KMSVerifierProviderOptions, verifierProviders map[string]struct{}) ([]cryptoutil.Verifier, error) { //nolint:gocognit
	verifiers := make([]cryptoutil.Verifier, 0)
	for verifierProvider := range verifierProviders {
		setters := so[verifierProvider]
		sp, err := signer.NewVerifierProvider(verifierProvider, setters...)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v verifier provider: %w", verifierProvider, err)
		}

		if ksp, ok := sp.(*kms.KMSSignerProvider); ok {
			for _, opt := range ksp.Options {
				pn := opt.ProviderName()
				for _, setter := range ko[pn] {
					vp, err := setter(ksp)
					if err != nil {
						return nil, fmt.Errorf("failed to configure KMS verifier provider %v: %w", verifierProvider, err)
					}

					kspv, ok := vp.(*kms.KMSSignerProvider)
					if !ok {
						return nil, fmt.Errorf("provided verifier provider is not a KMS verifier provider")
					}

					sp = kspv
				}
			}
		}

		s, err := sp.Verifier(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v verifier: %w", verifierProvider, err)
		}

		verifiers = append(verifiers, s)
	}

	return verifiers, nil
}
