// Copyright 2025 The Witness Contributors
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

package azure

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/attestation/signer"
	"github.com/aflock-ai/rookery/attestation/signer/kms"
	ttlcache "github.com/jellydator/ttlcache/v3"
)

type client interface {
	getHashFunc(ctx context.Context) (crypto.Hash, error)
	sign(ctx context.Context, digest []byte, hash crypto.Hash) ([]byte, error)
	verify(ctx context.Context, sig, message io.Reader) error
	setupClient(ctx context.Context, ksp *kms.KMSSignerProvider) (err error)
	fetchKey(ctx context.Context) (*azkeys.KeyBundle, error)
	fetchPublicKey(ctx context.Context) (crypto.PublicKey, error)
}

func init() {
	kms.AddProvider(ReferenceScheme, &azureClientOptions{}, func(ctx context.Context, ksp *kms.KMSSignerProvider) (cryptoutil.Signer, error) {
		return LoadSignerVerifier(ctx, ksp)
	})
}

const (
	cacheKey        = "signer"
	ReferenceScheme = "azurekms://"
)

var (
	errKMSReference = errors.New("kms specification should be in the format azurekms://[VAULT_NAME].vault.azure.net/[KEY_NAME][/KEY_VERSION]")

	// URI format: azurekms://vault-name.vault.azure.net/key-name[/key-version]
	// Examples:
	// - azurekms://my-vault.vault.azure.net/my-key
	// - azurekms://my-vault.vault.azure.net/my-key/1234567890abcdef
	azureKMSRegex = regexp.MustCompile(`^azurekms://([^/]+\.vault\.azure\.net)/([^/]+)(?:/([^/]+))?$`)
	providerName  = fmt.Sprintf("kms-%s", strings.TrimSuffix(ReferenceScheme, "kms://"))
)

// ValidReference returns a non-nil error if the reference string is invalid
func ValidReference(ref string) error {
	if !azureKMSRegex.MatchString(ref) {
		return errKMSReference
	}
	return nil
}

// ParseReference parses an azurekms-scheme URI into its constituent parts.
func ParseReference(resourceID string) (vaultURL, keyName, keyVersion string, err error) {
	matches := azureKMSRegex.FindStringSubmatch(resourceID)
	if len(matches) < 3 {
		err = fmt.Errorf("invalid azurekms format %q", resourceID)
		return vaultURL, keyName, keyVersion, err
	}

	vaultURL = fmt.Sprintf("https://%s/", matches[1])
	keyName = matches[2]
	if len(matches) > 3 {
		keyVersion = matches[3]
	}
	return vaultURL, keyName, keyVersion, err
}

type azureClient struct {
	client     *azkeys.Client
	vaultURL   string
	keyName    string
	keyVersion string
	keyCache   *ttlcache.Cache[string, keyBundle]
	options    *azureClientOptions
}

type azureClientOptions struct {
	verifyRemotely bool
}

type Option func(*azureClientOptions)

func (a *azureClientOptions) Init() []registry.Configurer {
	return []registry.Configurer{
		registry.BoolConfigOption(
			"azure-remote-verify",
			"verify signature using Azure Key Vault remote verification. If false, the public key will be pulled from Azure Key Vault and verification will take place locally",
			true,
			func(sp signer.SignerProvider, verify bool) (signer.SignerProvider, error) {
				ksp, ok := sp.(*kms.KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				co, ok := ksp.Options[providerName].(*azureClientOptions)
				if !ok {
					return sp, fmt.Errorf("failed to get azure client options from azure kms signer provider")
				}

				WithRemoteVerify(verify)(co)
				return ksp, nil
			},
		),
	}
}

func (*azureClientOptions) ProviderName() string {
	return providerName
}

func WithRemoteVerify(remote bool) Option {
	return func(opts *azureClientOptions) {
		opts.verifyRemotely = remote
	}
}

func newAzureClient(ctx context.Context, ksp *kms.KMSSignerProvider) (*azureClient, error) {
	if err := ValidReference(ksp.Reference); err != nil {
		return nil, err
	}

	a := &azureClient{}
	var err error
	a.vaultURL, a.keyName, a.keyVersion, err = ParseReference(ksp.Reference)
	if err != nil {
		return nil, err
	}

	if err := a.setupClient(ctx, ksp); err != nil {
		return nil, err
	}

	a.keyCache = ttlcache.New[string, keyBundle](
		ttlcache.WithDisableTouchOnHit[string, keyBundle](),
	)

	return a, nil
}

func (a *azureClient) setupClient(ctx context.Context, ksp *kms.KMSSignerProvider) (err error) {
	var ok bool
	for _, opt := range ksp.Options {
		a.options, ok = opt.(*azureClientOptions)
		if ok {
			break
		}
	}

	if a.options == nil {
		return fmt.Errorf("unable to find azure client options in azure kms signer provider")
	}

	// Use DefaultAzureCredential which supports multiple authentication methods
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to obtain Azure credential: %w", err)
	}

	// Create the Azure Key Vault client
	a.client, err = azkeys.NewClient(a.vaultURL, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	return nil
}

func (a *azureClient) fetchKey(ctx context.Context) (*azkeys.KeyBundle, error) {
	resp, err := a.client.GetKey(ctx, a.keyName, a.keyVersion, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get key from Azure Key Vault: %w", err)
	}
	return &resp.KeyBundle, nil
}

func (a *azureClient) fetchPublicKey(ctx context.Context) (crypto.PublicKey, error) {
	key, err := a.getKeyBundle(ctx)
	if err != nil {
		return nil, err
	}

	return key.PublicKey, nil
}

func (a *azureClient) getHashFunc(ctx context.Context) (crypto.Hash, error) {
	key, err := a.getKeyBundle(ctx)
	if err != nil {
		return 0, err
	}
	return key.HashFunc(), nil
}

func (a *azureClient) getKeyBundle(ctx context.Context) (*keyBundle, error) {
	var lerr error
	loader := ttlcache.LoaderFunc[string, keyBundle](
		func(c *ttlcache.Cache[string, keyBundle], key string) *ttlcache.Item[string, keyBundle] {
			var k *keyBundle
			k, lerr = a.fetchKeyBundle(ctx)
			if lerr == nil {
				return c.Set(cacheKey, *k, time.Second*300)
			}
			return nil
		},
	)

	item := a.keyCache.Get(cacheKey, ttlcache.WithLoader[string, keyBundle](loader))
	if lerr == nil {
		kb := item.Value()
		return &kb, nil
	}
	return nil, lerr
}

func (a *azureClient) fetchKeyBundle(ctx context.Context) (*keyBundle, error) {
	azKey, err := a.fetchKey(ctx)
	if err != nil {
		return nil, err
	}

	kb := &keyBundle{
		Key: azKey,
	}

	// Extract public key from JWK
	if azKey.Key == nil {
		return nil, errors.New("key data is missing from Azure Key Vault response")
	}

	jwk := azKey.Key
	if jwk.Kty == nil {
		return nil, errors.New("key type is missing from Azure Key Vault response")
	}
	switch *jwk.Kty {
	case azkeys.KeyTypeRSA, azkeys.KeyTypeRSAHSM:
		kb.PublicKey, err = extractRSAPublicKey(jwk)
	case azkeys.KeyTypeEC, azkeys.KeyTypeECHSM:
		kb.PublicKey, err = extractECPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", *jwk.Kty)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	return kb, nil
}

func extractRSAPublicKey(jwk *azkeys.JSONWebKey) (*rsa.PublicKey, error) {
	if jwk.N == nil || jwk.E == nil {
		return nil, errors.New("RSA key is missing required parameters")
	}

	// jwk.N and jwk.E are already []byte, no need to decode
	nBytes := jwk.N
	eBytes := jwk.E

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

func extractECPublicKey(jwk *azkeys.JSONWebKey) (*ecdsa.PublicKey, error) {
	if jwk.X == nil || jwk.Y == nil || jwk.Crv == nil {
		return nil, errors.New("EC key is missing required parameters")
	}

	// jwk.X and jwk.Y are already []byte, no need to decode
	xBytes := jwk.X
	yBytes := jwk.Y

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	var curve elliptic.Curve
	switch *jwk.Crv {
	case azkeys.CurveNameP256:
		curve = elliptic.P256()
	case azkeys.CurveNameP384:
		curve = elliptic.P384()
	case azkeys.CurveNameP521:
		curve = elliptic.P521()
	case azkeys.CurveNameP256K:
		// P-256K is secp256k1, not directly supported by Go standard library
		return nil, fmt.Errorf("curve %s is not supported", *jwk.Crv)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", *jwk.Crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

func (a *azureClient) sign(ctx context.Context, digest []byte, hash crypto.Hash) ([]byte, error) {
	key, err := a.getKeyBundle(ctx)
	if err != nil {
		return nil, err
	}

	alg := key.SigningAlgorithm()
	params := azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest,
	}

	resp, err := a.client.Sign(ctx, a.keyName, a.keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with Azure Key Vault: %w", err)
	}

	if resp.Result == nil {
		return nil, errors.New("signature result is missing from Azure Key Vault response")
	}

	// resp.Result is already []byte, no need to decode
	sig := resp.Result

	// For ECDSA signatures, Azure returns raw R||S concatenated bytes.
	// Convert to ASN.1 DER format for compatibility with Go's crypto/ecdsa.
	if ecKey, ok := key.PublicKey.(*ecdsa.PublicKey); ok {
		keySize := ecKey.Curve.Params().BitSize / 8
		if ecKey.Curve.Params().BitSize%8 != 0 {
			keySize++
		}
		if len(sig) != 2*keySize {
			return nil, fmt.Errorf("unexpected ECDSA signature length: got %d, expected %d", len(sig), 2*keySize)
		}

		r := new(big.Int).SetBytes(sig[:keySize])
		s := new(big.Int).SetBytes(sig[keySize:])
		derSig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA signature to ASN.1 DER: %w", err)
		}
		return derSig, nil
	}

	return sig, nil
}

func (a *azureClient) verify(ctx context.Context, sig, message io.Reader) error {
	s, err := io.ReadAll(sig)
	if err != nil {
		return err
	}

	if a.options.verifyRemotely {
		return a.verifyRemotely(ctx, s, message)
	}

	log.Debug("Verifying signature with Azure Key Vault locally")

	key, err := a.getKeyBundle(ctx)
	if err != nil {
		return err
	}

	// For ECDSA signatures, convert from ASN.1 DER back to raw R||S for the verifier
	// if needed, or verify directly with Go's ecdsa package
	if ecKey, ok := key.PublicKey.(*ecdsa.PublicKey); ok {
		digest, _, err := cryptoutil.ComputeDigest(message, key.HashFunc(), azureSupportedHashFuncs)
		if err != nil {
			return err
		}

		if !ecdsa.VerifyASN1(ecKey, digest, s) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil
	}

	verifier, err := key.Verifier()
	if err != nil {
		return err
	}

	return verifier.Verify(message, s)
}

func (a *azureClient) verifyRemotely(ctx context.Context, sig []byte, message io.Reader) error {
	key, err := a.getKeyBundle(ctx)
	if err != nil {
		return err
	}

	// Compute the digest first
	digest, _, err := cryptoutil.ComputeDigest(message, key.HashFunc(), azureSupportedHashFuncs)
	if err != nil {
		return err
	}

	// For ECDSA signatures, convert from ASN.1 DER back to raw R||S for Azure's API
	if ecKey, ok := key.PublicKey.(*ecdsa.PublicKey); ok { //nolint:nestif
		var parsed struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(sig, &parsed)
		if err != nil {
			return fmt.Errorf("failed to unmarshal ECDSA ASN.1 DER signature: %w", err)
		}
		if len(rest) > 0 {
			return fmt.Errorf("trailing data after ECDSA ASN.1 DER signature (%d bytes)", len(rest))
		}
		if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
			return errors.New("invalid ECDSA signature: R and S must be positive")
		}

		keySize := ecKey.Curve.Params().BitSize / 8
		if ecKey.Curve.Params().BitSize%8 != 0 {
			keySize++
		}

		rBytes := parsed.R.Bytes()
		sBytes := parsed.S.Bytes()
		if len(rBytes) > keySize || len(sBytes) > keySize {
			return fmt.Errorf("ECDSA signature component exceeds curve size: R=%d bytes, S=%d bytes, max=%d", len(rBytes), len(sBytes), keySize)
		}
		rawSig := make([]byte, 2*keySize)
		copy(rawSig[keySize-len(rBytes):keySize], rBytes)
		copy(rawSig[2*keySize-len(sBytes):], sBytes)
		sig = rawSig
	}

	// No need to encode signature, VerifyParameters expects []byte
	alg := key.SigningAlgorithm()

	params := azkeys.VerifyParameters{
		Algorithm: &alg,
		Digest:    digest,
		Signature: sig,
	}

	resp, err := a.client.Verify(ctx, a.keyName, a.keyVersion, params, nil)
	if err != nil {
		return fmt.Errorf("unable to verify signature: %w", err)
	}

	if resp.Value == nil || !*resp.Value {
		return errors.New("signature verification failed")
	}

	return nil
}

type keyBundle struct {
	Key       *azkeys.KeyBundle
	PublicKey crypto.PublicKey
}

func (k *keyBundle) HashFunc() crypto.Hash {
	if k.Key == nil || k.Key.Key == nil || len(k.Key.Key.KeyOps) == 0 {
		return crypto.SHA256 // default
	}

	// Determine hash function based on key type and size
	switch pubKey := k.PublicKey.(type) {
	case *rsa.PublicKey:
		// For RSA, we typically use SHA256
		return crypto.SHA256
	case *ecdsa.PublicKey:
		// For ECDSA, hash function depends on curve
		switch pubKey.Curve {
		case elliptic.P256():
			return crypto.SHA256
		case elliptic.P384():
			return crypto.SHA384
		case elliptic.P521():
			return crypto.SHA512
		default:
			return crypto.SHA256
		}
	default:
		return crypto.SHA256
	}
}

func (k *keyBundle) SigningAlgorithm() azkeys.SignatureAlgorithm {
	switch pubKey := k.PublicKey.(type) {
	case *rsa.PublicKey:
		// Default to RS256 for RSA keys
		return azkeys.SignatureAlgorithmRS256
	case *ecdsa.PublicKey:
		// Choose algorithm based on curve
		switch pubKey.Curve {
		case elliptic.P256():
			return azkeys.SignatureAlgorithmES256
		case elliptic.P384():
			return azkeys.SignatureAlgorithmES384
		case elliptic.P521():
			return azkeys.SignatureAlgorithmES512
		default:
			return azkeys.SignatureAlgorithmES256
		}
	default:
		return azkeys.SignatureAlgorithmRS256
	}
}

func (k *keyBundle) Verifier() (cryptoutil.Verifier, error) {
	return cryptoutil.NewVerifier(k.PublicKey, cryptoutil.VerifyWithHash(k.HashFunc()))
}
