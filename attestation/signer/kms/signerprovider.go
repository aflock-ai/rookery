// Copyright 2023 The Witness Contributors
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

package kms

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/attestation/signer"
)

func init() { //nolint:dupl,funlen
	signer.Register("kms", func() signer.SignerProvider { return New() }, //nolint:dupl
		registry.StringConfigOption(
			"ref",
			"The KMS Reference URI to use for connecting to the KMS service",
			"",
			func(sp signer.SignerProvider, ref string) (signer.SignerProvider, error) {
				ksp, ok := sp.(*KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				WithRef(ref)(ksp)
				return ksp, nil
			},
		),
		registry.StringConfigOption(
			"hashType",
			"The hash type to use for signing (SHA224, SHA256, SHA384, SHA512)",
			"sha256",
			func(sp signer.SignerProvider, hash string) (signer.SignerProvider, error) {
				ksp, ok := sp.(*KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				h, err := ParseHashFunc(hash)
				if err != nil {
					return sp, err
				}
				ksp.HashFunc = h
				return ksp, nil
			},
		),
		registry.StringConfigOption(
			"keyVersion",
			"The key version to use for signing",
			"",
			func(sp signer.SignerProvider, keyVersion string) (signer.SignerProvider, error) {
				ksp, ok := sp.(*KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided signer provider is not a kms signer provider")
				}

				WithKeyVersion(keyVersion)(ksp)
				return ksp, nil
			},
		),
	)

	signer.RegisterVerifier("kms", func() signer.VerifierProvider { return New() }, //nolint:dupl
		registry.StringConfigOption(
			"ref",
			"The KMS Reference URI to use for connecting to the KMS service",
			"",
			func(sp signer.VerifierProvider, ref string) (signer.VerifierProvider, error) {
				ksp, ok := sp.(*KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided verifier provider is not a kms verifier provider")
				}

				WithRef(ref)(ksp)
				return ksp, nil
			},
		),
		registry.StringConfigOption(
			"hashType",
			"The hash type used for verifying (SHA224, SHA256, SHA384, SHA512)",
			"sha256",
			func(sp signer.VerifierProvider, hash string) (signer.VerifierProvider, error) {
				ksp, ok := sp.(*KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided verifier provider is not a kms verifier provider")
				}

				h, err := ParseHashFunc(hash)
				if err != nil {
					return sp, err
				}
				ksp.HashFunc = h
				return ksp, nil
			},
		),
		registry.StringConfigOption(
			"keyVersion",
			"The key version to use for signing",
			"",
			func(sp signer.VerifierProvider, keyVersion string) (signer.VerifierProvider, error) {
				ksp, ok := sp.(*KMSSignerProvider)
				if !ok {
					return sp, fmt.Errorf("provided verifier provider is not a kms verifier provider")
				}

				WithKeyVersion(keyVersion)(ksp)
				return ksp, nil
			},
		),
	)
}

type KMSSignerProvider struct {
	Reference  string                      `jsonschema:"title=Reference,description=KMS key reference URI identifying the signing key"`
	KeyVersion string                      `jsonschema:"title=Key Version,description=Specific key version to use for signing operations"`
	HashFunc   crypto.Hash                 `jsonschema:"title=Hash Function,description=Cryptographic hash function for signing,default=SHA256"`
	Options    map[string]KMSClientOptions `jsonschema:"title=Options,description=Provider-specific KMS client configuration options"`
}

type KMSClientOptions interface {
	Init() []registry.Configurer
	ProviderName() string
}

type Option func(*KMSSignerProvider)

func WithRef(ref string) Option {
	return func(ksp *KMSSignerProvider) {
		ksp.Reference = ref
	}
}

// ParseHashFunc converts a hash name string to a crypto.Hash.
// Returns an error for unrecognized hash names to prevent silent fallback
// to a weaker or unexpected algorithm.
func ParseHashFunc(hash string) (crypto.Hash, error) {
	switch strings.ToUpper(hash) {
	case "SHA224":
		return crypto.SHA224, nil
	case "SHA256":
		return crypto.SHA256, nil
	case "SHA384":
		return crypto.SHA384, nil
	case "SHA512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm %q: valid values are SHA224, SHA256, SHA384, SHA512", hash)
	}
}

func WithHash(hash string) Option {
	return func(ksp *KMSSignerProvider) {
		h, err := ParseHashFunc(hash)
		if err != nil {
			// Option pattern can't return errors; default to SHA256 but this
			// should be caught earlier by the registry config validation.
			ksp.HashFunc = crypto.SHA256
			return
		}
		ksp.HashFunc = h
	}
}

func WithKeyVersion(keyVersion string) Option {
	return func(ksp *KMSSignerProvider) {
		ksp.KeyVersion = keyVersion
	}
}

func New(opts ...Option) *KMSSignerProvider {
	ksp := KMSSignerProvider{}

	for _, opt := range opts {
		opt(&ksp)
	}

	ksp.Options = make(map[string]KMSClientOptions)
	for _, opt := range providerOptionsMap {
		if opt == nil {
			continue
		}

		ksp.Options[opt.ProviderName()] = opt
	}

	return &ksp
}

// ProviderInit is a function that initializes provider-specific SignerVerifier.
//
// It takes a provider-specific resource ID and hash function, and returns a
// SignerVerifier using that resource, or any error that was encountered.
type ProviderInit func(context.Context, *KMSSignerProvider) (cryptoutil.Signer, error)

// AddProvider adds the provider implementation into the local cache
func AddProvider(keyResourceID string, opts KMSClientOptions, init ProviderInit) {
	providersMap[keyResourceID] = init
	providerOptionsMap[keyResourceID] = opts
}

func (ksp *KMSSignerProvider) Signer(ctx context.Context) (cryptoutil.Signer, error) {
	for ref, pi := range providersMap {
		if strings.HasPrefix(ksp.Reference, ref) {
			return pi(ctx, ksp)
		}
	}
	return nil, &ProviderNotFoundError{ref: ksp.Reference}
}

// NOTE: This is a temprorary implementation until we have a SignerVerifier interface
func (ksp *KMSSignerProvider) Verifier(ctx context.Context) (cryptoutil.Verifier, error) {
	for ref, pi := range providersMap {
		if strings.HasPrefix(ksp.Reference, ref) {
			p, err := pi(ctx, ksp)
			if err != nil {
				return nil, err
			}

			// we need to conver this into a cryptoutil.Verifier
			return p.Verifier()
		}
	}
	return nil, &ProviderNotFoundError{ref: ksp.Reference}
}

var providersMap = map[string]ProviderInit{}

var providerOptionsMap = map[string]KMSClientOptions{}

// SupportedProviders returns list of initialized providers
func SupportedProviders() []string {
	keys := make([]string, 0, len(providersMap))
	for key := range providersMap {
		keys = append(keys, key)
	}
	return keys
}

func ProviderOptions() map[string]KMSClientOptions {
	return providerOptionsMap
}

// ProviderNotFoundError indicates that no matching KMS provider was found
type ProviderNotFoundError struct {
	ref string
}

func (e *ProviderNotFoundError) Error() string {
	return fmt.Sprintf("no kms provider found for key reference: %s", e.ref)
}
