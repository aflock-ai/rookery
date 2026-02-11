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
	"errors"
	"io"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock types ---

type mockVerifier struct {
	keyID string
}

func (v *mockVerifier) KeyID() (string, error) { return v.keyID, nil }
func (v *mockVerifier) Verify(_ io.Reader, _ []byte) error { return nil }
func (v *mockVerifier) Bytes() ([]byte, error) { return []byte("mock-verifier-bytes"), nil }

type mockSigner struct {
	keyID    string
	verifier cryptoutil.Verifier
	signErr  error
}

func (s *mockSigner) KeyID() (string, error) { return s.keyID, nil }
func (s *mockSigner) Sign(_ io.Reader) ([]byte, error) {
	if s.signErr != nil {
		return nil, s.signErr
	}
	return []byte("mock-signature"), nil
}
func (s *mockSigner) Verifier() (cryptoutil.Verifier, error) {
	if s.verifier == nil {
		return nil, errors.New("no verifier available")
	}
	return s.verifier, nil
}

type mockKMSClientOptions struct {
	name string
}

func (o *mockKMSClientOptions) Init() []registry.Configurer { return nil }
func (o *mockKMSClientOptions) ProviderName() string        { return o.name }

// --- Helpers for test isolation ---

// saveAndRestoreGlobalMaps snapshots the global providersMap and providerOptionsMap,
// returning a cleanup function that restores them. Call this at the top of any test
// that mutates global state.
func saveAndRestoreGlobalMaps(t *testing.T) {
	t.Helper()

	origProviders := make(map[string]ProviderInit, len(providersMap))
	for k, v := range providersMap {
		origProviders[k] = v
	}
	origOptions := make(map[string]KMSClientOptions, len(providerOptionsMap))
	for k, v := range providerOptionsMap {
		origOptions[k] = v
	}

	t.Cleanup(func() {
		providersMap = origProviders
		providerOptionsMap = origOptions
	})
}

// --- Tests ---

func TestNew_Defaults(t *testing.T) {
	ksp := New()
	assert.NotNil(t, ksp)
	assert.Equal(t, "", ksp.Reference)
	assert.Equal(t, "", ksp.KeyVersion)
	assert.Equal(t, crypto.Hash(0), ksp.HashFunc, "HashFunc should be zero-value when no option is applied")
	assert.NotNil(t, ksp.Options, "Options map must be initialized even with no options")
}

func TestNew_WithOptions(t *testing.T) {
	ksp := New(
		WithRef("awskms://my-key"),
		WithHash("SHA384"),
		WithKeyVersion("3"),
	)
	require.NotNil(t, ksp)
	assert.Equal(t, "awskms://my-key", ksp.Reference)
	assert.Equal(t, crypto.SHA384, ksp.HashFunc)
	assert.Equal(t, "3", ksp.KeyVersion)
}

func TestNew_CopiesProviderOptionsMap(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	opts := &mockKMSClientOptions{name: "test-provider"}
	AddProvider("test://", opts, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return &mockSigner{keyID: "test"}, nil
	})

	ksp := New()
	require.NotNil(t, ksp.Options)
	assert.Contains(t, ksp.Options, "test-provider")
	assert.Equal(t, opts, ksp.Options["test-provider"])
}

func TestWithHash_AllVariants(t *testing.T) {
	tests := []struct {
		input    string
		expected crypto.Hash
	}{
		{"SHA224", crypto.SHA224},
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
		{"sha256", crypto.SHA256},   // lowercase -> default
		{"md5", crypto.SHA256},      // unknown -> default
		{"", crypto.SHA256},         // empty -> default
		{"SHA512/256", crypto.SHA256}, // unrecognized variant -> default
	}

	for _, tt := range tests {
		t.Run("hash_"+tt.input, func(t *testing.T) {
			ksp := New(WithHash(tt.input))
			assert.Equal(t, tt.expected, ksp.HashFunc, "WithHash(%q) should yield %v", tt.input, tt.expected)
		})
	}
}

func TestWithRef(t *testing.T) {
	ksp := New(WithRef("gcpkms://projects/p/locations/l/keyRings/kr/cryptoKeys/ck"))
	assert.Equal(t, "gcpkms://projects/p/locations/l/keyRings/kr/cryptoKeys/ck", ksp.Reference)
}

func TestWithKeyVersion(t *testing.T) {
	ksp := New(WithKeyVersion("42"))
	assert.Equal(t, "42", ksp.KeyVersion)
}

func TestSigner_NoMatchingProvider(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	// Clear out any providers that might exist from init()
	providersMap = map[string]ProviderInit{}
	providerOptionsMap = map[string]KMSClientOptions{}

	ksp := New(WithRef("unknown://key"))
	signer, err := ksp.Signer(context.Background())
	assert.Nil(t, signer)
	require.Error(t, err)

	var pnfe *ProviderNotFoundError
	require.ErrorAs(t, err, &pnfe, "error should be *ProviderNotFoundError")
	assert.Contains(t, err.Error(), "unknown://key")
}

func TestSigner_WithRegisteredProvider(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	expectedSigner := &mockSigner{keyID: "my-key-id"}
	AddProvider("mock://", &mockKMSClientOptions{name: "mock"}, func(_ context.Context, ksp *KMSSignerProvider) (cryptoutil.Signer, error) {
		return expectedSigner, nil
	})

	ksp := New(WithRef("mock://my-key"))
	signer, err := ksp.Signer(context.Background())
	require.NoError(t, err)
	assert.Equal(t, expectedSigner, signer)
}

func TestSigner_ProviderReturnsError(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	providerErr := errors.New("kms connection failed")
	AddProvider("failing://", &mockKMSClientOptions{name: "failing"}, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return nil, providerErr
	})

	ksp := New(WithRef("failing://key"))
	signer, err := ksp.Signer(context.Background())
	assert.Nil(t, signer)
	require.ErrorIs(t, err, providerErr)
}

func TestSigner_ProviderReceivesKSP(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	var capturedKSP *KMSSignerProvider
	AddProvider("capture://", &mockKMSClientOptions{name: "capture"}, func(_ context.Context, ksp *KMSSignerProvider) (cryptoutil.Signer, error) {
		capturedKSP = ksp
		return &mockSigner{keyID: "x"}, nil
	})

	ksp := New(WithRef("capture://foo"), WithHash("SHA512"), WithKeyVersion("7"))
	_, err := ksp.Signer(context.Background())
	require.NoError(t, err)

	require.NotNil(t, capturedKSP)
	assert.Equal(t, "capture://foo", capturedKSP.Reference)
	assert.Equal(t, crypto.SHA512, capturedKSP.HashFunc)
	assert.Equal(t, "7", capturedKSP.KeyVersion)
}

func TestVerifier_NoMatchingProvider(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	providersMap = map[string]ProviderInit{}
	providerOptionsMap = map[string]KMSClientOptions{}

	ksp := New(WithRef("nope://key"))
	verifier, err := ksp.Verifier(context.Background())
	assert.Nil(t, verifier)
	require.Error(t, err)

	var pnfe *ProviderNotFoundError
	require.ErrorAs(t, err, &pnfe)
	assert.Contains(t, err.Error(), "nope://key")
}

func TestVerifier_WithRegisteredProvider(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	expectedVerifier := &mockVerifier{keyID: "v-key"}
	ms := &mockSigner{
		keyID:    "s-key",
		verifier: expectedVerifier,
	}
	AddProvider("vmock://", &mockKMSClientOptions{name: "vmock"}, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return ms, nil
	})

	ksp := New(WithRef("vmock://my-key"))
	verifier, err := ksp.Verifier(context.Background())
	require.NoError(t, err)
	assert.Equal(t, expectedVerifier, verifier)
}

func TestVerifier_ProviderInitError(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	providerErr := errors.New("init failed")
	AddProvider("verr://", &mockKMSClientOptions{name: "verr"}, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return nil, providerErr
	})

	ksp := New(WithRef("verr://key"))
	verifier, err := ksp.Verifier(context.Background())
	assert.Nil(t, verifier)
	require.ErrorIs(t, err, providerErr)
}

func TestVerifier_SignerVerifierMethodFails(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	// Signer init succeeds, but Verifier() on the signer returns error
	ms := &mockSigner{
		keyID:    "no-verifier",
		verifier: nil, // will cause Verifier() to return error
	}
	AddProvider("novf://", &mockKMSClientOptions{name: "novf"}, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return ms, nil
	})

	ksp := New(WithRef("novf://key"))
	verifier, err := ksp.Verifier(context.Background())
	assert.Nil(t, verifier)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no verifier available")
}

func TestSupportedProviders(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	// Start from a clean slate
	providersMap = map[string]ProviderInit{}
	providerOptionsMap = map[string]KMSClientOptions{}

	assert.Empty(t, SupportedProviders(), "should be empty with no registered providers")

	AddProvider("alpha://", &mockKMSClientOptions{name: "alpha"}, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return nil, nil
	})
	AddProvider("beta://", &mockKMSClientOptions{name: "beta"}, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return nil, nil
	})

	providers := SupportedProviders()
	assert.Len(t, providers, 2)
	assert.ElementsMatch(t, []string{"alpha://", "beta://"}, providers)
}

func TestProviderOptions(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	providerOptionsMap = map[string]KMSClientOptions{}

	opts := &mockKMSClientOptions{name: "gamma"}
	AddProvider("gamma://", opts, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return nil, nil
	})

	result := ProviderOptions()
	require.Contains(t, result, "gamma://")
	assert.Equal(t, opts, result["gamma://"])
}

func TestProviderNotFoundError_Error(t *testing.T) {
	tests := []struct {
		ref      string
		expected string
	}{
		{"awskms://arn:aws:kms:us-east-1:123:key/abc", "no kms provider found for key reference: awskms://arn:aws:kms:us-east-1:123:key/abc"},
		{"", "no kms provider found for key reference: "},
		{"foo", "no kms provider found for key reference: foo"},
	}

	for _, tt := range tests {
		t.Run("ref_"+tt.ref, func(t *testing.T) {
			err := &ProviderNotFoundError{ref: tt.ref}
			assert.Equal(t, tt.expected, err.Error())
		})
	}
}

func TestProviderNotFoundError_ImplementsError(t *testing.T) {
	var err error = &ProviderNotFoundError{ref: "test"}
	assert.Error(t, err)
}

func TestAddProvider_OverwritesExisting(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	firstSigner := &mockSigner{keyID: "first"}
	secondSigner := &mockSigner{keyID: "second"}

	AddProvider("overwrite://", &mockKMSClientOptions{name: "ow1"}, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return firstSigner, nil
	})
	AddProvider("overwrite://", &mockKMSClientOptions{name: "ow2"}, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return secondSigner, nil
	})

	ksp := New(WithRef("overwrite://key"))
	signer, err := ksp.Signer(context.Background())
	require.NoError(t, err)
	assert.Equal(t, secondSigner, signer, "second AddProvider call should overwrite the first")
}

func TestNew_NilProviderOptionsSkipped(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	providerOptionsMap = map[string]KMSClientOptions{
		"nil-entry": nil,
	}

	// New() should skip nil entries without panicking
	ksp := New()
	require.NotNil(t, ksp)
	assert.NotContains(t, ksp.Options, "nil-entry", "nil provider option should not be copied into Options")
}

func TestSigner_EmptyReference(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	// Provider with empty-string prefix matches everything with HasPrefix
	AddProvider("", &mockKMSClientOptions{name: "catch-all"}, func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
		return &mockSigner{keyID: "catch-all"}, nil
	})

	ksp := New(WithRef("anything://goes"))
	signer, err := ksp.Signer(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, signer, "empty prefix provider should match any reference")
}

func TestMultipleOptions_AppliedInOrder(t *testing.T) {
	ksp := New(
		WithRef("first"),
		WithRef("second"),
		WithHash("SHA512"),
		WithHash("SHA224"),
	)
	assert.Equal(t, "second", ksp.Reference, "last WithRef should win")
	assert.Equal(t, crypto.SHA224, ksp.HashFunc, "last WithHash should win")
}
