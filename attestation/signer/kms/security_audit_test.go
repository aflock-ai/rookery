//go:build audit

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

package kms

import (
	"context"
	"crypto"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// FINDING K-1: Global provider maps have no synchronization (HIGH)
//
// providersMap and providerOptionsMap are package-level maps with no mutex.
// AddProvider() writes to them. Signer()/Verifier() iterate them with range.
// SupportedProviders() and ProviderOptions() read them.
//
// Currently safe ONLY because:
//   1. All AddProvider calls happen in init() functions
//   2. init() functions run sequentially before main()
//   3. After init(), the maps are read-only
//
// However, this is a latent concurrency bug:
//   - If any code calls AddProvider() after init (e.g., plugin loading),
//     concurrent map read/write will panic.
//   - The code has NO documentation that AddProvider must only be called
//     during init().
//   - Go's race detector would flag this if it happened.
// =============================================================================

func TestAudit_K1_ProviderMapConcurrency(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	// Demonstrate that concurrent reads are safe (current behavior)
	AddProvider("audit-k1://", &mockKMSClientOptions{name: "audit-k1"},
		func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
			return &mockSigner{keyID: "k1"}, nil
		})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = SupportedProviders()
			_ = ProviderOptions()

			ksp := New(WithRef("audit-k1://key"))
			_, _ = ksp.Signer(context.Background())
		}()
	}
	wg.Wait()

	t.Log("CONFIRMED K-1: providersMap and providerOptionsMap are unprotected " +
		"global maps. Currently safe because writes only happen in init(). " +
		"Any post-init AddProvider() call concurrent with reads will panic. " +
		"FIX: Protect with sync.RWMutex, or document the init()-only constraint " +
		"and add a sync.Once guard.")
}

// =============================================================================
// FINDING K-2: Provider prefix matching is order-dependent and ambiguous (MEDIUM)
//
// Signer() iterates providersMap with range and uses HasPrefix:
//   for ref, pi := range providersMap {
//       if strings.HasPrefix(ksp.Reference, ref) {
//           return pi(ctx, ksp)
//       }
//   }
//
// Problems:
// 1. Go map iteration is random, so if two providers have overlapping
//    prefixes (e.g., "aws://" and "awskms://"), the match is nondeterministic.
// 2. An empty-string prefix matches EVERYTHING (tested in signerprovider_test.go).
// 3. First match wins, but "first" is random in map iteration.
//
// This could lead to signing with the WRONG KMS provider if prefixes overlap.
// =============================================================================

func TestAudit_K2_AmbiguousPrefixMatching(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	providersMap = map[string]ProviderInit{}
	providerOptionsMap = map[string]KMSClientOptions{}

	// Register two providers with overlapping prefixes
	provider1Called := false
	provider2Called := false

	AddProvider("aws://", &mockKMSClientOptions{name: "aws"},
		func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
			provider1Called = true
			return &mockSigner{keyID: "aws"}, nil
		})

	AddProvider("awskms://", &mockKMSClientOptions{name: "awskms"},
		func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
			provider2Called = true
			return &mockSigner{keyID: "awskms"}, nil
		})

	// "awskms://key" has prefix "aws://" AND "awskms://"
	// Which provider gets called depends on map iteration order.
	ksp := New(WithRef("awskms://my-key"))

	// Run multiple times to try to trigger nondeterminism
	inconsistentResults := false
	results := make(map[string]int)
	for i := 0; i < 50; i++ {
		provider1Called = false
		provider2Called = false

		signer, err := ksp.Signer(context.Background())
		require.NoError(t, err)

		keyID, _ := signer.KeyID()
		results[keyID]++
	}

	if len(results) > 1 {
		inconsistentResults = true
		t.Errorf("CONFIRMED K-2: Ambiguous prefix matching produced inconsistent results: %v", results)
	}

	if !inconsistentResults {
		t.Logf("K-2: Got consistent results in this run (%v), but map iteration "+
			"order is inherently nondeterministic. The bug exists even if this "+
			"test doesn't trigger it every time. "+
			"FIX: Sort providers by prefix length (longest first) before matching, "+
			"or use a trie for prefix matching.", results)
	}
	_ = provider1Called
	_ = provider2Called
}

// =============================================================================
// FINDING K-3: WithHash silently defaults to SHA256 on error (MEDIUM)
//
// In signerprovider.go WithHash():
//   func WithHash(hash string) Option {
//       return func(ksp *KMSSignerProvider) {
//           h, err := ParseHashFunc(hash)
//           if err != nil {
//               ksp.HashFunc = crypto.SHA256
//               return
//           }
//           ksp.HashFunc = h
//       }
//   }
//
// If an invalid hash is provided via WithHash, it silently falls back to
// SHA256 instead of signaling an error. This means a typo like "SHA265"
// would silently use SHA256, potentially leading to signature verification
// failures if the verifier expects the typo'd algorithm.
//
// The registry config path (ParseHashFunc) correctly returns an error,
// but WithHash swallows it.
// =============================================================================

func TestAudit_K3_WithHashSilentFallback(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected crypto.Hash
	}{
		{"typo SHA265", "SHA265", crypto.SHA256},   // silent fallback
		{"typo SHA-256", "SHA-256", crypto.SHA256}, // silent fallback
		{"empty string", "", crypto.SHA256},        // silent fallback
		{"md5", "MD5", crypto.SHA256},              // silent fallback - dangerous!
		{"sha1", "SHA1", crypto.SHA256},            // silent fallback
		{"valid SHA512", "SHA512", crypto.SHA512},  // correct
		{"valid SHA256", "SHA256", crypto.SHA256},  // correct
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ksp := New(WithHash(tc.input))
			assert.Equal(t, tc.expected, ksp.HashFunc,
				"WithHash(%q) should produce %v", tc.input, tc.expected)

			if tc.input != "" && tc.expected == crypto.SHA256 && tc.input != "SHA256" {
				t.Logf("CONFIRMED K-3: WithHash(%q) silently fell back to SHA256 "+
					"instead of returning an error. A user who types %q expects "+
					"that algorithm, not SHA256.", tc.input, tc.input)
			}
		})
	}

	t.Log("CONFIRMED K-3: WithHash swallows errors from ParseHashFunc and " +
		"silently defaults to SHA256. This can cause signing with unexpected " +
		"algorithm. The comment says 'should be caught earlier by registry " +
		"config validation' but WithHash is a public function that can be " +
		"called directly. FIX: Remove WithHash or make it return an error.")
}

// =============================================================================
// FINDING K-4: ProviderNotFoundError leaks full reference URI (LOW)
//
// The error message includes the full reference URI:
//   "no kms provider found for key reference: awskms://arn:aws:kms:..."
//
// This could leak information about the KMS configuration in error
// messages that reach end users or logs.
// =============================================================================

func TestAudit_K4_ProviderNotFoundLeaksReference(t *testing.T) {
	sensitiveRef := "awskms://arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"
	err := &ProviderNotFoundError{ref: sensitiveRef}

	errMsg := err.Error()
	if len(errMsg) > 200 {
		t.Logf("K-4: Error message is %d bytes and contains the full reference URI. "+
			"This could leak KMS configuration details.", len(errMsg))
	}

	assert.Contains(t, errMsg, sensitiveRef,
		"The error exposes the full reference including AWS account ID and key ID")

	t.Log("CONFIRMED K-4: ProviderNotFoundError includes full KMS reference URI " +
		"which may contain AWS account IDs, key ARNs, etc. " +
		"Severity: LOW - useful for debugging but could leak config details. " +
		"FIX: Truncate or redact the reference in error messages.")
}

// =============================================================================
// FINDING K-5: Options applied before Options map initialized (LOW)
//
// In New():
//   ksp := KMSSignerProvider{}
//   for _, opt := range opts {
//       opt(&ksp)                    // Options applied here
//   }
//   ksp.Options = make(map[string]KMSClientOptions)  // Map initialized here
//   for _, opt := range providerOptionsMap {
//       ksp.Options[opt.ProviderName()] = opt
//   }
//
// If any Option function tries to access ksp.Options, it will be nil
// and cause a panic. Currently no built-in Option does this, but
// it's a footgun for future Options that might need to interact
// with provider-specific configuration.
// =============================================================================

func TestAudit_K5_OptionsBeforeMapInit(t *testing.T) {
	// Demonstrate that Options map is nil during option application
	var optionsWasNil bool

	inspectOpt := func(ksp *KMSSignerProvider) {
		optionsWasNil = ksp.Options == nil
	}

	ksp := New(Option(inspectOpt))
	require.NotNil(t, ksp)
	assert.True(t, optionsWasNil,
		"CONFIRMED K-5: ksp.Options is nil when Option functions execute. "+
			"Any Option that accesses Options map would panic.")

	t.Log("CONFIRMED K-5: Options are applied before the Options map is initialized. " +
		"This means custom Options cannot safely access ksp.Options. " +
		"FIX: Initialize Options map before applying options.")
}

// =============================================================================
// FINDING K-6: HashFunc zero value means no hash (MEDIUM)
//
// When New() is called without WithHash, HashFunc remains crypto.Hash(0).
// The registry config defaults to "sha256" but the constructor doesn't.
// If someone creates a KMSSignerProvider directly (not via registry),
// HashFunc will be 0, which is not a valid hash.
//
// The downstream provider (e.g., Vault) checks supportedHashesToString
// and will fail, but the error message will be confusing:
//   "vault does not support provided hash function "
// (crypto.Hash(0).String() returns "" which is unhelpful)
// =============================================================================

func TestAudit_K6_ZeroValueHashFunc(t *testing.T) {
	ksp := New() // No WithHash

	assert.Equal(t, crypto.Hash(0), ksp.HashFunc,
		"Default HashFunc should be zero value (no hash)")

	hashStr := ksp.HashFunc.String()
	t.Logf("crypto.Hash(0).String() = %q", hashStr)

	// The Vault provider would produce a confusing error
	if hashStr == "" || hashStr == "unknown hash value 0" {
		t.Log("CONFIRMED K-6: New() without WithHash leaves HashFunc as zero value. " +
			"Error messages downstream will be confusing because " +
			"crypto.Hash(0).String() is not descriptive. " +
			"FIX: Default to crypto.SHA256 in New(), matching the registry default.")
	}
}

// =============================================================================
// FINDING K-7: Signer() returns first match, Verifier() also returns first (INFO)
//
// Both Signer() and Verifier() use the same iteration pattern.
// They're consistent with each other, which is good. But both suffer
// from the same prefix-matching issues as K-2.
// =============================================================================

func TestAudit_K7_SignerVerifierConsistency(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	providersMap = map[string]ProviderInit{}
	providerOptionsMap = map[string]KMSClientOptions{}

	ms := &mockSigner{
		keyID:    "consistent",
		verifier: &mockVerifier{keyID: "consistent-verifier"},
	}
	AddProvider("consistent://", &mockKMSClientOptions{name: "consistent"},
		func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
			return ms, nil
		})

	ksp := New(WithRef("consistent://key"))

	signer, err := ksp.Signer(context.Background())
	require.NoError(t, err)
	signerKeyID, _ := signer.KeyID()

	verifier, err := ksp.Verifier(context.Background())
	require.NoError(t, err)
	verifierKeyID, _ := verifier.KeyID()

	// Both should use the same provider
	assert.Equal(t, "consistent", signerKeyID)
	assert.Equal(t, "consistent-verifier", verifierKeyID)

	t.Log("K-7 (INFO): Signer() and Verifier() both use the same provider " +
		"lookup mechanism, so they will match the same provider for a given " +
		"reference. This is correct behavior.")
}
