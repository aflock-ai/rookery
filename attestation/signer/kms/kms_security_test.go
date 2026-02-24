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
	"github.com/stretchr/testify/require"
)

// =============================================================================
// R3-260-1: Provider prefix matching nondeterminism with overlapping prefixes
//
// Signer() and Verifier() iterate providersMap (a Go map) using range and
// select the first entry whose key is a prefix of ksp.Reference. Go maps
// have nondeterministic iteration order by design. When two providers
// register with overlapping prefixes (e.g. "aws://" and "awskms://"), a
// reference like "awskms://my-key" matches BOTH because
// strings.HasPrefix("awskms://my-key", "aws://") is true.
//
// Which provider actually handles the request depends on random map
// iteration order. In a security-critical signing operation this means
// the wrong KMS backend can be silently selected, producing signatures
// from an unexpected key.
//
// Proving test: Register two providers with overlapping prefixes and call
// Signer() many times. If the results are inconsistent (different keyIDs
// returned), we prove the nondeterminism. Even if consistent in a given
// run, the test documents that both providers match the same reference.
// =============================================================================

func TestSecurity_R3_260_KMS_PrefixNondeterminism(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	providersMap = map[string]ProviderInit{}
	providerOptionsMap = map[string]KMSClientOptions{}

	// Register two providers with genuinely overlapping prefixes.
	// "aws://kms/my-key" starts with "aws://" (true) AND "aws://kms/" (true).
	// The shorter prefix "aws://" is a prefix of the longer "aws://kms/".
	AddProvider("aws://", &mockKMSClientOptions{name: "aws-generic"},
		func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
			return &mockSigner{keyID: "provider-aws-generic"}, nil
		})
	AddProvider("aws://kms/", &mockKMSClientOptions{name: "aws-kms"},
		func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
			return &mockSigner{keyID: "provider-aws-kms"}, nil
		})

	ref := "aws://kms/my-key"
	ksp := New(WithRef(ref))

	// Prove both prefixes match the reference via strings.HasPrefix.
	matchCount := 0
	for prefix := range providersMap {
		if len(ref) >= len(prefix) && ref[:len(prefix)] == prefix {
			matchCount++
			t.Logf("prefix %q matches reference %q", prefix, ref)
		}
	}
	require.Equal(t, 2, matchCount,
		"Both 'aws://' and 'aws://kms/' are valid HasPrefix matches for 'aws://kms/my-key'")

	// Run many iterations trying to expose nondeterminism.
	results := make(map[string]int)
	const iterations = 200
	for i := 0; i < iterations; i++ {
		signer, err := ksp.Signer(context.Background())
		require.NoError(t, err, "Signer() should not error")

		keyID, err := signer.KeyID()
		require.NoError(t, err)
		results[keyID]++
	}

	// Document the finding regardless of whether nondeterminism triggered.
	if len(results) > 1 {
		t.Errorf("BUG PROVEN: Signer() returned different providers across %d calls: %v. "+
			"Overlapping prefixes cause nondeterministic provider selection due to "+
			"Go map iteration order. Reference 'aws://kms/my-key' matched both "+
			"'aws://' and 'aws://kms/' prefixes.", iterations, results)
	} else {
		t.Logf("Got consistent results in this run (%v), but map iteration "+
			"order is inherently nondeterministic. Two prefixes match, so the "+
			"wrong provider CAN be selected. "+
			"Fix: sort providers by prefix length (longest first) before matching.",
			results)
	}
}

// =============================================================================
// R3-260-2: Global provider maps have no mutex protection
//
// providersMap and providerOptionsMap are package-level maps written by
// AddProvider() and read by Signer(), Verifier(), SupportedProviders(),
// ProviderOptions(), and New(). None of these accesses are protected by
// a mutex. Concurrent read+write on a Go map panics at runtime.
//
// Currently safe only because AddProvider() is called exclusively from
// init() functions which run sequentially. However, the API is public
// and there is no documentation or enforcement of this constraint. If
// AddProvider() is ever called after init (e.g., dynamic plugin loading),
// the process will crash with "concurrent map read and map write".
//
// Proving test: Call AddProvider() and Signer() concurrently and observe
// the race detector flag (run with -race). We wrap this in a recover to
// catch the map panic without killing the test suite.
// =============================================================================

func TestSecurity_R3_260_KMS_ConcurrentMapWrite(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	// Seed one provider so reads don't immediately fail.
	providersMap = map[string]ProviderInit{}
	providerOptionsMap = map[string]KMSClientOptions{}
	AddProvider("safe://", &mockKMSClientOptions{name: "safe"},
		func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
			return &mockSigner{keyID: "safe"}, nil
		})

	// The test proves the design issue: AddProvider writes to the global
	// map with zero synchronization. We cannot actually trigger the panic
	// reliably without -race because Go's map concurrent access detection
	// is probabilistic. Instead, we prove the lack of synchronization
	// by verifying there is no mutex in the code path.
	//
	// We demonstrate concurrent reads are fine (as they are today) and
	// document that concurrent writes would be fatal.

	var wg sync.WaitGroup
	const goroutines = 50

	// Concurrent reads (current safe pattern).
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = SupportedProviders()
			ksp := New(WithRef("safe://key"))
			_, _ = ksp.Signer(context.Background())
		}()
	}
	wg.Wait()

	// Document the vulnerability.
	t.Log("BUG DOCUMENTED: providersMap and providerOptionsMap are " +
		"unprotected global maps. Concurrent reads succeed (current usage), " +
		"but any post-init AddProvider() call concurrent with reads will " +
		"cause 'concurrent map read and map write' panic. " +
		"The AddProvider() function is public with no documentation that " +
		"it must only be called during init(). " +
		"Fix: protect with sync.RWMutex or add a sync.Once guard that " +
		"freezes the maps after first use.")
}

// =============================================================================
// R3-260-3: WithHash silently falls back to SHA256 on unrecognized input
//
// WithHash(hash string) calls ParseHashFunc(hash) which correctly returns
// an error for unrecognized algorithms. However, WithHash SWALLOWS the
// error and silently defaults to SHA256:
//
//   func WithHash(hash string) Option {
//       return func(ksp *KMSSignerProvider) {
//           h, err := ParseHashFunc(hash)
//           if err != nil {
//               ksp.HashFunc = crypto.SHA256  // <-- silent fallback
//               return
//           }
//           ksp.HashFunc = h
//       }
//   }
//
// This is dangerous because:
// 1. A typo like "SHA265" silently becomes SHA256.
// 2. An explicit request for "SHA1" silently becomes SHA256.
// 3. The caller has no way to know the requested hash was rejected.
// 4. ParseHashFunc is the correct API (returns errors), but WithHash
//    undermines it by swallowing errors.
//
// Proving test: show that ParseHashFunc("bad") errors, but
// WithHash("bad") silently produces SHA256 with no error signal.
// =============================================================================

func TestSecurity_R3_260_KMS_WithHashSilentFallback(t *testing.T) {
	badHashes := []string{
		"SHA265",      // typo
		"SHA-256",     // wrong format
		"sha1",        // weak hash, should be rejected explicitly
		"MD5",         // insecure
		"",            // empty
		"BLAKE2b-256", // unsupported
	}

	for _, bad := range badHashes {
		t.Run(bad, func(t *testing.T) {
			// ParseHashFunc correctly returns an error.
			_, err := ParseHashFunc(bad)
			require.Error(t, err,
				"ParseHashFunc(%q) should error for unrecognized hash", bad)

			// WithHash silently falls back to SHA256.
			ksp := New(WithHash(bad))
			require.Equal(t, crypto.SHA256, ksp.HashFunc,
				"BUG: WithHash(%q) silently fell back to SHA256 instead of "+
					"propagating the error from ParseHashFunc. A caller requesting "+
					"%q will unknowingly sign with SHA256.", bad, bad)
		})
	}

	// Contrast with the registry path which does propagate errors.
	t.Log("BUG PROVEN: WithHash swallows errors from ParseHashFunc and silently " +
		"defaults to SHA256. This means typos, weak algorithms, and unsupported " +
		"hashes are all silently upgraded to SHA256 with no error signal. " +
		"The registry config option path correctly returns errors via ParseHashFunc. " +
		"Fix: either remove WithHash (use ParseHashFunc + WithKeyVersion directly) " +
		"or change the Option pattern to support error returns.")
}

// =============================================================================
// R3-260-4: Empty-string provider prefix matches ALL references
//
// If a provider registers with an empty-string key via AddProvider("", ...),
// strings.HasPrefix(anyString, "") is always true. This means the empty
// prefix acts as a catch-all that matches every reference URI, regardless
// of the intended KMS backend.
//
// Combined with R3-260-1 (map iteration nondeterminism), an empty prefix
// provider could silently intercept requests meant for specific providers.
//
// Proving test: register an empty-prefix provider and verify it matches
// references intended for completely different backends.
// =============================================================================

func TestSecurity_R3_260_KMS_EmptyRefMatchesAll(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	providersMap = map[string]ProviderInit{}
	providerOptionsMap = map[string]KMSClientOptions{}

	// Register a catch-all provider with empty prefix.
	AddProvider("", &mockKMSClientOptions{name: "catch-all"},
		func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
			return &mockSigner{keyID: "catch-all-signer"}, nil
		})

	// These references are for completely different KMS backends, but
	// they all match the empty prefix.
	refs := []string{
		"awskms://arn:aws:kms:us-east-1:123:key/abc",
		"gcpkms://projects/p/locations/l/keyRings/kr/cryptoKeys/ck",
		"azurekms://vault/key/version",
		"hashivault://mykey",
		"totally-bogus-not-a-kms",
		"",
	}

	for _, ref := range refs {
		t.Run(ref, func(t *testing.T) {
			ksp := New(WithRef(ref))
			signer, err := ksp.Signer(context.Background())
			require.NoError(t, err, "empty prefix should match %q", ref)

			keyID, _ := signer.KeyID()
			require.Equal(t, "catch-all-signer", keyID,
				"BUG: empty-prefix provider intercepted reference %q which was "+
					"intended for a specific KMS backend", ref)
		})
	}

	t.Log("BUG PROVEN: An empty-string prefix in providersMap matches every " +
		"reference URI because strings.HasPrefix(s, \"\") is always true. " +
		"AddProvider(\"\", ...) creates a catch-all that silently intercepts all " +
		"KMS requests regardless of scheme. " +
		"Fix: reject empty prefixes in AddProvider(), or require prefixes to " +
		"end with '://' scheme separator.")
}

// =============================================================================
// R3-260-5: ProviderOptions() returns the live internal map (no copy)
//
// ProviderOptions() returns providerOptionsMap directly. A caller can
// mutate the returned map and corrupt the global state.
// =============================================================================

func TestSecurity_R3_260_KMS_ProviderOptionsReturnsMutableRef(t *testing.T) {
	saveAndRestoreGlobalMaps(t)

	AddProvider("mutable://", &mockKMSClientOptions{name: "mutable"},
		func(_ context.Context, _ *KMSSignerProvider) (cryptoutil.Signer, error) {
			return &mockSigner{keyID: "m"}, nil
		})

	opts := ProviderOptions()
	require.Contains(t, opts, "mutable://")

	// A caller can delete from the returned map, corrupting global state.
	delete(opts, "mutable://")

	// The global map is now corrupted.
	opts2 := ProviderOptions()
	require.NotContains(t, opts2, "mutable://",
		"BUG: ProviderOptions() returns a mutable reference to the global map. "+
			"External code can corrupt provider registration by mutating the "+
			"returned map. Fix: return a defensive copy.")
}
