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

package dsse

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test 1: Concurrent verification of the same envelope with the same verifier.
//
// Envelope.Verify creates local state (verifiedKeyIDs map, checkedVerifiers
// slice) per call. This test verifies that concurrent calls on the same
// Envelope value do not race on shared state. The Envelope fields (Payload,
// PayloadType, Signatures) are read-only during Verify.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentVerifySameEnvelope(t *testing.T) {
	signer, verifier, err := createTestKey()
	require.NoError(t, err)

	env, err := Sign("test-payload", bytes.NewReader([]byte("concurrent verify test")), SignWithSigners(signer))
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	results := make([][]CheckedVerifier, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			checked, err := env.Verify(VerifyWithVerifiers(verifier))
			results[idx] = checked
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
		require.Len(t, results[i], 1, "goroutine %d: should have 1 checked verifier", i)
		assert.Nil(t, results[i][0].Error, "goroutine %d: verifier should pass", i)
	}
}

// ---------------------------------------------------------------------------
// Test 2: Concurrent verification with multiple different verifiers.
//
// Each goroutine tries to verify with a different set of verifiers. This
// tests that the verifier's Verify method has no shared mutable state.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentVerifyDifferentVerifiers(t *testing.T) {
	// Create 5 signers and sign the envelope with all of them.
	const numSigners = 5
	signers := make([]cryptoutil.Signer, numSigners)
	verifiers := make([]cryptoutil.Verifier, numSigners)

	for i := range numSigners {
		s, v, err := createTestKey()
		require.NoError(t, err)
		signers[i] = s
		verifiers[i] = v
	}

	env, err := Sign("multi-signer", bytes.NewReader([]byte("multi-signer payload")),
		SignWithSigners(signers...))
	require.NoError(t, err)

	const goroutines = 30
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	passedCounts := make([]int, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Each goroutine uses a different subset of verifiers.
			verifierSubset := verifiers[idx%numSigners : idx%numSigners+1]
			checked, err := env.Verify(
				VerifyWithVerifiers(verifierSubset...),
				VerifyWithThreshold(1),
			)
			errs[idx] = err
			passed := 0
			for _, cv := range checked {
				if cv.Error == nil {
					passed++
				}
			}
			passedCounts[idx] = passed
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
		assert.Equal(t, 1, passedCounts[i],
			"goroutine %d: exactly 1 verifier should pass", i)
	}
}

// ---------------------------------------------------------------------------
// Test 3: Concurrent verification with threshold checks.
//
// Multiple goroutines verify the same multi-signed envelope with different
// threshold values simultaneously.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentVerifyWithThresholds(t *testing.T) {
	const numSigners = 3
	signers := make([]cryptoutil.Signer, numSigners)
	verifiers := make([]cryptoutil.Verifier, numSigners)

	for i := range numSigners {
		s, v, err := createTestKey()
		require.NoError(t, err)
		signers[i] = s
		verifiers[i] = v
	}

	env, err := Sign("threshold-test", bytes.NewReader([]byte("threshold payload")),
		SignWithSigners(signers...))
	require.NoError(t, err)

	// Threshold values 1..3 should pass, 4+ should fail.
	thresholds := []int{1, 2, 3, 4, 5, 10}

	const repeats = 10 // run each threshold multiple times
	var wg sync.WaitGroup
	type result struct {
		threshold int
		err       error
		passed    int
	}
	allResults := make([]result, len(thresholds)*repeats)

	for i, threshold := range thresholds {
		for r := range repeats {
			idx := i*repeats + r
			wg.Add(1)
			go func(idx, threshold int) {
				defer wg.Done()
				checked, err := env.Verify(
					VerifyWithVerifiers(verifiers...),
					VerifyWithThreshold(threshold),
				)
				passed := 0
				for _, cv := range checked {
					if cv.Error == nil {
						passed++
					}
				}
				allResults[idx] = result{
					threshold: threshold,
					err:       err,
					passed:    passed,
				}
			}(idx, threshold)
		}
	}
	wg.Wait()

	for _, r := range allResults {
		if r.threshold <= numSigners {
			assert.NoError(t, r.err,
				"threshold=%d should pass with %d signers", r.threshold, numSigners)
			assert.Equal(t, numSigners, r.passed,
				"threshold=%d: all %d signers should verify", r.threshold, numSigners)
		} else {
			assert.Error(t, r.err,
				"threshold=%d should fail with only %d signers", r.threshold, numSigners)
			var threshErr ErrThresholdNotMet
			assert.ErrorAs(t, r.err, &threshErr)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 4: Concurrent verification with wrong verifiers (all should fail).
//
// Validates that the error paths (ErrNoMatchingSigs) are safe under
// concurrent access.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentVerifyAllFail(t *testing.T) {
	signer, _, err := createTestKey()
	require.NoError(t, err)

	env, err := Sign("fail-test", bytes.NewReader([]byte("data")),
		SignWithSigners(signer))
	require.NoError(t, err)

	// Generate wrong verifiers.
	const numWrong = 5
	wrongVerifiers := make([]cryptoutil.Verifier, numWrong)
	for i := range numWrong {
		_, v, err := createTestKey()
		require.NoError(t, err)
		wrongVerifiers[i] = v
	}

	const goroutines = 30
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := env.Verify(VerifyWithVerifiers(wrongVerifiers...))
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.Error(t, errs[i], "goroutine %d should fail", i)
		assert.ErrorAs(t, errs[i], &ErrNoMatchingSigs{},
			"goroutine %d: should be ErrNoMatchingSigs", i)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Concurrent Sign and Verify interleaved.
//
// Multiple goroutines sign different payloads and verify concurrently. This
// tests that the signing and verification paths have no shared mutable state.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentSignAndVerify(t *testing.T) {
	const goroutines = 20
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s, v, err := createTestKey()
			if err != nil {
				errs[idx] = err
				return
			}

			payload := fmt.Sprintf("payload-%d-with-unique-content", idx)
			env, err := Sign("concurrent-sign",
				bytes.NewReader([]byte(payload)),
				SignWithSigners(s))
			if err != nil {
				errs[idx] = err
				return
			}

			_, err = env.Verify(VerifyWithVerifiers(v))
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		assert.NoError(t, errs[i], "goroutine %d", i)
	}
}

// ---------------------------------------------------------------------------
// Test 6: Concurrent verification with ed25519 keys.
//
// ed25519 verification is fast and stateless. This validates that the
// ED25519Verifier has no internal mutable state (it shouldn't -- it just
// holds a public key).
// ---------------------------------------------------------------------------

func TestRace_ConcurrentVerifyED25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := cryptoutil.NewED25519Signer(priv)
	verifier := cryptoutil.NewED25519Verifier(pub)

	env, err := Sign("ed25519-test", bytes.NewReader([]byte("ed25519 payload")),
		SignWithSigners(signer))
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := env.Verify(VerifyWithVerifiers(verifier))
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		assert.NoError(t, errs[i], "goroutine %d", i)
	}
}

// ---------------------------------------------------------------------------
// Test 7: Concurrent KeyID calls on the same verifier.
//
// KeyID computes a hash of the public key. If there were any caching or
// mutable state, concurrent calls could race.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentKeyID(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	const goroutines = 100
	var wg sync.WaitGroup
	keyIDs := make([]string, goroutines)
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			kid, err := verifier.KeyID()
			keyIDs[idx] = kid
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
	}

	// All KeyIDs must be identical.
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, keyIDs[0], keyIDs[i],
			"goroutine %d: KeyID differs", i)
	}
}

// ---------------------------------------------------------------------------
// Test 8: Concurrent Bytes() calls on the same verifier.
//
// Bytes() marshals the public key to PEM. This should be purely functional
// with no shared state, but let's prove it.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentVerifierBytes(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewED25519Verifier(pub)

	const goroutines = 50
	var wg sync.WaitGroup
	results := make([][]byte, goroutines)
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			b, err := verifier.Bytes()
			results[idx] = b
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
	}

	for i := 1; i < goroutines; i++ {
		assert.Equal(t, results[0], results[i],
			"goroutine %d: Bytes() output differs", i)
	}
}

// ---------------------------------------------------------------------------
// Test 9: Concurrent verification of different envelopes sharing verifiers.
//
// All goroutines share the same verifier slice but operate on different
// envelopes. This verifies that verifier objects are safe to share across
// concurrent Verify calls operating on different data.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentVerifyDifferentEnvelopes(t *testing.T) {
	signer, verifier, err := createTestKey()
	require.NoError(t, err)

	const goroutines = 30
	envelopes := make([]Envelope, goroutines)
	for i := range goroutines {
		payload := fmt.Sprintf("unique-payload-%d", i)
		env, err := Sign("multi-env-test",
			bytes.NewReader([]byte(payload)),
			SignWithSigners(signer))
		require.NoError(t, err)
		envelopes[i] = env
	}

	// All goroutines share the same verifier object.
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := envelopes[idx].Verify(VerifyWithVerifiers(verifier))
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		assert.NoError(t, errs[i], "goroutine %d", i)
	}
}

// ---------------------------------------------------------------------------
// Test 10: Concurrent preauthEncode (internal helper).
//
// preauthEncode is a pure function. This test validates there is no hidden
// package-level mutable state affecting its output.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentPreauthEncode(t *testing.T) {
	const goroutines = 100
	var wg sync.WaitGroup
	results := make([][]byte, goroutines)

	body := []byte("shared body content for PAE")
	bodyType := "application/test"

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = preauthEncode(bodyType, body)
		}(g)
	}
	wg.Wait()

	for i := 1; i < goroutines; i++ {
		assert.Equal(t, results[0], results[i],
			"goroutine %d: preauthEncode result differs", i)
	}
}

// ---------------------------------------------------------------------------
// Test 11: Concurrent duplicate-signature threshold verification.
//
// This validates that the verifiedKeyIDs deduplication logic is correct
// under concurrent access. Each goroutine independently creates its own
// verifiedKeyIDs map, so there should be no cross-contamination.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentDuplicateSigThreshold(t *testing.T) {
	signer, verifier, err := createTestKey()
	require.NoError(t, err)

	env, err := Sign("dedup-test", bytes.NewReader([]byte("dedup payload")),
		SignWithSigners(signer))
	require.NoError(t, err)

	// Duplicate the signature 5 times.
	origSig := env.Signatures[0]
	env.Signatures = []Signature{origSig, origSig, origSig, origSig, origSig}

	const goroutines = 30
	var wg sync.WaitGroup

	// Half try threshold=1 (should pass), half try threshold=2 (should fail).
	type result struct {
		threshold int
		err       error
	}
	allResults := make([]result, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			threshold := 1
			if idx%2 == 1 {
				threshold = 2
			}
			_, err := env.Verify(
				VerifyWithVerifiers(verifier),
				VerifyWithThreshold(threshold),
			)
			allResults[idx] = result{threshold: threshold, err: err}
		}(g)
	}
	wg.Wait()

	for _, r := range allResults {
		if r.threshold == 1 {
			assert.NoError(t, r.err,
				"threshold=1 should pass with duplicated sigs from 1 key")
		} else {
			assert.Error(t, r.err,
				"threshold=2 should fail: only 1 distinct key despite 5 sigs")
			var threshErr ErrThresholdNotMet
			if assert.ErrorAs(t, r.err, &threshErr) {
				assert.Equal(t, 1, threshErr.Actual,
					"only 1 unique key should be counted")
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test 12: Concurrent verifierKeyID calls (internal helper).
//
// verifierKeyID is called inside Verify for each verifier. This test
// validates it is safe to call concurrently on the same verifier.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentVerifierKeyID(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	const goroutines = 100
	var wg sync.WaitGroup
	results := make([]string, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = verifierKeyID(verifier)
		}(g)
	}
	wg.Wait()

	for i := 1; i < goroutines; i++ {
		assert.Equal(t, results[0], results[i],
			"goroutine %d: verifierKeyID result differs", i)
	}
}

// ---------------------------------------------------------------------------
// Test 13: Concurrent Sign with different payloads sharing same signer.
//
// The RSASigner uses rand.Reader internally. This test validates that
// concurrent signing with the same signer object doesn't produce corrupted
// signatures.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentSignSameSigner(t *testing.T) {
	signer, verifier, err := createTestKey()
	require.NoError(t, err)

	const goroutines = 20
	var wg sync.WaitGroup
	envelopes := make([]Envelope, goroutines)
	signErrs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := fmt.Sprintf("payload-for-goroutine-%d", idx)
			env, err := Sign("concurrent-sign",
				bytes.NewReader([]byte(payload)),
				SignWithSigners(signer))
			envelopes[idx] = env
			signErrs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, signErrs[i], "goroutine %d sign", i)
	}

	// Verify each envelope separately (they have different payloads so
	// each must verify independently).
	for i := range goroutines {
		_, err := envelopes[i].Verify(VerifyWithVerifiers(verifier))
		assert.NoError(t, err, "goroutine %d verify", i)
	}
}

// ---------------------------------------------------------------------------
// Test 14: Concurrent verification with mixed key types (RSA + ed25519).
//
// Validates that the polymorphic Verifier interface dispatch is safe under
// concurrent access with different concrete verifier types.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentVerifyMixedKeyTypes(t *testing.T) {
	// Create RSA signer/verifier.
	rsaSigner, rsaVerifier, err := createTestKey()
	require.NoError(t, err)

	// Create ed25519 signer/verifier.
	ed25519Pub, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ed25519Signer := cryptoutil.NewED25519Signer(ed25519Priv)
	ed25519Verifier := cryptoutil.NewED25519Verifier(ed25519Pub)

	// Sign with both.
	env, err := Sign("mixed-keys", bytes.NewReader([]byte("mixed key payload")),
		SignWithSigners(rsaSigner, ed25519Signer))
	require.NoError(t, err)

	const goroutines = 40
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	passedCounts := make([]int, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			checked, err := env.Verify(
				VerifyWithVerifiers(rsaVerifier, ed25519Verifier),
				VerifyWithThreshold(2),
			)
			errs[idx] = err
			passed := 0
			for _, cv := range checked {
				if cv.Error == nil {
					passed++
				}
			}
			passedCounts[idx] = passed
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		assert.NoError(t, errs[i], "goroutine %d", i)
		assert.Equal(t, 2, passedCounts[i],
			"goroutine %d: both key types should verify", i)
	}
}
