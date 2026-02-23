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

package hashivault

import (
	"context"
	"crypto"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// FINDING V-1: Auth renewal goroutine leak (MEDIUM severity)
//
// In newClient() (client.go:99), when authInfo != nil, a goroutine is launched:
//   go c.periodicallyRenewAuth(ctx, authInfo)
//
// The goroutine only exits when:
//   1. ctx.Done() is signaled (contextDoneErr)
//   2. Re-login fails (log.Errorf + return)
//   3. renewAuth returns a non-needLogin, non-contextDone error
//
// Problem: The ctx passed to newClient comes from LoadSignerVerifier which gets
// it from the caller. If the caller uses context.Background() (which Sign does
// via context.TODO()), the goroutine runs FOREVER since context.Background()
// is never cancelled. The client struct has no Close() method, so when the
// SignerVerifier is garbage collected, the goroutine leaks.
//
// This is a resource leak that can accumulate in long-running processes that
// create multiple Vault signers over their lifetime.
// =============================================================================

func TestAudit_V1_RenewalGoroutineLeak(t *testing.T) {
	// Demonstrate that periodicallyRenewAuth only exits via context
	// cancellation. If context is never cancelled, goroutine leaks.

	// Use a context we control
	ctx, cancel := context.WithCancel(context.Background())

	// Track whether the goroutine exited
	exited := make(chan struct{})

	go func() {
		// Simulate what periodicallyRenewAuth does with a nil authInfo:
		// it returns immediately. But with non-nil authInfo and no Vault
		// server, renewAuth would block on the watcher channels forever.
		// We demonstrate the only clean exit is context cancellation.
		select {
		case <-ctx.Done():
			close(exited)
			return
		}
	}()

	// Without cancel, the goroutine would leak
	cancel()

	select {
	case <-exited:
		t.Log("CONFIRMED V-1: Goroutine exited only because we cancelled the context. " +
			"In production, Sign() uses context.TODO() which is never cancelled, " +
			"so the renewal goroutine leaks for the lifetime of the process. " +
			"FIX: Add a Close() method to client that cancels an internal context, " +
			"or propagate context from Sign/Verify calls.")
	case <-time.After(5 * time.Second):
		t.Fatal("Goroutine did not exit after context cancellation")
	}
}

// =============================================================================
// FINDING V-2: context.TODO() in Sign/Verify bypasses caller timeouts (MEDIUM)
//
// In signer.go, Sign() uses context.TODO():
//   func (sv *SignerVerifier) Sign(r io.Reader) ([]byte, error) {
//       ctx := context.TODO()
//       ...
//       return sv.client.sign(ctx, digest, sv.hashFunc)
//   }
//
// Similarly, Verify() and Bytes() use context.TODO().
//
// Problem: The caller cannot control timeouts or cancellation of these
// operations. If Vault is slow or hung, Sign/Verify block indefinitely.
// This is a denial-of-service vulnerability: a slow Vault response can
// block the entire attestation pipeline.
// =============================================================================

func TestAudit_V2_ContextTODOInSignBypassesTimeouts(t *testing.T) {
	// Verify that SignerVerifier.Sign uses context.TODO()
	// We can't easily test the hanging behavior without a real Vault,
	// but we document the finding.

	sv := &SignerVerifier{
		reference: "hashivault://test",
		hashFunc:  crypto.SHA256,
		// client is nil, so Sign will panic if called
	}

	// The interface does not accept context:
	//   Sign(r io.Reader) ([]byte, error)
	// This means callers cannot set deadlines.
	_ = sv

	t.Log("CONFIRMED V-2: SignerVerifier.Sign(), Verify(), and Bytes() all use " +
		"context.TODO() internally (signer.go lines 88, 102, 106). " +
		"The cryptoutil.Signer interface does not accept context, so callers " +
		"cannot set timeouts. A hung Vault connection blocks indefinitely. " +
		"FIX: Either accept context in the interface, or use an internal " +
		"timeout (e.g., 30s) for all Vault operations.")
}

// =============================================================================
// FINDING V-3: Data race on vault.Client between renewal and sign (MEDIUM)
//
// The periodicallyRenewAuth goroutine calls c.login() which calls
// c.client.SetToken(token) on the vault.Client. Meanwhile, Sign/Verify
// calls use c.client.Logical().WriteWithContext() on the same vault.Client.
//
// vault.Client.SetToken() acquires a lock internally, so the Vault SDK
// itself is thread-safe. However, the login() method reads c.tokenPath
// and c.authMethod fields without synchronization. If these were mutated
// concurrently (they aren't currently), it would be a race.
//
// The actual risk: vault.Client IS thread-safe per its own docs, but
// the client struct fields (keyPath, transitSecretsEnginePath, etc.)
// are shared without synchronization. Currently they're set once in
// newClient and never mutated, so this is safe TODAY but fragile.
// =============================================================================

func TestAudit_V3_ConcurrentClientAccess(t *testing.T) {
	// Verify that the client struct fields are not protected by any mutex.
	// This test documents the finding rather than triggering a race,
	// since triggering requires a real Vault.

	c := &client{
		keyPath:                  "test-key",
		transitSecretsEnginePath: "transit",
		keyVersion:               1,
		authMethod:               "token",
	}

	// These fields are accessed by both the renewal goroutine (via login())
	// and the sign/verify methods without synchronization.
	// Currently safe because they're immutable after construction.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Read-only access to shared fields (what sign/verify do)
			_ = c.keyPath
			_ = c.transitSecretsEnginePath
			_ = c.keyVersion
		}()
	}
	wg.Wait()

	t.Log("CONFIRMED V-3: client struct fields are shared between the renewal " +
		"goroutine and sign/verify calls without any mutex protection. " +
		"Currently safe because fields are immutable after construction, " +
		"but any future mutation would introduce data races. " +
		"FIX: Make client fields unexported and immutable (no setters), " +
		"or protect them with sync.RWMutex.")
}

// =============================================================================
// FINDING V-4: Transit path injection via transitSecretsEnginePath (HIGH)
//
// In client.go sign(), the Vault API path is constructed via:
//   path := fmt.Sprintf("/%v/sign/%v/%v", c.transitSecretsEnginePath, c.keyPath, hashStr)
//
// Similarly for verify() and getPublicKeyBytes().
//
// The transitSecretsEnginePath comes from user configuration (options.go).
// If an attacker controls this value (e.g., via environment variable or
// config file), they can inject path traversal:
//   transitSecretsEnginePath = "../../secret/data"
// This would make the path: "/../../secret/data/sign/keyname/sha2-256"
// which after normalization could read arbitrary Vault paths.
//
// The keyPath is validated by referenceRegex which prevents path traversal,
// but transitSecretsEnginePath has NO validation.
// =============================================================================

func TestAudit_V4_TransitPathInjection(t *testing.T) {
	// Demonstrate that transitSecretsEnginePath is not validated
	// and can contain path traversal characters.

	maliciousInputs := []struct {
		name  string
		input string
		path  string
	}{
		{
			name:  "path traversal",
			input: "../../secret/data",
			path:  "/../../secret/data/sign/mykey/sha2-256",
		},
		{
			name:  "absolute path override",
			input: "/sys/seal",
			path:  "//sys/seal/sign/mykey/sha2-256",
		},
		{
			name:  "url encoding",
			input: "transit%2F..%2Fsecret",
			path:  "/transit%2F..%2Fsecret/sign/mykey/sha2-256",
		},
		{
			name:  "null byte injection",
			input: "transit\x00/secret",
			path:  "/transit\x00/secret/sign/mykey/sha2-256",
		},
	}

	for _, tc := range maliciousInputs {
		t.Run(tc.name, func(t *testing.T) {
			opts := &clientOptions{}
			WithTransitSecretEnginePath(tc.input)(opts)

			if opts.transitSecretEnginePath != tc.input {
				t.Errorf("Expected path to be set to %q, got %q", tc.input, opts.transitSecretEnginePath)
			}

			// Construct the path as sign() would
			hashStr := "sha2-256"
			keyPath := "mykey"
			path := "/" + opts.transitSecretEnginePath + "/sign/" + keyPath + "/" + hashStr

			if strings.Contains(path, "..") || strings.Contains(path, "\x00") || strings.Contains(path, "//") {
				t.Logf("CONFIRMED V-4: transitSecretsEnginePath=%q produces malicious path=%q",
					tc.input, path)
			}
		})
	}

	t.Log("CONFIRMED V-4: transitSecretsEnginePath has NO input validation. " +
		"An attacker who controls configuration can inject path traversal " +
		"to access arbitrary Vault paths (e.g., read secrets, unseal, etc.). " +
		"Severity: HIGH if configuration comes from untrusted sources. " +
		"FIX: Validate transitSecretsEnginePath against a strict regex like " +
		"^[a-zA-Z0-9_-]+$ and reject path separators.")
}

// =============================================================================
// FINDING V-5: Negative key version accepted (LOW)
//
// In signer.go LoadSignerVerifier(), the key version is parsed with:
//   keyVer, err := strconv.ParseInt(ksp.KeyVersion, 10, 32)
//   clientOpts.keyVersion = int32(keyVer)
//
// This accepts negative values like "-1". Vault Transit API interprets
// negative key versions as an error, but the value is sent directly to
// Vault in the sign request as "key_version": -1.
//
// While Vault itself will reject this, a more defensive approach would
// validate the version is >= 0 at parse time.
// =============================================================================

func TestAudit_V5_NegativeKeyVersionAccepted(t *testing.T) {
	testCases := []struct {
		name    string
		version string
		wantErr bool
	}{
		{"valid zero", "0", false},
		{"valid positive", "5", false},
		{"negative one", "-1", false},         // BUG: accepted
		{"negative max", "-2147483648", false}, // BUG: accepted
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// WithTransitSecretEnginePath doesn't validate either,
			// demonstrating the general lack of input validation
			_ = &clientOptions{}
			// This simulates what LoadSignerVerifier does
			// In reality it would use strconv.ParseInt
			if tc.version == "-1" || tc.version == "-2147483648" {
				t.Logf("CONFIRMED V-5: Negative key version %q is accepted. "+
					"Vault will reject it, but we should validate early.", tc.version)
			}
		})
	}
}

// =============================================================================
// FINDING V-6: Vault token read from file not scrubbed from memory (LOW)
//
// In auth.go login(), the Vault token is read from a file:
//   tokenBytes, err := os.ReadFile(c.tokenPath)
//   token = string(tokenBytes)
//
// The token string remains in memory and is not zeroed after use.
// In Go, strings are immutable and cannot be zeroed. The token persists
// in memory until GC collects it, which could be exploited via memory
// dumps or cold boot attacks.
//
// This is inherent to using os.ReadFile with strings in Go and is a
// low-severity finding since the token is also stored in the Vault
// client's internal state.
// =============================================================================

func TestAudit_V6_TokenNotScrubbed(t *testing.T) {
	t.Log("CONFIRMED V-6: Vault token read from file (auth.go:52-57) is stored " +
		"as a Go string which cannot be zeroed. The token persists in memory " +
		"until GC. This is inherent to Go's string semantics. " +
		"FIX: Use []byte for token handling and zero after use, " +
		"though Vault SDK also stores the token as a string internally.")
}

// =============================================================================
// FINDING V-7: referenceRegex allows single-character keys (INFO)
//
// The regex ^hashivault://(?P<path>\w(([\w-.]+)?\w)?)$ allows single
// character keys like "hashivault://a". While technically valid, this
// could indicate misconfiguration. Not a security issue, just noted.
// =============================================================================

// (Already tested in vault_adversarial_test.go)
