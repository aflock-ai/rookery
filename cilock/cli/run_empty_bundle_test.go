// Copyright 2026 TestifySec, Inc.
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
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =====================================================================
// Empty-bundle warning — Bug 1 from the blind Linux UX test
// =====================================================================
//
// When a build "succeeds" (exit 0) but every traced write got
// classified as cache / dropped by globs, the resulting envelope has
// no binary subject — the user shipped a "signed but empty" bundle
// and didn't know. These tests pin the warning so a regression
// re-silently the failure.

// captureLogger is a Logger that records every Warnf call into a
// shared buffer. Tests use it via log.SetLogger and inspect the
// buffer after invoking the unit under test.
type captureLogger struct {
	mu    sync.Mutex
	warns []string
}

func (c *captureLogger) Errorf(format string, args ...interface{}) {}
func (c *captureLogger) Error(args ...interface{})                 {}
func (c *captureLogger) Warnf(format string, args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warns = append(c.warns, fmt.Sprintf(format, args...))
}
func (c *captureLogger) Warn(args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warns = append(c.warns, fmt.Sprint(args...))
}
func (c *captureLogger) Debugf(format string, args ...interface{}) {}
func (c *captureLogger) Debug(args ...interface{})                 {}
func (c *captureLogger) Infof(format string, args ...interface{})  {}
func (c *captureLogger) Info(args ...interface{})                  {}

func (c *captureLogger) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.warns))
	copy(out, c.warns)
	return out
}

// useCaptureLogger swaps the global logger for the duration of the
// test, returning it for inspection. SilentLogger is restored on
// cleanup.
func useCaptureLogger(t *testing.T) *captureLogger {
	t.Helper()
	c := &captureLogger{}
	prev := log.GetLogger()
	log.SetLogger(c)
	t.Cleanup(func() { log.SetLogger(prev) })
	return c
}

// productWithEmptyDropped builds a product.Attestor whose Products()
// is empty and whose DroppedByClassification() returns `dropped`.
// Uses the public option/getter API so the test exercises the same
// surface the CLI does.
func productWithEmptyDropped(t *testing.T, dropped int) *product.Attestor {
	t.Helper()
	a := product.New()
	// Trigger Attest in walk mode against a temp dir we never wrote
	// to → empty products, droppedByClassification stays 0. To get
	// dropped > 0 without running a real trace, we reach in via
	// reflection-free option: there is no such option. Instead, we
	// run Attest in trace mode via a fakeProbe (see precedence
	// integration test in product package). For this CLI unit test,
	// we test the early-return path (dropped=0 → no warning) and
	// the no-product attestor path (no commandrun → no warning).
	//
	// The dropped=N path is exercised by an integration test that
	// runs the full pipeline against a synthesized trace; here we
	// just verify the warning fires when the product attestor
	// reports dropped > 0 by setting it through a test-only hook.
	//
	// The hook is a method exported only for testing — keeps the
	// production API surface narrow.
	product.SetDroppedForTesting(a, dropped)
	return a
}

// TestWarnEmptyProductBundle_FiresOnSilentDrop is the primary
// regression. Exit code 0, no products, but trace dropped N writes
// → all three warning lines must appear in order.
func TestWarnEmptyProductBundle_FiresOnSilentDrop(t *testing.T) {
	cl := useCaptureLogger(t)

	prod := productWithEmptyDropped(t, 42)
	cmd := commandrun.New(commandrun.WithCommand([]string{"go", "build"}))
	require.NotNil(t, cmd)
	// Exit code is the zero value; we don't set it explicitly to
	// exercise the "successful command" branch.

	warnEmptyProductBundle([]attestation.Attestor{prod, cmd})

	warns := cl.snapshot()
	require.Len(t, warns, 3, "expected three-line warning, got: %v", warns)
	assert.Contains(t, warns[0], "traced 42 file write(s)")
	assert.Contains(t, warns[1], "products set is empty")
	assert.Contains(t, warns[2], "--attestor-product-include-glob")
}

// TestWarnEmptyProductBundle_QuietWhenNoCommandRun: no commandrun
// attestor in the slice → quiet. We don't second-guess library
// callers who didn't wrap a command.
func TestWarnEmptyProductBundle_QuietWhenNoCommandRun(t *testing.T) {
	cl := useCaptureLogger(t)

	prod := productWithEmptyDropped(t, 5)
	warnEmptyProductBundle([]attestation.Attestor{prod})

	assert.Empty(t, cl.snapshot(), "no commandrun in attestors → no warning")
}

// TestWarnEmptyProductBundle_QuietWhenCommandFailed: the build
// exited non-zero. An empty product set then is just "build broke";
// the operator already sees the real failure. Don't compound the
// noise.
func TestWarnEmptyProductBundle_QuietWhenCommandFailed(t *testing.T) {
	cl := useCaptureLogger(t)

	prod := productWithEmptyDropped(t, 5)
	cmd := commandrun.New(commandrun.WithCommand([]string{"go", "build"}))
	commandrun.SetExitCodeForTesting(cmd, 1)

	warnEmptyProductBundle([]attestation.Attestor{prod, cmd})

	assert.Empty(t, cl.snapshot(), "command exited non-zero → no warning (build broke, not classification)")
}

// TestWarnEmptyProductBundle_QuietWhenProductsNotEmpty: products
// exist; nothing to warn about.
func TestWarnEmptyProductBundle_QuietWhenProductsNotEmpty(t *testing.T) {
	cl := useCaptureLogger(t)

	prod := productWithEmptyDropped(t, 0)
	// Stuff a product directly so Products() is non-empty.
	product.SetProductsForTesting(prod, map[string]attestation.Product{
		"/build/argocd": {MimeType: "application/octet-stream"},
	})
	cmd := commandrun.New(commandrun.WithCommand([]string{"go", "build"}))

	warnEmptyProductBundle([]attestation.Attestor{prod, cmd})

	assert.Empty(t, cl.snapshot(), "non-empty product set → no warning")
}

// TestWarnEmptyProductBundle_QuietWhenNoDrops: trace observed zero
// writes (or all writes already became products). Operator simply
// ran a non-build command; don't lecture them.
func TestWarnEmptyProductBundle_QuietWhenNoDrops(t *testing.T) {
	cl := useCaptureLogger(t)

	prod := productWithEmptyDropped(t, 0)
	cmd := commandrun.New(commandrun.WithCommand([]string{"go", "build"}))

	warnEmptyProductBundle([]attestation.Attestor{prod, cmd})

	for _, w := range cl.snapshot() {
		assert.False(t, strings.Contains(w, "products set is empty"),
			"trace observed 0 writes → don't fire the empty-bundle warning; got: %q", w)
	}
}
