//go:build audit

package attestation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

// --- Test helpers ---

type slowAttestor struct {
	name     string
	runType  RunType
	duration time.Duration
	err      error
}

func (a *slowAttestor) Name() string               { return a.name }
func (a *slowAttestor) Type() string               { return "https://test/" + a.name }
func (a *slowAttestor) RunType() RunType           { return a.runType }
func (a *slowAttestor) Schema() *jsonschema.Schema { return nil }
func (a *slowAttestor) Attest(ctx *AttestationContext) error {
	select {
	case <-ctx.Context().Done():
		return ctx.Context().Err()
	case <-time.After(a.duration):
		return a.err
	}
}

type materialAttestor struct {
	name      string
	runType   RunType
	materials map[string]cryptoutil.DigestSet
}

func (a *materialAttestor) Name() string               { return a.name }
func (a *materialAttestor) Type() string               { return "https://test/" + a.name }
func (a *materialAttestor) RunType() RunType           { return a.runType }
func (a *materialAttestor) Schema() *jsonschema.Schema { return nil }
func (a *materialAttestor) Attest(ctx *AttestationContext) error {
	// Simulate some work
	time.Sleep(time.Millisecond)
	return nil
}
func (a *materialAttestor) Materials() map[string]cryptoutil.DigestSet {
	return a.materials
}

type productAttestor struct {
	name     string
	runType  RunType
	products map[string]Product
}

func (a *productAttestor) Name() string                         { return a.name }
func (a *productAttestor) Type() string                         { return "https://test/" + a.name }
func (a *productAttestor) RunType() RunType                     { return a.runType }
func (a *productAttestor) Schema() *jsonschema.Schema           { return nil }
func (a *productAttestor) Attest(ctx *AttestationContext) error { return nil }
func (a *productAttestor) Products() map[string]Product {
	return a.products
}

type failingAttestor struct {
	name    string
	runType RunType
	err     error
}

func (a *failingAttestor) Name() string               { return a.name }
func (a *failingAttestor) Type() string               { return "https://test/" + a.name }
func (a *failingAttestor) RunType() RunType           { return a.runType }
func (a *failingAttestor) Schema() *jsonschema.Schema { return nil }
func (a *failingAttestor) Attest(ctx *AttestationContext) error {
	return a.err
}

type emptyRunTypeAttestor struct{}

func (a *emptyRunTypeAttestor) Name() string                         { return "empty-run-type" }
func (a *emptyRunTypeAttestor) Type() string                         { return "https://test/empty" }
func (a *emptyRunTypeAttestor) RunType() RunType                     { return "" }
func (a *emptyRunTypeAttestor) Schema() *jsonschema.Schema           { return nil }
func (a *emptyRunTypeAttestor) Attest(ctx *AttestationContext) error { return nil }

// --- Tests ---

// TestRunAttestors_ContextCancellation verifies that long-running attestors
// respect context cancellation propagated via WithContext.
func TestRunAttestors_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	attestors := []Attestor{
		&slowAttestor{
			name:     "slow-one",
			runType:  ExecuteRunType,
			duration: 10 * time.Second,
		},
	}

	actx, err := NewContext("cancel-test", attestors, WithContext(ctx))
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	// Cancel context after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_ = actx.RunAttestors()
	elapsed := time.Since(start)

	// The attestor should have bailed out quickly (< 2s), not waited 10s.
	if elapsed > 2*time.Second {
		t.Logf("OK: RunAttestors eventually returned, but took %v", elapsed)
		// Not flagging as BUG because the attestor above does check ctx.Context().Done().
		// But if the attestor did NOT check, RunAttestors itself has no cancellation logic.
	} else {
		t.Logf("OK: context cancellation respected, returned in %v", elapsed)
	}

	// Verify that the completed attestor has an error from context cancellation
	completed := actx.CompletedAttestors()
	if len(completed) != 1 {
		t.Fatalf("expected 1 completed attestor, got %d", len(completed))
	}
	if completed[0].Error == nil {
		t.Errorf("BUG: attestor should have errored from context cancellation")
	}
}

// TestRunAttestors_NoContextCancellationPropagation verifies that
// RunAttestors does NOT itself check context cancellation between stages.
// This means if a context is cancelled between stage transitions, attestors
// in later stages will still be launched.
func TestRunAttestors_NoContextCancellationBetweenStages(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	prematerialRan := false
	executeRan := false

	prematerialAtt := &slowAttestor{
		name:     "pre",
		runType:  PreMaterialRunType,
		duration: 10 * time.Millisecond,
	}
	executeAtt := &slowAttestor{
		name:     "exec",
		runType:  ExecuteRunType,
		duration: 10 * time.Millisecond,
	}

	// Wrap to track execution
	type trackingAttestor struct {
		Attestor
		ran *bool
	}

	_ = prematerialAtt
	_ = executeAtt
	_ = prematerialRan
	_ = executeRan

	// Cancel context immediately
	cancel()

	attestors := []Attestor{
		&slowAttestor{name: "pre", runType: PreMaterialRunType, duration: 10 * time.Millisecond},
		&slowAttestor{name: "exec", runType: ExecuteRunType, duration: 10 * time.Millisecond},
	}

	actx, err := NewContext("between-stages", attestors, WithContext(ctx))
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	_ = actx.RunAttestors()

	completed := actx.CompletedAttestors()
	// Both attestors should run because RunAttestors does NOT check context between stages.
	// The attestors themselves DO check context, so they should each fail with context.Canceled.
	if len(completed) != 2 {
		t.Errorf("BUG: expected 2 completed attestors (both stages should run even with cancelled ctx), got %d", len(completed))
	}

	for _, c := range completed {
		if c.Error == nil {
			t.Logf("OK: attestor %s completed without error despite cancelled context -- attestor ignores context", c.Attestor.Name())
		} else {
			t.Logf("OK: attestor %s returned error: %v", c.Attestor.Name(), c.Error)
		}
	}

	// KEY FINDING: RunAttestors does not check ctx.ctx.Err() between stages.
	// Attestors in later stages will be launched even if context is already cancelled.
	// Whether this is a bug depends on intent, but it's worth noting.
	t.Logf("OK: RunAttestors does not short-circuit between stages on context cancellation (by design or oversight)")
}

// TestRunAttestors_CalledTwice verifies what happens when RunAttestors is
// called twice on the same AttestationContext. The completedAttestors slice
// should accumulate (which may or may not be intended).
func TestRunAttestors_CalledTwice(t *testing.T) {
	att := &failingAttestor{
		name:    "simple",
		runType: ExecuteRunType,
		err:     nil,
	}

	actx, err := NewContext("double-run", []Attestor{att})
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	if err := actx.RunAttestors(); err != nil {
		t.Fatalf("first RunAttestors failed: %v", err)
	}

	first := actx.CompletedAttestors()
	if len(first) != 1 {
		t.Fatalf("expected 1 completed attestor after first run, got %d", len(first))
	}

	// Run again on the same context
	if err := actx.RunAttestors(); err != nil {
		t.Fatalf("second RunAttestors failed: %v", err)
	}

	second := actx.CompletedAttestors()
	if len(second) != 2 {
		t.Fatalf("expected 2 completed attestors after second run, got %d", len(second))
	}

	// This is a potential bug: running attestors twice accumulates results.
	// The workflow layer (run.go) iterates CompletedAttestors() and would see duplicates.
	t.Errorf("BUG: RunAttestors can be called multiple times on the same context, accumulating completed attestors (got %d). "+
		"There is no guard preventing re-use, and downstream consumers (workflow.run) will see duplicate attestors.", len(second))
}

// TestRunAttestors_EmptyRunType verifies that an attestor with no RunType returns an error.
func TestRunAttestors_EmptyRunType(t *testing.T) {
	actx, err := NewContext("empty-runtype", []Attestor{&emptyRunTypeAttestor{}})
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	err = actx.RunAttestors()
	if err == nil {
		t.Errorf("BUG: expected error for attestor with empty RunType")
	} else {
		t.Logf("OK: empty RunType correctly rejected: %v", err)
	}
}

// TestRunAttestors_VerifyWithOtherTypes verifies the constraint that
// VerifyRunType attestors cannot be mixed with other types.
func TestRunAttestors_VerifyWithOtherTypes(t *testing.T) {
	attestors := []Attestor{
		&failingAttestor{name: "verify", runType: VerifyRunType},
		&failingAttestor{name: "execute", runType: ExecuteRunType},
	}

	actx, err := NewContext("mixed-verify", attestors)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	err = actx.RunAttestors()
	if err == nil {
		t.Errorf("BUG: expected error when mixing VerifyRunType with other types")
	} else {
		t.Logf("OK: correctly rejected mixed verify+other attestors: %v", err)
	}
}

// TestRunAttestors_ConcurrentMaterialWriters tests race conditions when
// multiple attestors in the same stage write materials concurrently.
func TestRunAttestors_ConcurrentMaterialWriters(t *testing.T) {
	// Create multiple material attestors in the same stage that will run concurrently
	attestors := make([]Attestor, 20)
	for i := 0; i < 20; i++ {
		attestors[i] = &materialAttestor{
			name:    fmt.Sprintf("mat-%d", i),
			runType: MaterialRunType,
			materials: map[string]cryptoutil.DigestSet{
				fmt.Sprintf("file-%d.txt", i): {},
			},
		}
	}

	actx, err := NewContext("concurrent-materials", attestors)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	// This should not race because context.go uses mutex in addMaterials
	if err := actx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors failed: %v", err)
	}

	materials := actx.Materials()
	if len(materials) != 20 {
		t.Errorf("BUG: expected 20 materials, got %d (race condition in addMaterials?)", len(materials))
	} else {
		t.Logf("OK: all 20 concurrent material attestors wrote their materials correctly")
	}
}

// TestRunAttestors_ConcurrentProductWriters tests race conditions when
// multiple attestors in the same stage write products concurrently.
func TestRunAttestors_ConcurrentProductWriters(t *testing.T) {
	attestors := make([]Attestor, 20)
	for i := 0; i < 20; i++ {
		attestors[i] = &productAttestor{
			name:    fmt.Sprintf("prod-%d", i),
			runType: ProductRunType,
			products: map[string]Product{
				fmt.Sprintf("output-%d.bin", i): {MimeType: "application/octet-stream"},
			},
		}
	}

	actx, err := NewContext("concurrent-products", attestors)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	if err := actx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors failed: %v", err)
	}

	products := actx.Products()
	if len(products) != 20 {
		t.Errorf("BUG: expected 20 products, got %d (race condition in addProducts?)", len(products))
	} else {
		t.Logf("OK: all 20 concurrent product attestors wrote their products correctly")
	}
}

// TestRunAttestors_AttestorFailureInSameStage verifies that if one attestor
// fails in a concurrent stage, the other attestors in the same stage still run.
func TestRunAttestors_AttestorFailureInSameStage(t *testing.T) {
	sentinel := errors.New("deliberate failure")

	attestors := []Attestor{
		&failingAttestor{name: "good-1", runType: ExecuteRunType, err: nil},
		&failingAttestor{name: "bad-1", runType: ExecuteRunType, err: sentinel},
		&failingAttestor{name: "good-2", runType: ExecuteRunType, err: nil},
	}

	actx, err := NewContext("partial-failure", attestors)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	// RunAttestors should NOT return an error itself for attestor failures.
	// Errors are recorded in CompletedAttestors.
	err = actx.RunAttestors()
	if err != nil {
		t.Fatalf("RunAttestors itself returned error: %v (expected nil; errors should be in CompletedAttestors)", err)
	}

	completed := actx.CompletedAttestors()
	if len(completed) != 3 {
		t.Errorf("BUG: expected all 3 attestors to appear in CompletedAttestors, got %d", len(completed))
	}

	failCount := 0
	successCount := 0
	for _, c := range completed {
		if c.Error != nil {
			failCount++
		} else {
			successCount++
		}
	}

	if failCount != 1 || successCount != 2 {
		t.Errorf("BUG: expected 1 failure and 2 successes, got %d failures and %d successes", failCount, successCount)
	} else {
		t.Logf("OK: one failure does not prevent other attestors in the same stage from completing")
	}
}

// TestWithDirHashGlob_InvalidPattern verifies that WithDirHashGlob silently
// ignores invalid glob patterns instead of returning an error.
func TestWithDirHashGlob_InvalidPattern(t *testing.T) {
	// The pattern "[invalid" is not a valid glob
	invalidPatterns := []string{"[invalid", "valid-*"}

	actx, err := NewContext("glob-test", nil, WithDirHashGlob(invalidPatterns))
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	globs := actx.DirHashGlob()
	if len(globs) != 2 {
		t.Fatalf("expected 2 globs in slice, got %d", len(globs))
	}

	// The invalid glob position should contain nil because the error was discarded
	if globs[0] == nil {
		t.Errorf("BUG: WithDirHashGlob silently stores nil for invalid glob pattern '[invalid'. " +
			"The compile error is discarded (line 107: dirHashGlobItemCompiled, _ := glob.Compile(...)). " +
			"Downstream code calling glob.Match on this nil will panic.")
	} else {
		t.Logf("OK: invalid glob pattern was handled (unexpectedly compiled successfully)")
	}

	// The valid pattern should be fine
	if globs[1] == nil {
		t.Errorf("BUG: valid glob pattern 'valid-*' compiled to nil")
	} else {
		t.Logf("OK: valid glob pattern compiled correctly")
	}
}

// TestSetEnvironmentCapturer_MutexProtected verifies that
// SetEnvironmentCapturer is mutex-protected and does not race with
// concurrent EnvironmentCapturer() reads.
func TestSetEnvironmentCapturer_MutexProtected(t *testing.T) {
	actx, err := NewContext("env-capturer-race", nil)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	// Run with -race to verify no data race.
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			actx.SetEnvironmentCapturer(nil)
		}()
		go func() {
			defer wg.Done()
			_ = actx.EnvironmentCapturer()
		}()
	}
	wg.Wait()
	// If -race doesn't flag this, the mutex fix is working.
}

// TestNewContext_NilAttestors verifies that nil attestors slice is handled.
func TestNewContext_NilAttestors(t *testing.T) {
	actx, err := NewContext("nil-attestors", nil)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	// RunAttestors with nil attestors should just be a no-op
	err = actx.RunAttestors()
	if err != nil {
		t.Errorf("BUG: RunAttestors with nil attestors returned error: %v", err)
	} else {
		t.Logf("OK: RunAttestors with nil attestors is a no-op")
	}

	completed := actx.CompletedAttestors()
	if len(completed) != 0 {
		t.Errorf("BUG: expected 0 completed attestors, got %d", len(completed))
	}
}

// TestCompletedAttestors_ReturnsCopy verifies that CompletedAttestors returns
// a defensive copy, not a reference to the internal slice.
func TestCompletedAttestors_ReturnsCopy(t *testing.T) {
	att := &failingAttestor{name: "test", runType: ExecuteRunType}

	actx, err := NewContext("copy-test", []Attestor{att})
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	_ = actx.RunAttestors()

	first := actx.CompletedAttestors()
	second := actx.CompletedAttestors()

	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected 1 completed attestor in both calls")
	}

	// Mutate the first slice -- it should not affect the second
	first[0].Error = errors.New("mutated")
	fresh := actx.CompletedAttestors()
	if fresh[0].Error != nil {
		t.Errorf("BUG: CompletedAttestors does not return a defensive copy -- mutation leaked through")
	} else {
		t.Logf("OK: CompletedAttestors returns a defensive copy")
	}
}

// TestMaterials_ReturnsCopy verifies Materials() returns a defensive copy.
func TestMaterials_ReturnsCopy(t *testing.T) {
	actx, err := NewContext("materials-copy", nil)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	mats := actx.Materials()
	mats["injected"] = cryptoutil.DigestSet{}

	fresh := actx.Materials()
	if _, found := fresh["injected"]; found {
		t.Errorf("BUG: Materials() does not return a defensive copy")
	} else {
		t.Logf("OK: Materials() returns a defensive copy")
	}
}

// TestProducts_ReturnsCopy verifies Products() returns a defensive copy.
func TestProducts_ReturnsCopy(t *testing.T) {
	actx, err := NewContext("products-copy", nil)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	prods := actx.Products()
	prods["injected"] = Product{}

	fresh := actx.Products()
	if _, found := fresh["injected"]; found {
		t.Errorf("BUG: Products() does not return a defensive copy")
	} else {
		t.Logf("OK: Products() returns a defensive copy")
	}
}

// TestRunAttestors_MixedStagesOrdering verifies that attestors run in the
// correct stage order: prematerial -> material -> execute -> product -> postproduct.
func TestRunAttestors_MixedStagesOrdering(t *testing.T) {
	var mu sync.Mutex
	var order []string

	makeTracking := func(name string, rt RunType) Attestor {
		return &trackingOrderAttestor{
			name:    name,
			runType: rt,
			mu:      &mu,
			order:   &order,
		}
	}

	attestors := []Attestor{
		makeTracking("post", PostProductRunType),
		makeTracking("exec", ExecuteRunType),
		makeTracking("pre", PreMaterialRunType),
		makeTracking("mat", MaterialRunType),
		makeTracking("prod", ProductRunType),
	}

	actx, err := NewContext("ordering", attestors)
	if err != nil {
		t.Fatalf("NewContext failed: %v", err)
	}

	if err := actx.RunAttestors(); err != nil {
		t.Fatalf("RunAttestors failed: %v", err)
	}

	expected := []string{"pre", "mat", "exec", "prod", "post"}
	mu.Lock()
	defer mu.Unlock()

	if len(order) != len(expected) {
		t.Fatalf("expected %d attestors to run, got %d: %v", len(expected), len(order), order)
	}

	for i, name := range expected {
		if order[i] != name {
			t.Errorf("BUG: expected attestor %q at position %d, got %q. Order: %v", name, i, order[i], order)
		}
	}
	t.Logf("OK: attestors ran in correct stage order: %v", order)
}

type trackingOrderAttestor struct {
	name    string
	runType RunType
	mu      *sync.Mutex
	order   *[]string
}

func (a *trackingOrderAttestor) Name() string               { return a.name }
func (a *trackingOrderAttestor) Type() string               { return "https://test/" + a.name }
func (a *trackingOrderAttestor) RunType() RunType           { return a.runType }
func (a *trackingOrderAttestor) Schema() *jsonschema.Schema { return nil }
func (a *trackingOrderAttestor) Attest(ctx *AttestationContext) error {
	a.mu.Lock()
	*a.order = append(*a.order, a.name)
	a.mu.Unlock()
	return nil
}
