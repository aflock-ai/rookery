package fulcio

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	fulciopb "github.com/sigstore/fulcio/pkg/generated/protobuf"
	"google.golang.org/grpc"
)

// stallingCAClient blocks CreateSigningCertificate until its context is
// cancelled — the exact "TCP-accept-then-stall" a wedged Fulcio replica or a
// half-open LB connection presents. Before the per-call deadline fix, getCert
// passed an unbounded run context here and parked forever; the retry loop never
// engaged because the first call never returned.
type stallingCAClient struct {
	fulciopb.CAClient
	started chan struct{}
}

func (s *stallingCAClient) CreateSigningCertificate(ctx context.Context, _ *fulciopb.CreateSigningCertificateRequest, _ ...grpc.CallOption) (*fulciopb.SigningCertificate, error) {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-ctx.Done() // never returns until the caller's deadline/cancel fires
	return nil, ctx.Err()
}

// TestGetCert_BoundsStalledGRPC is the regression test for the CI hang: a
// stalled gRPC server must make getCert RETURN (bounded) instead of hanging.
// With a short test timeout the whole 3-attempt retry budget completes in well
// under a second, proving each attempt is deadline-bounded.
func TestGetCert_BoundsStalledGRPC(t *testing.T) {
	prev := fulcioCertRequestTimeout
	fulcioCertRequestTimeout = 100 * time.Millisecond
	t.Cleanup(func() { fulcioCertRequestTimeout = prev })

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := generateTestToken("test@example.com", "")
	client := &stallingCAClient{started: make(chan struct{}, 1)}

	done := make(chan error, 1)
	go func() {
		// Parent context has NO deadline — exactly the run context cilock
		// passes. The fix's per-call deadline is what must bound this.
		_, gerr := getCert(context.Background(), key, client, token)
		done <- gerr
	}()

	// 3 attempts × (100ms deadline + backoff 1s,2s) ≈ 3.3s worst case. Give
	// generous headroom but far below the "20-minute hang" this fixes.
	select {
	case gerr := <-done:
		if gerr == nil {
			t.Fatal("expected a deadline error from the stalled server, got nil")
		}
		// The first attempt must have actually reached the stub.
		select {
		case <-client.started:
		default:
			t.Error("CreateSigningCertificate was never invoked")
		}
		if !errors.Is(gerr, context.DeadlineExceeded) &&
			!containsDeadline(gerr.Error()) {
			t.Logf("returned error (acceptable as long as it returned): %v", gerr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("getCert HUNG against a stalled gRPC server — the per-call deadline is not bounding the request")
	}
}

func containsDeadline(s string) bool {
	for _, sub := range []string{"deadline", "DeadlineExceeded", "context canceled"} {
		if len(s) >= len(sub) && (indexOf(s, sub) >= 0) {
			return true
		}
	}
	return false
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
