package auth

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A local process that opens the loopback port, sends a POST's headers with
// a Content-Length, and then never sends the body used to hold the handler
// inside ParseForm — and the deferred Shutdown(context.Background()) then
// waited for that handler forever, after the real callback had already
// delivered. The command never returned and the credential was never
// redeemed. Codex, round 10.

// stalledPost opens a connection and sends only the headers of a POST that
// promises a body it never sends.
func stalledPost(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	_, err = fmt.Fprintf(conn, "POST /callback HTTP/1.1\r\nHost: %s\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4096\r\n\r\nsealed_credential=", addr)
	require.NoError(t, err)
	return conn
}

func TestShutdownLoopbackReturnsDespiteAStalledRequest(t *testing.T) {
	entered := make(chan struct{}, 1)
	srv := newLoopbackServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		_ = r.ParseForm() // blocks on the body the staller never sends
		w.WriteHeader(http.StatusOK)
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = srv.Serve(ln) }()

	conn := stalledPost(t, ln.Addr().String())
	defer conn.Close()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never saw the stalled request")
	}

	start := time.Now()
	shutdownLoopback(srv)
	assert.Less(t, time.Since(start), loopbackDrainTimeout+2*time.Second, "shutdown must be bounded by the drain grace, not by the staller")
}

func TestLoopbackReadTimeoutBoundsTheBody(t *testing.T) {
	// Independently of the drain: the stalled request itself ends when the
	// read timeout fires, so a handler is never held longer than that even
	// while the ceremony is still waiting for the genuine callback.
	assert.Greater(t, loopbackReadTimeout, loopbackHeaderTimeout, "the whole-request bound covers the headers bound")
	srv := newLoopbackServer(http.NotFoundHandler())
	assert.Equal(t, loopbackReadTimeout, srv.ReadTimeout)
	assert.Equal(t, loopbackHeaderTimeout, srv.ReadHeaderTimeout)
}

func readSourceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	require.NoError(t, err)
	return string(b)
}

func TestBothLoopbackServersAreBuiltByTheOneConstructor(t *testing.T) {
	// The bounds live in one function so neither ceremony can lose them. A
	// grep-shaped assertion, executed: the two files must not build a
	// bare http.Server any more.
	for _, f := range []string{"agentenroll.go", "browser.go"} {
		assert.NotContains(t, readSourceFile(t, f), "&http.Server{", f)
		assert.Contains(t, readSourceFile(t, f), "newLoopbackServer(", f)
		assert.Contains(t, readSourceFile(t, f), "shutdownLoopback(", f)
	}
}
