package auth

import (
	"context"
	"net/http"
	"time"
)

// The loopback servers (`cilock login`, `cilock enroll agent`) accept one
// browser POST from any local process that can reach the port. Two bounds
// keep an unfriendly local process from wedging the command:
//
//   - loopbackReadTimeout bounds the WHOLE request read — headers and body —
//     so a POST that sends its headers and then stalls mid-body does not hold
//     a handler open inside ParseForm. ReadHeaderTimeout alone bounded only
//     the headers, which is exactly the half a staller does not stall on.
//   - shutdownLoopback bounds the drain. http.Server.Shutdown with a
//     background context waits for every in-flight handler; with one wedged
//     handler that was forever, and it ran DEFERRED after the ceremony had
//     already delivered — so a successful enrollment never redeemed and a
//     timed-out one never returned. A short grace lets the genuine handler
//     finish writing its page; then whatever is still open is closed.
const (
	loopbackHeaderTimeout = 10 * time.Second
	loopbackReadTimeout   = 30 * time.Second
	loopbackDrainTimeout  = 3 * time.Second
)

// newLoopbackServer is the one place the loopback servers are configured, so
// the bounds above cannot be forgotten by one of them.
func newLoopbackServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: loopbackHeaderTimeout,
		ReadTimeout:       loopbackReadTimeout,
	}
}

// shutdownLoopback drains for at most loopbackDrainTimeout, then closes every
// remaining connection. Returns quickly whatever a local process is doing to
// the port.
func shutdownLoopback(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), loopbackDrainTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		_ = srv.Close()
	}
}
