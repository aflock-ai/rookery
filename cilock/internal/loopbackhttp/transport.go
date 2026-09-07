// Package loopbackhttp keeps local CLI connections independent of host DNS.
package loopbackhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

// Install must run before requests or background workers start. Only the dial
// target changes: URL, Host, proxy selection, TLS SNI/verification and issuer
// comparisons remain untouched. RFC 6761 section 6.3 reserves localhost for
// loopback even when a sandbox cannot read hosts files or query system DNS.
func Install() error {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return errors.New("localhost transport requires the standard HTTP transport")
	}
	http.DefaultTransport = transport(base)
	return nil
}

func transport(base *http.Transport) *http.Transport {
	result := base.Clone()
	dial := result.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	result.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") ||
			(network != "tcp" && network != "tcp4" && network != "tcp6") {
			return dial(ctx, network, address)
		}
		if network == "tcp6" {
			return dial(ctx, network, net.JoinHostPort("::1", port))
		}
		conn, err := dial(ctx, network, net.JoinHostPort("127.0.0.1", port))
		if err == nil || network == "tcp4" || ctx.Err() != nil {
			return conn, err
		}
		return dial(ctx, network, net.JoinHostPort("::1", port))
	}
	return result
}
