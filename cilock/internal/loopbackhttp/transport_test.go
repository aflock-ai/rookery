// jade:ring local
package loopbackhttp

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalhostDialOnly(t *testing.T) {
	for _, tc := range []struct {
		network, address string
		want             []string
	}{
		{"tcp", "localhost:80", []string{"127.0.0.1:80", "[::1]:80"}},
		{"tcp", "LOCALHOST.:443", []string{"127.0.0.1:443", "[::1]:443"}},
		{"tcp4", "localhost:80", []string{"127.0.0.1:80"}},
		{"tcp6", "localhost:80", []string{"[::1]:80"}},
		{"tcp", "localhost.example:80", []string{"localhost.example:80"}},
		{"tcp", "example.localhost:80", []string{"example.localhost:80"}},
		{"tcp", "127.0.0.2:80", []string{"127.0.0.2:80"}},
		{"tcp", "invalid-address", []string{"invalid-address"}},
		{"unix", "localhost:80", []string{"localhost:80"}},
	} {
		t.Run(tc.network+tc.address, func(t *testing.T) {
			var got []string
			base := &http.Transport{DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
				require.Equal(t, tc.network, network)
				got = append(got, address)
				return nil, errors.New("connection refused")
			}}
			_, err := transport(base).DialContext(context.Background(), tc.network, tc.address)
			require.Error(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestHTTPPreservesLogicalHostAndNeverResolvesLocalhost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Host, "localhost:") {
			t.Errorf("logical request host changed: %q", r.Host)
		}
		_, _ = io.WriteString(w, "local")
	}))
	defer server.Close()
	base := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		require.NoError(t, err)
		require.NotNil(t, net.ParseIP(host), "dialer must receive an IP, not a DNS name")
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	tr := transport(base)
	defer tr.CloseIdleConnections()
	response, err := (&http.Client{Transport: tr}).Get(strings.Replace(server.URL, "127.0.0.1", "localhost", 1))
	require.NoError(t, err)
	defer response.Body.Close()
	bytes, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, "local", string(bytes))
}

func TestCanceledDialDoesNotTrySecondAddress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	tr := transport(&http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		calls++
		cancel()
		return nil, context.Canceled
	}})
	_, err := tr.DialContext(ctx, "tcp", "localhost:80")
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, calls)
}

func TestTLSStillRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("untrusted request reached handler")
	}))
	defer server.Close()
	tr := transport(&http.Transport{})
	defer tr.CloseIdleConnections()
	response, err := (&http.Client{Transport: tr}).Get(strings.Replace(server.URL, "127.0.0.1", "localhost", 1))
	if response != nil {
		require.NoError(t, response.Body.Close())
	}
	require.Error(t, err)
	require.Contains(t, err.Error(), "certificate")
	require.False(t, tr.TLSClientConfig.InsecureSkipVerify)
}

func TestTLSChecksLogicalHostnameEvenWithTrustedRoot(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "trusted IP endpoint")
	}))
	defer server.Close()
	base, ok := server.Client().Transport.(*http.Transport)
	require.True(t, ok)
	tr := transport(base)
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	positive, err := client.Get(server.URL)
	require.NoError(t, err, "the certificate is trusted for its IP SAN")
	require.NoError(t, positive.Body.Close())
	response, err := client.Get(strings.Replace(server.URL, "127.0.0.1", "localhost", 1))
	if response != nil {
		require.NoError(t, response.Body.Close())
	}
	var hostnameError x509.HostnameError
	require.ErrorAs(t, err, &hostnameError)
	require.Equal(t, "localhost", hostnameError.Host)
}
