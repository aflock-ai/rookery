package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"time"
)

// newState returns a cryptographically random one-time verifier for the login
// flow. It binds the approve page to this exact loopback session so a forged
// POST to the callback (from a malicious local page or another process) can't
// inject an attacker-controlled token.
func newState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate login state: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// LoginParams carries the optional scope hints the caller (a human or, more
// commonly, an AI agent) supplies on the command line. They pre-fill the
// platform's approve page so nobody has to wrestle an interactive picker —
// authentication and scope selection stay separate concerns. All fields are
// optional; an empty field is simply omitted from the auth URL.
type LoginParams struct {
	Tenant  string // tenant id or name
	Product string // product id or name
	Purpose string // human-readable credential purpose
	// AllowTrust opts the session into the narrow oidc:write scope so it can
	// later run `cilock trust`. Off by default — registering CI trust is a
	// privileged action the user must explicitly request at login.
	AllowTrust bool
}

// BrowserLogin opens the TestifySec platform's /auth/cli page for the user to
// approve a cilock session credential. A loopback server receives the JWT via
// POST (keeping it out of URLs/history). The page is branded and scoped for
// cilock via client=cilock; scope hints (tenant/product/purpose) are passed
// through so the page can pre-fill rather than prompt.
func BrowserLogin(judgeURL string, params LoginParams) (*Credential, error) {
	judgeURL = NormalizeURL(judgeURL)
	state, err := newState()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port //nolint:errcheck // guaranteed *net.TCPAddr
	callbackURL := fmt.Sprintf("http://localhost:%d/callback", port)

	resultCh := make(chan *Credential, 1)
	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		_ = r.ParseForm()
		token := r.FormValue("token")
		// Reject any callback whose state doesn't match the one we minted for
		// this login. Constant-time compare avoids leaking the verifier via
		// timing. Without this a forged POST could persist a rogue token.
		if token != "" && subtle.ConstantTimeCompare([]byte(r.FormValue("state")), []byte(state)) != 1 {
			http.Error(w, "invalid state", http.StatusForbidden)
			return
		}
		if token != "" {
			resultCh <- &Credential{
				PlatformURL: judgeURL,
				Token:       token,
				TenantID:    r.FormValue("tenant_id"),
				TenantName:  r.FormValue("tenant"),
				ProductID:   r.FormValue("product_id"),
				ProductName: r.FormValue("product"),
				Email:       r.FormValue("email"),
				ExpiresAt:   time.Now().Add(30 * 24 * time.Hour),
			}
			w.Header().Set("Content-Type", "text/html")
			writeCallbackPage(w, r.FormValue("tenant"))
			return
		}
		http.Redirect(w, r, cliAuthURL(judgeURL, callbackURL, state, params), http.StatusFound)
	})

	go func() { _ = srv.Serve(listener) }()
	defer srv.Shutdown(context.Background()) //nolint:errcheck // best-effort cleanup

	loginURL := cliAuthURL(judgeURL, callbackURL, state, params)
	fmt.Printf("Opening browser to sign in to %s ...\n", judgeURL)
	fmt.Printf("If it doesn't open, visit:\n  %s\n\n", loginURL)
	openBrowserURL(loginURL)

	select {
	case c := <-resultCh:
		return c, nil
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("login timed out after 5 minutes")
	}
}

// writeCallbackPage renders the loopback success page shown after the platform
// POSTs the credential back. tenant is the only interpolated value; it is
// HTML-escaped because a crafted `tenant` form value on the callback could
// otherwise inject script into the page, and the loopback listener is reachable
// by any other local process — so the value is escaped to neutralize XSS.
func writeCallbackPage(w io.Writer, tenant string) {
	//nolint:gosec // G705: tenant is the only interpolation and is html-escaped; loopback-only, state-gated page
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8">`+
		`<style>body{font-family:-apple-system,system-ui,sans-serif;background:#1e1b4b;color:#e2e8f0;`+
		`display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}`+
		`.card{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.15);border-radius:16px;`+
		`padding:40px;max-width:400px;text-align:center}.ok{color:#34d399;font-size:48px}</style></head>`+
		`<body><div class="card"><div class="ok">&#x2713;</div><h2>cilock authorized</h2>`+
		`<p>Tenant: <strong>%s</strong></p><p style="color:#94a3b8">You can close this window.</p></div>`+
		`<script>setTimeout(function(){window.close()},3000)</script></body></html>`, html.EscapeString(tenant))
}

// cliAuthURL builds the /auth/cli URL. client=cilock scopes/brands the page;
// callback is the loopback the JWT is POSTed back to; state is the one-time
// verifier the approve page echoes back so the callback can reject forged
// POSTs; tenant/product/purpose are optional pre-fill hints. There is
// deliberately no repository parameter — cilock signing identity is the user,
// not a repo.
func cliAuthURL(judgeURL, callbackURL, state string, params LoginParams) string {
	q := url.Values{}
	q.Set("callback", callbackURL)
	q.Set("client", "cilock")
	q.Set("state", state)
	if params.Tenant != "" {
		q.Set("tenant", params.Tenant)
	}
	if params.Product != "" {
		q.Set("product", params.Product)
	}
	if params.Purpose != "" {
		q.Set("purpose", params.Purpose)
	}
	if params.AllowTrust {
		// The approve page reads this to pre-include the oidc:write scope, so the
		// minted session can register CI trust (`cilock trust`). The user still
		// sees and authorizes the scope in the browser.
		q.Set("allow_trust", "1")
	}
	return judgeURL + "/auth/cli?" + q.Encode()
}

func openBrowserURL(rawURL string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", rawURL) //nolint:gosec // G204: fixed opener binary; only the URL (built by cliAuthURL) varies
	default:
		cmd = exec.Command("open", rawURL) //nolint:gosec // G204: fixed opener binary; only the URL (built by cliAuthURL) varies
	}
	_ = cmd.Start()
}
