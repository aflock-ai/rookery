package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
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
	// PushgateOrigin is the Pushgate origin platform discovery advertises
	// (scheme://host), or "" for none. The success page then names Pushgate
	// as the next step.
	PushgateOrigin string
}

// BrowserLogin opens the TestifySec platform's /auth/cli page for the user to
// approve a cilock session credential. A loopback server receives the JWT via
// POST (keeping it out of URLs/history). The page is branded and scoped for
// cilock via client=cilock; scope hints (tenant/product/purpose) are passed
// through so the page can pre-fill rather than prompt.
func BrowserLogin(judgeURL string, params LoginParams) (*Credential, error) {
	if InCI(os.Getenv) {
		return nil, ErrBrowserInCI
	}
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
	srv := newLoopbackServer(mux) // bounded read and drain: loopback.go

	mux.HandleFunc("/callback", loginCallbackHandler(judgeURL, state, params.PushgateOrigin, resultCh))

	go func() { _ = srv.Serve(listener) }()
	defer shutdownLoopback(srv)

	loginURL := cliAuthURL(judgeURL, callbackURL, state, params)
	fmt.Printf("Opening browser to sign in to %s ...\n", judgeURL)
	opened := openBrowserURL(loginURL)
	fmt.Print(ceremonyInvitation("sign in", loginURL, opened))

	select {
	case c := <-resultCh:
		return c, nil
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("login timed out after 5 minutes")
	}
}

// loginCallbackHandler is `cilock login`'s loopback endpoint. Extracted from
// BrowserLogin for the same reason enrollCallbackHandler was extracted from
// BrowserEnroll: buried in a server closure, the only way to reach these
// decisions was a live browser ceremony, and a guard nothing can exercise is a
// guard nothing can trust.
//
// It is the enrollment callback's decisions, in the same refusal-first order,
// because it is the same loopback under the same threat — every local process
// on the machine — and the three defects below were live here after being
// closed there (#8739):
//
//   - A NON-POST REQUEST IS NOT A DELIVERY. ParseForm folds the query string in
//     for a GET, so a GET carrying `token` and `state` in its URL used to be
//     accepted — and a URL is the one shape a session token must never travel
//     in: it lands in shell history, browser history and every proxy log.
//   - A CREDENTIAL-LESS REQUEST LEAKS NOTHING. It used to be answered with a
//     302 to the approve page, whose `Location` carries `state`, so any local
//     process could GET the loopback, read the verifier out of the redirect,
//     and POST a forged token that then passed the constant-time compare. Now
//     it is a bare 405 with no body and no Location — the listener still
//     answers, which is all a liveness probe needs.
//   - ONE VALID CALLBACK ENDS THE FLOW. There was no single-shot at all here,
//     so a racing or replayed POST overwrote what the browser had just
//     delivered. A second callback is refused 409 and examined no further.
func loginCallbackHandler(judgeURL, state, pushgateOrigin string, resultCh chan<- *Credential) http.HandlerFunc {
	var consumed atomic.Bool
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			refuseLoopbackProbe(w)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		// A ParseForm error is deliberately not inspected: it fails CLOSED.
		// Every FormValue then returns "", so an oversized or malformed body
		// falls into the credential-less path rather than reaching a decision.
		_ = r.ParseForm()
		token := r.FormValue("token")
		if token == "" {
			refuseLoopbackProbe(w)
			return
		}
		// Reject any callback whose state doesn't match the one we minted for
		// this login. Constant-time compare avoids leaking the verifier via
		// timing. Without this a forged POST could persist a rogue token.
		if subtle.ConstantTimeCompare([]byte(r.FormValue("state")), []byte(state)) != 1 {
			http.Error(w, "invalid state", http.StatusForbidden)
			return
		}
		// The flow is spent. Refuse BEFORE reading anything else off the
		// request: a delivered ceremony is examined against nothing further.
		if !consumed.CompareAndSwap(false, true) {
			http.Error(w, flowAlreadyDelivered, http.StatusConflict)
			return
		}
		resultCh <- newBrowserCredential(judgeURL, token, map[string]string{
			"tenant_id":  r.FormValue("tenant_id"),
			"tenant":     r.FormValue("tenant"),
			"product_id": r.FormValue("product_id"),
			"product":    r.FormValue("product"),
			"email":      r.FormValue("email"),
		})
		w.Header().Set("Content-Type", "text/html")
		writeCallbackPage(w, r.FormValue("tenant"), pushgateOrigin)
	}
}

// flowAlreadyDelivered is the one refusal both ceremonies give a second
// callback. It is DISTINCT from every other refusal on the port (403 wrong
// state, 400 unreadable payload) so an operator reading a terminal can tell
// "someone raced this ceremony" from "someone guessed at it" — and it says
// nothing a caller could not already infer from having been first or second.
const flowAlreadyDelivered = "this ceremony has already delivered its credential"

// refuseLoopbackProbe is the answer to anything that is not a credential
// delivery: a bare 405 with NO body, NO Location and NO echo. Both loopbacks
// share it so neither can drift into answering a probe with something the
// probe did not already have.
func refuseLoopbackProbe(w http.ResponseWriter) {
	w.Header().Set("Allow", http.MethodPost)
	http.Error(w, "", http.StatusMethodNotAllowed)
}

// secretCeremonyParams names the ceremony-URL query parameters that AUTHORIZE
// rather than describe. Everything else in the URL — the platform, the
// loopback port, the pre-fill hints — is discoverable or harmless.
var secretCeremonyParams = []string{"state", "seal_pub"}

// redactedParam is what a withheld parameter renders as. It is deliberately
// not a plausible value: a human who pastes this URL gets the page's "Invalid
// Request" card, not a ceremony that half-works.
const redactedParam = "REDACTED"

// redactCeremonyURL rewrites a ceremony URL for HUMAN EYES, replacing every
// authorizing parameter with a placeholder. A URL that will not parse is
// truncated at its query string rather than echoed: printing a value we could
// not read is exactly how a secret escapes.
func redactCeremonyURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexByte(raw, '?'); i >= 0 {
			return raw[:i]
		}
		return raw
	}
	q := u.Query()
	for _, k := range secretCeremonyParams {
		if q.Has(k) {
			q.Set(k, redactedParam)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ceremonyInvitation is the block a browser ceremony prints AFTER it has tried
// to open a browser, and the printing side of #8739.
//
// THE VERIFIER IS NOT PRINTED WHILE A BROWSER HOLDS IT. The ceremony URL
// carries everything the loopback callback checks — `state` for both
// ceremonies, and `seal_pub` too for enrollment. A local process that reads
// this output therefore holds the whole inbound check: it can seal a
// credential of its own to the published recipient key with the published
// state bound in, POST it before the human finishes approving, and spend the
// one-shot. The callback cannot tell that POST from the platform's, because
// every value it compares is in it. So the fix is here: when a browser already
// has the URL, the parts that AUTHORIZE are withheld from the terminal, and
// what prints is enough to recognize the ceremony and nothing more.
//
// When NOTHING opened, the whole URL prints. That output is then the only
// channel to the human (and to the UAT harness, which sets BROWSER=none and
// reads the first URL line) — withholding it there would not be a control, it
// would be a ceremony that cannot be completed. `verb` names what the reader
// does there, which differs per ceremony.
//
// RESIDUAL, stated rather than claimed away: a process that can read this
// process's MEMORY, or re-run the command with BROWSER=none, still obtains the
// verifier. Same-UID isolation is not what this closes; it closes the
// verifier's escape into transcripts, logs and scrollback, which outlive the
// ceremony and are read by things that were never on this machine.
func ceremonyInvitation(verb, ceremonyURL string, browserOpened bool) string {
	if !browserOpened {
		return fmt.Sprintf("Nothing opened a browser — %s at:\n  %s\n\n"+
			"That URL carries this ceremony's one-time verifier. Paste it into a browser you\n"+
			"trust and nowhere else.\n\n", verb, ceremonyURL)
	}
	return fmt.Sprintf("The ceremony is at:\n  %s\n\n"+
		"Its authorizing parameters are withheld on purpose: anything that can read them —\n"+
		"another local process, a saved transcript, a log — can deliver a credential of its\n"+
		"own before the browser does. If no browser came up, re-run with BROWSER=none and\n"+
		"copy the whole URL from a terminal only you can read.\n\n",
		redactCeremonyURL(ceremonyURL))
}

// defaultSessionTTL bounds a session credential whose JWT carries no `exp`
// claim. It is a fallback only — when the token declares an `exp`, that real
// server-side expiry wins (see newBrowserCredential / TokenCredential). Without
// an `exp`, gating on a bounded window is still safer than treating the token
// as valid forever.
const defaultSessionTTL = 30 * 24 * time.Hour

// sessionTTL resolves the fallback window applied to an exp-less session token.
// Operators can shorten (or lengthen) it via CILOCK_SESSION_TTL, a Go duration
// string (e.g. "24h", "168h"). An unset, empty, unparseable, or non-positive
// value falls back to defaultSessionTTL — a bad knob never weakens the bound by
// accident, it just reverts to the safe default.
func sessionTTL() time.Duration {
	if v := os.Getenv("CILOCK_SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultSessionTTL
}

// newBrowserCredential builds the session credential the loopback callback
// stores. ExpiresAt is taken from the token's own `exp` claim so a
// server-expired token is recognized as expired client-side; only when the
// token carries no decodable `exp` does it fall back to a bounded default
// window (defaultSessionTTL) rather than the previous unconditional now+30d
// that ignored the real expiry entirely (GHSA #5991). form supplies the
// tenant/product/email values the approve page POSTs back.
func newBrowserCredential(judgeURL, token string, form map[string]string) *Credential {
	expiresAt := time.Now().Add(sessionTTL())
	if exp, ok := tokenExp(token); ok {
		expiresAt = exp
	}
	return &Credential{
		PlatformURL: judgeURL,
		Token:       token,
		TenantID:    form["tenant_id"],
		TenantName:  form["tenant"],
		ProductID:   form["product_id"],
		ProductName: form["product"],
		Email:       form["email"],
		ExpiresAt:   expiresAt,
	}
}

// writeCallbackPage renders the loopback success page shown after the platform
// POSTs the credential back. tenant is the only interpolated value; it is
// HTML-escaped because a crafted `tenant` form value on the callback could
// otherwise inject script into the page, and the loopback listener is reachable
// by any other local process — so the value is escaped to neutralize XSS.
func writeCallbackPage(w io.Writer, tenant, pushgateOrigin string) {
	page := callbackPage{
		Title: "Cilock authorized", Heading: "Cilock authorized",
		Label: "Tenant", Value: tenant,
		Message: "The platform sent your sign-in credential to Cilock. Return to your terminal to continue.",
		Next:    FirstRunCommand,
	}
	if pushgateOrigin != "" {
		page.Connect, page.PushgateURL, page.Prompt = PushgateConnectLine(pushgateOrigin), pushgateOrigin+"/", PushgateAgentPrompt(pushgateOrigin)
	}
	writeCilockCallbackPage(w, page)
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

// openBrowserURL launches the ceremony page and REPORTS WHETHER IT DID. The
// bool is load-bearing, not informational: the ceremony URL carries this
// flow's one-time verifier, so it is printed in full only when nothing opened
// it — the one case where a human has no other way to reach the page.
func openBrowserURL(rawURL string) bool {
	// BROWSER=none is the conventional way to say "print the URL, do not open
	// anything" — a harness that drives its own browser (the UAT lane) sets
	// it so the ceremony URL goes only where the harness reads it. Any other
	// value of $BROWSER is deliberately not honoured as an opener: it would be
	// an executable name taken from the environment.
	if os.Getenv("BROWSER") == "none" {
		return false
	}
	if !openableURL(rawURL) {
		return false
	}
	name, args := openerCommand(runtime.GOOS, rawURL)
	cmd := exec.Command(name, args...) //nolint:gosec // G204: fixed opener binary per GOOS (openerCommand); only the URL (built by cliAuthURL) varies
	// Start, not Run: the opener is fire-and-forget. A failure to START (no
	// opener binary on this machine) is the honest "nothing opened" signal;
	// what the browser does afterwards is not observable from here, which is
	// why the printed text tells the human how to recover rather than
	// claiming a browser is up.
	return cmd.Start() == nil
}

// openableURL admits only an absolute http(s) URL with a host. The openers are
// not URL-only: rundll32 FileProtocolHandler, macOS `open` and xdg-open all
// launch a local path, an app bundle or a file: URL they are handed, and an
// argument beginning with `-` is read as an option. OpenURL takes any string,
// so this gate sits in front of every platform's opener; a refused value
// reports "nothing opened" and the caller prints it instead.
func openableURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// openerCommand is the argv that opens rawURL on goos. It is pure so the
// per-platform choice is testable on any OS without launching anything.
func openerCommand(goos, rawURL string) (name string, args []string) {
	switch goos {
	case "linux":
		return "xdg-open", []string{rawURL}
	case "windows":
		// rundll32 hands the URL to the default protocol handler as one argv
		// element. `cmd /c start` would not: cmd.exe splits its command line
		// at `&`, so every query parameter after the first (state, the
		// verifier) would be cut off the ceremony URL.
		return "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		return "open", []string{rawURL}
	}
}

// OpenURL opens a page that carries no secret (a review link) and reports
// whether an opener started. BROWSER=none suppresses it, as for the ceremonies.
func OpenURL(rawURL string) bool { return openBrowserURL(rawURL) }
