package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRefusalNeverEchoesTheCredentialBack pins that a server reflecting its own
// request body cannot leak the refresh credential through cilock's error.
//
// The exchange reports the server's refusal verbatim on purpose — the platform's
// message is the only thing telling an operator what happened. But the request
// body carries a long-lived bearer, and an endpoint that is broken,
// misconfigured, or hostile can echo its input straight back. Without redaction
// that echo lands in a terminal and a log, turning one bad response into a
// durable credential disclosure by way of code trying to be helpful.
//
// Each case is a realistic shape of the same accident: a handler that includes
// what it received in what it returns.
func TestRefusalNeverEchoesTheCredentialBack(t *testing.T) {
	cred := bindingCred("")
	secret := cred.RefreshCredential

	bodies := map[string]string{
		"plain echo":           "rejected credential " + secret,
		"json echo of request": `{"error":"invalid","received":{"refresh_credential":"` + secret + `"}}`,
		"echo inside a stack":  "handler panic: token=" + secret + " at line 12",
		"repeated twice":       secret + " and again " + secret,
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			_, err := ExchangeAgentCredential(srv.URL, bindingCred(srv.URL))
			if err == nil {
				t.Fatal("a non-200 must be an error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the refresh credential was echoed back and reached the error: %q", err)
			}
			// The server's message must still be USEFUL — redaction that swallows
			// the whole body would leave an operator with nothing to act on.
			if !strings.Contains(err.Error(), "redacted") {
				t.Fatalf("the redaction must be visible so a reader knows text was removed: %q", err)
			}
		})
	}
}

// THE ECHO THAT DEFEATS A LITERAL-ONLY REDACTION: the credential does not go
// onto the wire as itself.
//
// The test above echoes the raw secret, which a literal match catches. But the
// request is JSON, and encoding/json REWRITES the value on the way out — it
// escapes quotes and backslashes structurally, control characters numerically,
// and by default HTML-escapes "<", ">" and "&" into <, >, &. So
// the bytes a reflecting server receives, and therefore the bytes it echoes,
// are NOT the bytes redaction was told to look for. A literal ReplaceAll walks
// straight past them and the secret reaches a terminal and a log.
//
// This drives the real path rather than a hand-built string: the handler echoes
// exactly what it received, so whatever encoding the client genuinely applied
// is what comes back. If the request encoding ever changes, this test follows
// it instead of asserting a stale spelling.
func TestRefusalCannotLeakTheCredentialThroughItsJSONEscaping(t *testing.T) {
	// Every class encoding/json rewrites: HTML escapes, structural escapes, and
	// a control character.
	const nasty = "s3cret<value>&more\"quoted\\slash\u0001ctrl"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16)) //nolint:errcheck // echoing whatever arrived is the point
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(append([]byte("rejected, you sent: "), received...))
	}))
	defer srv.Close()

	cred := bindingCred(srv.URL)
	cred.RefreshCredential = nasty

	_, err := ExchangeAgentCredential(srv.URL, cred)
	if err == nil {
		t.Fatal("a non-200 must be an error")
	}

	// The literal form — already covered before this test existed.
	if strings.Contains(err.Error(), nasty) {
		t.Fatalf("the literal credential reached the error: %q", err)
	}

	quoted, merr := json.Marshal(nasty)
	if merr != nil {
		t.Fatal(merr)
	}
	wire := string(quoted[1 : len(quoted)-1]) // drop the surrounding quotes

	// GUARD AGAINST A VACUOUS PASS. If json.Marshal ever stopped rewriting this
	// value, the wire form would equal the literal, the assertion below would be
	// a duplicate of the one above, and this test would report success while
	// testing nothing.
	if wire == nasty {
		t.Fatalf("this test is vacuous: json.Marshal did not rewrite %q", nasty)
	}

	if strings.Contains(err.Error(), wire) {
		t.Fatalf("the JSON-escaped credential survived redaction and reached the error.\n"+
			"wire form: %q\nerror: %q", wire, err)
	}
}

// TestRefusalKeepsTheServersMessageWhenItHoldsNoSecret is the control: without
// it, the test above would pass on an implementation that discarded every
// server message, which would destroy the diagnosability the verbatim report
// exists to provide.
func TestRefusalKeepsTheServersMessageWhenItHoldsNoSecret(t *testing.T) {
	const serverSays = "agent principal is revoked"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(serverSays))
	}))
	defer srv.Close()

	_, err := ExchangeAgentCredential(srv.URL, bindingCred(srv.URL))
	if err == nil {
		t.Fatal("a non-200 must be an error")
	}
	if !strings.Contains(err.Error(), serverSays) {
		t.Fatalf("a message with no secret in it must survive verbatim, got %q", err)
	}
}

// TestRedactCredentialIsNotDefeatedByPositionOrCount exercises the helper
// directly, including the empty-credential case a caller could hit before
// enrollment completes.
func TestRedactCredentialIsNotDefeatedByPositionOrCount(t *testing.T) {
	cred := bindingCred("")
	s := cred.RefreshCredential

	for name, in := range map[string]string{
		"at the start": s + " trailing",
		"at the end":   "leading " + s,
		"alone":        s,
		"three times":  fmt.Sprintf("%s|%s|%s", s, s, s),
	} {
		t.Run(name, func(t *testing.T) {
			if got := redactCredential(in, cred); strings.Contains(got, s) {
				t.Fatalf("redactCredential left the secret in %q", got)
			}
		})
	}

	t.Run("an empty credential redacts nothing", func(t *testing.T) {
		empty := AgentCredential{}
		const text = "some server message"
		if got := redactCredential(text, empty); got != text {
			t.Fatalf("an empty credential must leave text untouched, got %q", got)
		}
	})
}

// TestNoResponseDerivedErrorCarriesTheCredential is the GENERAL form of the
// test above, and it exists because the specific one was not enough.
//
// The refusal body was the obvious way a server hands the credential back, and
// closing only that left three others open — every one of them a place where an
// error message quotes server-controlled text in order to be diagnosable:
//
//   - a REDIRECT, where Location is chosen entirely by the server, and
//     url.URL.Redacted() masks userinfo while leaving the QUERY intact;
//   - a successful HTTP 200 whose `spiffe_id` does not match the credential,
//     quoted verbatim by the mismatch error;
//   - a successful 200 whose JWT `sub` does not match, likewise quoted.
//
// Each case puts the secret exactly where that path would read it, so the test
// fails if the redaction ever stops covering the boundary rather than only the
// site that was patched first.
func TestNoResponseDerivedErrorCarriesTheCredential(t *testing.T) {
	cred := bindingCred("")
	secret := cred.RefreshCredential

	// A token whose `sub` claim is the secret: a 200 that is internally
	// consistent enough to reach the subject check.
	subClaim := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + secret + `"}`))
	tokenWithSecretSubject := "h." + subClaim + ".s"

	handlers := map[string]http.HandlerFunc{
		"redirect with the credential in the query": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example.com/?credential="+secret, http.StatusTemporaryRedirect)
		},
		"200 with the credential in spiffe_id": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token": "h.e30.s", "token_type": "Bearer",
				"spiffe_id": "spiffe://judge.testifysec.com/tenant/" + secret + "/agent/x",
			})
		},
		"200 with the credential in the token subject": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token": tokenWithSecretSubject, "token_type": "Bearer",
				"spiffe_id": "spiffe://judge.testifysec.com/tenant/" + cred.TenantID + "/agent/" + cred.AgentID,
			})
		},
	}

	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()

			_, err := ExchangeAgentCredential(srv.URL, bindingCred(srv.URL))
			if err == nil {
				t.Fatal("a response that does not name the enrolled principal must be an error")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("the refresh credential reached the error text: %q", err)
			}
		})
	}
}

// jsonBody is unused by the cases above but documents the shape a real handler
// would return; kept out of the table so the table stays readable.
var _ = json.Marshal
