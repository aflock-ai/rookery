// jade:ring local

package auth

import (
	"bytes"
	"html"
	"strings"
	"testing"
)

func TestCallbackPagesShareAccessibleEscapedShell(t *testing.T) {
	payload := strings.Repeat("long-name", 80) + `<img src=x onerror="alert(1)"><script>bad()</script>`
	for _, tc := range []struct {
		name, title string
		render      func(*bytes.Buffer)
	}{
		{"login", "Cilock authorized", func(w *bytes.Buffer) { writeCallbackPage(w, payload) }},
		{"enrollment", "Agent credential received", func(w *bytes.Buffer) { writeEnrollCallbackPage(w, payload, payload) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			tc.render(&out)
			page := out.String()
			for _, want := range []string{
				`<html lang="en">`, `<meta name="viewport" content="width=device-width, initial-scale=1">`,
				"<title>" + tc.title + " · Cilock</title>", `<main class="card" aria-labelledby="callback-heading">`,
				`<h1 id="callback-heading">` + tc.title + `</h1>`, `<p role="status">`,
				`id="close-window">Close window</button>`, "close this tab and return to your terminal",
				"setTimeout(closeWindow,3000)", "addEventListener('click',closeWindow)",
				"prefers-color-scheme:dark", "padding:24px", "overflow-wrap:anywhere", "min-height:44px", "button:focus-visible",
				html.EscapeString(payload),
			} {
				if !strings.Contains(page, want) {
					t.Errorf("rendered page is missing %q", want)
				}
			}
			if strings.Contains(page, payload) || strings.Count(page, "<script>") != 1 || strings.Contains(page, "<img") {
				t.Fatal("callback data injected active markup")
			}
		})
	}
}

func TestEnrollmentCallbackDoesNotClaimActivation(t *testing.T) {
	var out bytes.Buffer
	writeEnrollCallbackPage(&out, "", "agent-id")
	page := out.String()
	for _, forbidden := range []string{"Agent enrolled", "now signs", "successfully activated"} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("receipt page claimed redemption: %q", forbidden)
		}
	}
	if !strings.Contains(page, "Agent: <strong>agent</strong>") ||
		!strings.Contains(page, "<code>agent/agent-id</code>") ||
		!strings.Contains(page, "Cilock will confirm enrollment after activating the credential with the platform.") {
		t.Fatal("page must show the received identity and leave activation confirmation to Cilock")
	}
}
