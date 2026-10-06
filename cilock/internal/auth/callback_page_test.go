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
		{"login", "Cilock authorized", func(w *bytes.Buffer) { writeCallbackPage(w, payload, "https://pushgate.dev") }},
		{"login-no-pushgate", "Cilock authorized", func(w *bytes.Buffer) { writeCallbackPage(w, payload, "") }},
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
				"addEventListener('click',closeWindow)",
				"prefers-color-scheme:dark", "padding:24px", "overflow-wrap:anywhere", "min-height:44px", "button:focus-visible",
				html.EscapeString(payload),
			} {
				if !strings.Contains(page, want) {
					t.Errorf("rendered page is missing %q", want)
				}
			}
			// The page stays up until the user closes it: it carries the next
			// command to run, and a tab that closes itself after 3s takes that
			// instruction with it.
			if strings.Contains(page, "setTimeout") {
				t.Error("callback page must not close itself")
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

// When the platform advertises Pushgate, the loopback page sends the human
// there and hands them the agent prompt with a copy button; `cilock run` is the
// fallback.
func TestLoginCallbackPointsAtPushgate(t *testing.T) {
	var out bytes.Buffer
	writeCallbackPage(&out, "acme", "https://pushgate.dev")
	page := out.String()
	connect := strings.Index(page, html.EscapeString(PushgateConnectLine("https://pushgate.dev"))+` <a href="https://pushgate.dev/">`)
	prompt := strings.Index(page, `<pre class="prompt" id="agent-prompt">`+html.EscapeString(PushgateAgentPrompt("https://pushgate.dev"))+`</pre>`)
	copyButton := strings.Index(page, `<button type="button" id="copy-prompt">Copy prompt</button>`)
	run := strings.Index(page, `Or attest a build directly:</p><code class="next">`+html.EscapeString(FirstRunCommand))
	if connect < 0 || prompt < 0 || copyButton < 0 || run < 0 || connect > prompt || prompt > copyButton || copyButton > run {
		t.Fatalf("want connect line, prompt, copy button, then the cilock run fallback:\n%s", page)
	}
	if !strings.Contains(page, "navigator.clipboard.writeText(document.getElementById('agent-prompt').textContent)") {
		t.Fatal("copy button must copy the prompt block")
	}
}

// The prompt is Pushgate's own connect-page sentence plus its install consent,
// so an agent meets the same contract wording wherever it starts. It asks; it
// never connects or activates anything itself. This text is quoted in
// customer email, so changing it is a deliberate act.
func TestPushgateNextStepText(t *testing.T) {
	const want = "Fetch and execute the instructions to set this repository up for gated pushes from https://pushgate.dev/agent-setup/prompt.md\n" +
		"You may install or upgrade cilock to the release those instructions require, using only the install command they print; ask me before installing anything else."
	if got := PushgateAgentPrompt("https://pushgate.dev"); got != want {
		t.Fatalf("PushgateAgentPrompt = %q", got)
	}
	if got := PushgateConnectLine("https://pushgate.dev"); got != "Next: connect a repository at https://pushgate.dev/ to gate its pushes." {
		t.Fatalf("PushgateConnectLine = %q", got)
	}
}

func TestLoginCallbackNamesTheFirstRun(t *testing.T) {
	var out bytes.Buffer
	writeCallbackPage(&out, "acme", "")
	if want := html.EscapeString(FirstRunCommand); !strings.Contains(out.String(), `<code class="next">`+want+`</code>`) {
		t.Fatalf("login callback page does not show %q:\n%s", FirstRunCommand, out.String())
	}
	if strings.Contains(out.String(), "pushgate") {
		t.Fatal("with no advertised Pushgate the page must not name one")
	}
	out.Reset()
	writeEnrollCallbackPage(&out, "", "agent-id")
	if strings.Contains(out.String(), "cilock run") {
		t.Fatal("agent enrollment receipt must not suggest a human first run")
	}
}
