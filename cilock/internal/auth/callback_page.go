package auth

import (
	"html/template"
	"io"
)

// Callback pages display receipt of a credential, not successful redemption.
// All data remains plain strings escaped by html/template; no credential,
// state, return URL, or caller-controlled markup belongs in this presentation.
type callbackPage struct {
	Title, Heading, Label, Value, Identity, Message string
	// The next steps after a login, built in this package from the Pushgate
	// origin platform discovery advertises; never callback form data. Connect
	// and Prompt are empty when the platform advertises no Pushgate.
	Connect, PushgateURL, Prompt, Next string
}

// The next steps after a human `cilock login`. The login output, this callback
// page and the web /auth/cli success card (web/src/pages/auth/cli/firstRun.ts)
// all render these, and a web test holds the copies equal.
const (
	// cilockInstallAuthorization is Pushgate's CILOCK_INSTALL_AUTHORIZATION
	// (jade/factory/edge/git/policies.js), verbatim: the human's up-front
	// consent the setup document quotes back.
	cilockInstallAuthorization = "You may install or upgrade cilock to the release those instructions require, using only the install command they print; ask me before installing anything else."
	// FirstRunCommand is the secondary path: wrap a build so its first
	// attestation is recorded against the bound tenant and product.
	FirstRunCommand = "cilock run --step build -- <your build command>"
)

// PushgateConnectLine sends the human to connect a repository at the Pushgate
// origin (scheme://host, no trailing slash). Connecting a repository and
// activating a policy are the human's acts; no prompt performs them.
func PushgateConnectLine(origin string) string {
	return "Next: connect a repository at " + origin + "/ to gate its pushes."
}

// PushgateAgentPrompt is the prompt a human pastes into their coding agent. It
// is the sentence Pushgate's own connect page hands out
// (jade/factory/edge/git/connect.js setupPrompt), pointed at the generic setup
// document, which has the agent ask its human which repository they connected
// rather than act on its own.
func PushgateAgentPrompt(origin string) string {
	return "Fetch and execute the instructions to set this repository up for gated pushes from " +
		origin + "/agent-setup/prompt.md\n" + cilockInstallAuthorization
}

var cilockCallbackPage = template.Must(template.New("cilock-callback").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{{.Title}} · Cilock</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;min-height:100svh;display:grid;place-items:center;padding:24px;
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
background:linear-gradient(135deg,#f1f5f9,#eef2ff);color:#111827}
.card{width:100%;max-width:40rem;min-width:0;padding:24px;border:1px solid #d1d5db;border-radius:16px;
background:#fff;box-shadow:0 12px 32px #1118270d;overflow-wrap:anywhere}
.brand{margin:0 0 20px;font-weight:600;color:#475569}.ok{color:#15803d;font-size:32px}
h1{font-size:20px;line-height:1.3;margin:8px 0 16px}p{margin:12px 0}
code{display:block;font-size:12px;white-space:normal}pre.prompt{margin:8px 0 0;padding:8px 12px;border-radius:8px;background:#f1f5f9;font-size:13px;white-space:pre-wrap}code.next{padding:8px 12px;border-radius:8px;background:#f1f5f9;font-size:13px}.hint{font-size:12px;color:#475569}
button{width:100%;min-height:44px;margin-top:12px;padding:12px 16px;border:0;border-radius:8px;
background:#2563eb;color:#fff;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#1d4ed8}button:focus-visible{outline:2px solid #2563eb;outline-offset:3px}
@media(prefers-color-scheme:dark){body{background:linear-gradient(135deg,#111827,#1e293b);color:#f1f5f9}
.card{background:#111827;border-color:#475569}code.next,pre.prompt{background:#1e293b}.brand,.hint{color:#cbd5e1}.ok{color:#4ade80}}
</style></head><body>
<main class="card" aria-labelledby="callback-heading">
<p class="brand">TestifySec · Cilock</p><div class="ok" aria-hidden="true">&#x2713;</div>
<h1 id="callback-heading">{{.Heading}}</h1>
<p>{{.Label}}: <strong>{{.Value}}</strong></p>
{{if .Identity}}<code>{{.Identity}}</code>{{end}}
<p role="status">{{.Message}}</p>
{{if .Connect}}<p>{{.Connect}} <a href="{{.PushgateURL}}">Open Pushgate</a></p>
<p>Then paste this prompt into your coding agent (Claude Code, Codex, or similar):</p>
<pre class="prompt" id="agent-prompt">{{.Prompt}}</pre>
<button type="button" id="copy-prompt">Copy prompt</button>
{{end}}{{if .Next}}<p>{{if .Connect}}Or attest a build directly:{{else}}Next, wrap your build so Cilock records its first attestation:{{end}}</p><code class="next">{{.Next}}</code>{{end}}
<button type="button" id="close-window">Close window</button>
<p class="hint">When you are done here, close this tab and return to your terminal.</p>
</main>
<script>function closeWindow(){window.close()}document.getElementById('close-window').addEventListener('click',closeWindow);
var copy=document.getElementById('copy-prompt');if(copy){copy.addEventListener('click',function(){navigator.clipboard.writeText(document.getElementById('agent-prompt').textContent).then(function(){copy.textContent='Copied'})})}</script>
</body></html>`))

func writeCilockCallbackPage(w io.Writer, page callbackPage) {
	_ = cilockCallbackPage.Execute(w, page)
}
