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
code{display:block;font-size:12px;white-space:normal}.hint{font-size:12px;color:#475569}
button{width:100%;min-height:44px;margin-top:12px;padding:12px 16px;border:0;border-radius:8px;
background:#2563eb;color:#fff;font:inherit;font-weight:600;cursor:pointer}
button:hover{background:#1d4ed8}button:focus-visible{outline:2px solid #2563eb;outline-offset:3px}
@media(prefers-color-scheme:dark){body{background:linear-gradient(135deg,#111827,#1e293b);color:#f1f5f9}
.card{background:#111827;border-color:#475569}.brand,.hint{color:#cbd5e1}.ok{color:#4ade80}}
</style></head><body>
<main class="card" aria-labelledby="callback-heading">
<p class="brand">TestifySec · Cilock</p><div class="ok" aria-hidden="true">&#x2713;</div>
<h1 id="callback-heading">{{.Heading}}</h1>
<p>{{.Label}}: <strong>{{.Value}}</strong></p>
{{if .Identity}}<code>{{.Identity}}</code>{{end}}
<p role="status">{{.Message}}</p>
<button type="button" id="close-window">Close window</button>
<p class="hint">This window will try to close automatically. If it stays open, close this tab and return to your terminal.</p>
</main>
<script>function closeWindow(){window.close()}document.getElementById('close-window').addEventListener('click',closeWindow);setTimeout(closeWindow,3000)</script>
</body></html>`))

func writeCilockCallbackPage(w io.Writer, page callbackPage) {
	_ = cilockCallbackPage.Execute(w, page)
}
