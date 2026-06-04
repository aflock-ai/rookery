/**
 * Internal analytics dashboard shell: GET /dash
 *
 * JWT-gated (Cloudflare Access, @testifysec.com only — see _lib/access). This route
 * just serves the app shell + mounts the client (/dash/app.js); all data comes from the
 * JWT-gated JSON API at /dash/api. TestifySec's own traffic is excluded by default.
 */

import { authedEmail } from '../_lib/access';

export const onRequestGet: PagesFunction = async (context) => {
  const email = await authedEmail(context.request);
  if (!email) return new Response('Forbidden — TestifySec sign-in required.', { status: 403 });

  const html = `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CI/lock · Analytics</title>
<link rel="icon" href="/img/favicon.ico">
<meta name="dash-user" content="${email.replace(/"/g, '')}">
<link rel="stylesheet" href="/dash/app.css">
</head><body>
<div id="app" data-user="${email.replace(/"/g, '')}"><div class="boot">Loading analytics…</div></div>
<script src="/dash/app.js" defer></script>
</body></html>`;

  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
};
