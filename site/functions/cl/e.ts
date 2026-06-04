/**
 * First-party behavioral beacon receiver: POST /cl/e
 *
 * The client beacon (injected in docusaurus.config.js) sends small JSON events:
 *   { t:'pv'|'eng'|'search', p:path, r:referer, ms:dwell, sd:scrollDepth, vw,vh, q?:query }
 * cl_vid/cl_sid cookies ride along automatically. We enrich with cf signals and
 * write to Workers Analytics Engine (binding ANALYTICS) — with a log + optional D1
 * fallback so it works before bindings are wired.
 *
 * Consent: the client only fires this when allowed, but we re-check server-side
 * (defense in depth) — regulated geo without cl_consent=granted => 204, no write.
 */

import { type Cf, classifyNetwork, classifyBot, tlsFp, mayTrack, readCookie } from '../_lib/signals';

interface Env {
  ANALYTICS?: AnalyticsEngineDataset;
  DB?: D1Database;
}

export const onRequestPost: PagesFunction<Env> = async (context) => {
  const req = context.request;
  const cf = (req as Request & { cf?: Cf }).cf || {};
  const cookieHeader = req.headers.get('cookie');

  // Server-side consent gate (the client already gated, this is belt-and-suspenders).
  if (!mayTrack(cf, cookieHeader)) return new Response(null, { status: 204 });

  let ev: Record<string, unknown> = {};
  try { ev = await req.json(); } catch { return new Response(null, { status: 204 }); }

  const ua = req.headers.get('user-agent') || '';
  const hasClientHints = !!req.headers.get('sec-ch-ua');
  const ip = req.headers.get('cf-connecting-ip') || '';
  const networkClass = classifyNetwork(cf, ip);
  // A request that executed our JS beacon is almost certainly human.
  const botClass = ((): string => {
    const c = classifyBot(cf, ua, hasClientHints, networkClass);
    return c === 'suspected_bot' ? 'human' : c; // beacon execution overrides the heuristic
  })();

  const type = String(ev.t || 'pv').slice(0, 12);
  // `query` doubles as the detail field: the search text for type=search, or the
  // click target / copied snippet for type=click|copy.
  const rec = {
    type,
    path: String(ev.p || '').slice(0, 256),
    query: type === 'search' ? String(ev.q || '').slice(0, 80)
      : (type === 'click' || type === 'copy') ? String(ev.d || '').slice(0, 200) : '',
    referer: String(ev.r || '').slice(0, 256),
    visitor_id: readCookie(cookieHeader, 'cl_vid') || '',
    session_id: readCookie(cookieHeader, 'cl_sid') || '',
    country: cf.country || '',
    region: cf.regionCode || '',
    as_org: cf.asOrganization || '',
    network_class: networkClass,
    bot_class: botClass,
    tls_fp: tlsFp(cf),
    ua,
    dwell_ms: Math.max(0, Math.min(Number(ev.ms) || 0, 86400000)),
    scroll: Math.max(0, Math.min(Number(ev.sd) || 0, 100)),
    vw: Number(ev.vw) || 0,
    vh: Number(ev.vh) || 0,
  };

  console.log(`EVENT ${JSON.stringify(rec)}`);

  if (context.env.ANALYTICS) {
    context.env.ANALYTICS.writeDataPoint({
      blobs: [rec.type, rec.path, rec.query, rec.visitor_id, rec.session_id, rec.country,
        rec.region, rec.as_org, rec.network_class, rec.bot_class, rec.tls_fp, rec.referer, rec.ua],
      doubles: [rec.dwell_ms, rec.scroll, rec.vw, rec.vh, cf.asn || 0],
      indexes: [rec.path.slice(0, 96)],
    });
  }

  if (context.env.DB) {
    context.waitUntil(
      context.env.DB.prepare(
        `INSERT INTO events (ts, visitor_id, session_id, type, path, query, dwell_ms, scroll, vw, vh, country, network_class, bot_class, referer, ua)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      )
        .bind(Date.now(), rec.visitor_id, rec.session_id, rec.type, rec.path, rec.query, rec.dwell_ms,
          rec.scroll, rec.vw, rec.vh, rec.country, rec.network_class, rec.bot_class, rec.referer, rec.ua)
        .run()
        .catch((e) => console.log(`EVENT_DB_ERR ${String(e)}`))
    );
  }

  return new Response(null, { status: 204 });
};
