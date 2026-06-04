/**
 * Edge capture "sidecar" + consent-gated cookie middleware (Cloudflare Pages).
 *
 * Captures HTML page-view entry points (full loads). In-SPA route changes are
 * captured separately by the first-party beacon -> /cl/e (Docusaurus is an SPA,
 * so route changes don't reach the origin).
 *
 * Per page view it records IP, visitor id, session, UA, ASN/asOrganization, geo,
 * a self-computed TLS fingerprint, a network class (residential/datacenter/
 * apple_relay/cgnat/corporate/mobile/unknown), and a bot class — then:
 *   1. always logs a structured line (wrangler tail / Logpush),
 *   2. writes to Workers Analytics Engine if the ANALYTICS binding is present,
 *   3. writes a row to D1 if the DB binding is present.
 *
 * First-party cookies (ours, no third party): cl_vid (2y, repeat visitors),
 * cl_sid (30m, session), cf_country (1h geo hint). All tracking cookies + capture
 * are CONSENT-GATED in regulated regions (see _lib/signals.mayTrack). cf_country
 * (a transient geo hint, not tracking) is the only thing ever set pre-consent.
 */

import { type Cf, classifyNetwork, classifyBot, tlsFp, mayTrack, readCookie } from './_lib/signals';

interface Env {
  ANALYTICS?: AnalyticsEngineDataset;
  DB?: D1Database;
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const response = await context.next();

  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('text/html')) return response;

  const req = context.request;
  const cf = (req as Request & { cf?: Cf }).cf || {};
  const cookieHeader = req.headers.get('cookie');

  const headers = new Headers(response.headers);

  // cf_country is a transient geo hint (not tracking) — always set so the client banner can decide.
  if (cf.country) {
    headers.append('Set-Cookie', `cf_country=${cf.country}; Path=/; Max-Age=3600; SameSite=Lax`);
  }

  if (mayTrack(cf, cookieHeader)) {
    let vid = readCookie(cookieHeader, 'cl_vid');
    const returning = !!vid;
    if (!vid) vid = crypto.randomUUID();

    let sid = readCookie(cookieHeader, 'cl_sid');
    const newSession = !sid;
    if (!sid) sid = crypto.randomUUID();

    const ip = req.headers.get('cf-connecting-ip') || '';
    const ua = req.headers.get('user-agent') || '';
    const networkClass = classifyNetwork(cf, ip);
    const botClass = classifyBot(cf, ua, !!req.headers.get('sec-ch-ua'), networkClass);
    const fp = tlsFp(cf);
    const url = new URL(req.url);

    const visit = {
      ts: Date.now(),
      type: 'pageload',
      visitor_id: vid,
      session_id: sid,
      returning: returning ? 1 : 0,
      ip,
      asn: cf.asn ?? null,
      as_org: cf.asOrganization ?? null,
      country: cf.country ?? null,
      region: cf.regionCode ?? null,
      city: cf.city ?? null,
      network_class: networkClass,
      bot_class: botClass,
      tls_fp: fp,
      bot_score: cf.botManagement?.score ?? null, // Enterprise-only; null otherwise
      path: url.pathname,
      referer: req.headers.get('referer') || null,
      user_agent: ua || null,
    };

    console.log(`VISIT ${JSON.stringify(visit)}`);

    if (context.env.ANALYTICS) {
      context.env.ANALYTICS.writeDataPoint({
        blobs: ['pageload', visit.path, visit.visitor_id, visit.session_id, visit.country || '',
          visit.region || '', visit.as_org || '', networkClass, botClass, fp, visit.referer || '', ua],
        doubles: [visit.asn || 0, visit.returning, visit.bot_score ?? -1],
        indexes: [visit.path.slice(0, 96)],
      });
    }

    if (context.env.DB) {
      context.waitUntil(
        context.env.DB.prepare(
          `INSERT INTO visits (ts, visitor_id, session_id, is_returning, ip, asn, as_org, country, region, city, network_class, bot_class, tls_fp, bot_score, path, referer, user_agent)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
        )
          .bind(visit.ts, visit.visitor_id, visit.session_id, visit.returning, visit.ip, visit.asn,
            visit.as_org, visit.country, visit.region, visit.city, networkClass, botClass, fp,
            visit.bot_score, visit.path, visit.referer, visit.user_agent)
          .run()
          .catch((e) => console.log(`VISIT_DB_ERR ${String(e)}`))
      );
    }

    headers.append('Set-Cookie', `cl_vid=${vid}; Path=/; Max-Age=63072000; SameSite=Lax`);
    if (newSession) {
      headers.append('Set-Cookie', `cl_sid=${sid}; Path=/; Max-Age=1800; SameSite=Lax`);
    }
  }

  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
};
