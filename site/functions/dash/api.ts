/**
 * Analytics data API: GET /dash/api?range=&segment=&network=&country=
 *
 * JWT-gated (same Cloudflare Access gate as /dash). Returns every dashboard block as
 * JSON so the client (/dash/app.js) can filter + re-render without a page reload.
 *
 * DEFAULT SEGMENT = "external": TestifySec's own traffic is excluded from every view
 * and every headline metric unless you explicitly switch the segment. "Internal" = any
 * cl_vid that has ever hit a /dash* route (behind Access => @testifysec.com only).
 *
 * Raw cl_vid UUIDs never leave the edge — visitors are returned only as pseudonyms.
 */

import { authedEmail } from '../_lib/access';
import { pseudonym, readerId } from '../_lib/pseudonym';

interface Env { DB?: D1Database }

type Row = Record<string, unknown>;

const RANGES: Record<string, number> = {
  '24h': 24 * 3600e3,
  '7d': 7 * 86400e3,
  '30d': 30 * 86400e3,
  '90d': 90 * 86400e3,
};
const SEGMENTS = new Set(['external', 'internal', 'humans', 'bots', 'all']);
const NETWORKS = new Set(['residential', 'datacenter', 'apple_relay', 'cgnat', 'corporate', 'mobile', 'tor', 'unknown']);

// cl_vids that have ever reached a /dash* route => TestifySec internal (all-time, not
// range-scoped, so the tag is stable). Used as a subquery in the segment filter.
const INTERNAL_SET = `(SELECT visitor_id FROM visits WHERE path LIKE '/dash%' AND visitor_id<>'')`;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

// Build a WHERE fragment + bound params from the active filters. `skip` lets a breakdown
// query omit the dimension it groups by (so e.g. the network chart isn't pre-narrowed).
function filt(
  segment: string,
  network: string,
  country: string,
  skip: { segment?: boolean; network?: boolean; country?: boolean } = {},
): { sql: string; params: unknown[] } {
  let sql = '';
  const params: unknown[] = [];
  if (!skip.segment) {
    switch (segment) {
      case 'internal': sql += ` AND visitor_id IN ${INTERNAL_SET}`; break;
      case 'humans': sql += ` AND bot_class='human'`; break;
      case 'bots': sql += ` AND bot_class<>'human'`; break;
      case 'all': break;
      case 'external':
      default: sql += ` AND bot_class='human' AND path NOT LIKE '/dash%' AND visitor_id NOT IN ${INTERNAL_SET}`; break;
    }
  }
  if (!skip.network && network) { sql += ` AND network_class=?`; params.push(network); }
  if (!skip.country && country) { sql += ` AND country=?`; params.push(country); }
  return { sql, params };
}

function host(referer: unknown): string {
  const r = String(referer ?? '');
  if (!r) return '(direct)';
  try { return new URL(r).hostname.replace(/^www\./, ''); } catch { return '(other)'; }
}

function section(path: string): string {
  const p = path.replace(/^\/+|\/+$/g, '');
  if (!p) return '(home)';
  return p.split('/')[0];
}

function normPath(p: string): string {
  let s = (p || '').toLowerCase().split('?')[0].split('#')[0];
  if (!s.startsWith('/')) s = '/' + s;
  if (s.length > 1) s = s.replace(/\/+$/, '');
  return s || '/';
}

// Fetch the published sitemap so we can show pages with ZERO traffic (the "cold" ones).
async function sitemapPaths(reqUrl: string): Promise<string[]> {
  try {
    const u = new URL('/sitemap.xml', reqUrl);
    const res = await fetch(u.toString(), { cf: { cacheTtl: 300, cacheEverything: true } } as RequestInit);
    if (!res.ok) return [];
    const xml = await res.text();
    const out = new Set<string>();
    for (const m of xml.matchAll(/<loc>([^<]+)<\/loc>/g)) {
      try { out.add(normPath(new URL(m[1]).pathname)); } catch { /* skip */ }
    }
    return [...out];
  } catch { return []; }
}

export const onRequestGet: PagesFunction<Env> = async (context) => {
  const email = await authedEmail(context.request);
  if (!email) return new Response('Forbidden — TestifySec sign-in required.', { status: 403 });
  if (!context.env.DB) return json({ error: 'D1 binding "DB" not configured.' }, 503);

  const db = context.env.DB;
  const url = new URL(context.request.url);
  const range = RANGES[url.searchParams.get('range') || '7d'] ? (url.searchParams.get('range') as string) : '7d';
  const segRaw = url.searchParams.get('segment') || 'external';
  const segment = SEGMENTS.has(segRaw) ? segRaw : 'external';
  const netRaw = url.searchParams.get('network') || '';
  const network = NETWORKS.has(netRaw) ? netRaw : '';
  const ctryRaw = (url.searchParams.get('country') || '').toUpperCase();
  const country = /^[A-Z]{2}$/.test(ctryRaw) ? ctryRaw : '';

  const since = Date.now() - RANGES[range];
  const bucket = range === '24h' ? 3600e3 : 86400e3;

  const all = (sql: string, params: unknown[] = []) =>
    db.prepare(sql).bind(...params).all().then((r) => r.results as Row[]).catch(() => [] as Row[]);
  const one = (sql: string, params: unknown[] = []) =>
    db.prepare(sql).bind(...params).first<Row>().catch(() => null);

  // Filter variants: detail = full filter; breakdowns omit their own dimension; the
  // human/bot split ignores segment (its whole job is to show that split).
  const det = filt(segment, network, country);
  const netF = filt(segment, network, country, { network: true });
  const ctryF = filt(segment, network, country, { country: true });
  const botF = filt(segment, network, country, { segment: true });

  const [
    summary, internalCount, series, topPages, searches, engaged, clicks, copies,
    networks, bots, countries, referrers, returners, recent, smapRows, smapPaths,
  ] = await Promise.all([
    one(
      `SELECT COUNT(*) loads, COUNT(DISTINCT visitor_id) visitors,
              COUNT(DISTINCT CASE WHEN is_returning=1 THEN visitor_id END) returning_v
         FROM visits WHERE ts>?${det.sql}`,
      [since, ...det.params],
    ),
    one(`SELECT COUNT(DISTINCT visitor_id) n FROM visits WHERE ts>? AND visitor_id IN ${INTERNAL_SET}`, [since]),
    all(
      `SELECT CAST(ts/? AS INTEGER) b, COUNT(*) loads, SUM(CASE WHEN is_returning=1 THEN 1 ELSE 0 END) returning_v
         FROM visits WHERE ts>?${det.sql} GROUP BY b ORDER BY b`,
      [bucket, since, ...det.params],
    ),
    all(
      `SELECT path, COUNT(*) views FROM visits WHERE ts>?${det.sql} AND instr(path,'.')=0
         GROUP BY path ORDER BY views DESC LIMIT 15`,
      [since, ...det.params],
    ),
    all(
      `SELECT query, COUNT(*) n FROM events WHERE type='search' AND query<>'' AND ts>?${det.sql}
         GROUP BY query ORDER BY n DESC LIMIT 20`,
      [since, ...det.params],
    ),
    all(
      `SELECT path, COUNT(*) n, CAST(AVG(dwell_ms)/1000 AS INT) avg_s, CAST(AVG(scroll) AS INT) scroll
         FROM events WHERE type='eng' AND ts>?${det.sql} GROUP BY path ORDER BY n DESC LIMIT 15`,
      [since, ...det.params],
    ),
    all(
      `SELECT query k, COUNT(*) n FROM events WHERE type='click' AND query<>'' AND ts>?${det.sql}
         GROUP BY query ORDER BY n DESC LIMIT 15`,
      [since, ...det.params],
    ),
    all(
      `SELECT query k, COUNT(*) n FROM events WHERE type='copy' AND query<>'' AND ts>?${det.sql}
         GROUP BY query ORDER BY n DESC LIMIT 15`,
      [since, ...det.params],
    ),
    all(
      `SELECT network_class k, COUNT(*) n FROM visits WHERE ts>?${netF.sql} GROUP BY k ORDER BY n DESC`,
      [since, ...netF.params],
    ),
    all(
      `SELECT bot_class k, COUNT(*) n FROM visits WHERE ts>?${botF.sql} GROUP BY k ORDER BY n DESC`,
      [since, ...botF.params],
    ),
    all(
      `SELECT country k, COUNT(*) n FROM visits WHERE ts>?${ctryF.sql} AND country<>'' GROUP BY k ORDER BY n DESC LIMIT 12`,
      [since, ...ctryF.params],
    ),
    all(
      `SELECT referer, COUNT(*) n FROM visits WHERE ts>?${det.sql} GROUP BY referer ORDER BY n DESC LIMIT 30`,
      [since, ...det.params],
    ),
    all(
      `SELECT visitor_id, COUNT(*) loads, COUNT(DISTINCT session_id) sessions,
              MIN(ts) first_seen, MAX(ts) last_seen,
              MAX(visitor_id IN ${INTERNAL_SET}) internal,
              MAX(bot_class<>'human') is_bot,
              (SELECT path FROM visits v2 WHERE v2.visitor_id=v.visitor_id
                 GROUP BY path ORDER BY COUNT(*) DESC LIMIT 1) fav
         FROM visits v WHERE ts>?${det.sql} AND visitor_id<>''
         GROUP BY visitor_id HAVING loads>1 ORDER BY loads DESC, last_seen DESC LIMIT 25`,
      [since, ...det.params],
    ),
    all(
      `SELECT ts, path, country, network_class, bot_class, visitor_id,
              (visitor_id IN ${INTERNAL_SET}) internal
         FROM visits WHERE ts>?${det.sql} ORDER BY ts DESC LIMIT 30`,
      [since, ...det.params],
    ),
    all(
      `SELECT path, COUNT(*) views FROM visits WHERE ts>?${det.sql} GROUP BY path`,
      [since, ...det.params],
    ),
    sitemapPaths(context.request.url),
  ]);

  // Build the hot/cold site map: every known page, with its load count (0 = cold).
  // Skip non-page asset requests (favicon, sitemap, robots, static files).
  const isAsset = (p: string) => /\.(ico|xml|txt|png|jpe?g|svg|gif|webp|js|css|json|map|woff2?)$/.test(p);
  const views = new Map<string, number>();
  for (const r of smapRows) {
    const p = normPath(String(r.path));
    if (isAsset(p)) continue;
    views.set(p, (views.get(p) || 0) + (Number(r.views) || 0));
  }
  const allPaths = new Set<string>([...smapPaths.filter((p) => !isAsset(p)), ...views.keys()]);
  const siteMap = [...allPaths]
    .map((p) => ({ path: p, views: views.get(p) || 0, section: section(p) }))
    .sort((a, b) => b.views - a.views || a.path.localeCompare(b.path))
    .slice(0, 80);

  // Aggregate referrers down to hostnames.
  const refMap = new Map<string, number>();
  for (const r of referrers) refMap.set(host(r.referer), (refMap.get(host(r.referer)) || 0) + (Number(r.n) || 0));
  const referrerRows = [...refMap.entries()].map(([k, n]) => ({ k, n })).sort((a, b) => b.n - a.n).slice(0, 12);

  const visitors = Number(summary?.visitors || 0);
  const returningV = Number(summary?.returning_v || 0);

  return json({
    generatedAt: Date.now(),
    filters: { range, segment, network, country },
    facets: {
      ranges: Object.keys(RANGES),
      segments: [...SEGMENTS],
      networks: networks.map((r) => String(r.k)),
      countries: countries.map((r) => String(r.k)),
    },
    summary: {
      loads: Number(summary?.loads || 0),
      visitors,
      returning: returningV,
      newVisitors: Math.max(0, visitors - returningV),
      internalExcluded: Number(internalCount?.n || 0),
    },
    bucket: range === '24h' ? 'hour' : 'day',
    bucketMs: bucket,
    series: series.map((r) => ({ t: Number(r.b) * bucket, loads: Number(r.loads), returning: Number(r.returning_v) })),
    topPages: topPages.map((r) => ({ path: String(r.path), views: Number(r.views) })),
    siteMap,
    searches: searches.map((r) => ({ query: String(r.query), n: Number(r.n) })),
    engaged: engaged.map((r) => ({ path: String(r.path), n: Number(r.n), avgSec: Number(r.avg_s), scroll: Number(r.scroll) })),
    clicks: clicks.map((r) => ({ k: String(r.k), n: Number(r.n) })),
    copies: copies.map((r) => ({ k: String(r.k), n: Number(r.n) })),
    networks: networks.map((r) => ({ k: String(r.k), n: Number(r.n) })),
    bots: bots.map((r) => ({ k: String(r.k), n: Number(r.n) })),
    countries: countries.map((r) => ({ k: String(r.k), n: Number(r.n) })),
    referrers: referrerRows,
    returners: returners.map((r) => ({
      reader: pseudonym(r.visitor_id, !!Number(r.is_bot)),
      rid: readerId(r.visitor_id),
      internal: !!Number(r.internal),
      loads: Number(r.loads),
      sessions: Number(r.sessions),
      fav: String(r.fav || ''),
      firstSeen: Number(r.first_seen),
      lastSeen: Number(r.last_seen),
    })),
    recent: recent.map((r) => ({
      t: Number(r.ts),
      reader: pseudonym(r.visitor_id, String(r.bot_class || '') !== 'human'),
      rid: readerId(r.visitor_id),
      internal: !!Number(r.internal),
      path: String(r.path || ''),
      country: String(r.country || ''),
      network: String(r.network_class || ''),
      bot: String(r.bot_class || ''),
    })),
  });
};
