/**
 * Per-reader journey drill-down: GET /dash/journey?rid=<opaque reader id>
 *
 * JWT-gated (same Access gate as /dash). Resolves the opaque rid back to a cl_vid at
 * the edge (raw cl_vids never reach the browser), then returns that visitor's full
 * timeline — page loads + beacon events (views, searches, engaged reads) — grouped
 * into sessions, plus a small profile. All-time, capped.
 */

import { authedEmail } from '../_lib/access';
import { pseudonym, readerId } from '../_lib/pseudonym';

interface Env { DB?: D1Database }
type Row = Record<string, unknown>;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

function host(referer: unknown): string {
  const r = String(referer ?? '');
  if (!r) return '(direct)';
  try {
    const h = new URL(r).hostname.replace(/^www\./, '');
    return h === 'cilock.dev' ? '(on-site)' : h;
  } catch { return '(other)'; }
}

// Coarse device read from the user-agent — on-site context only (what they browsed with).
function parseUA(ua: unknown): { browser: string; os: string; type: string } {
  const s = String(ua ?? '');
  const os = /Windows NT/.test(s) ? 'Windows' : /Mac OS X/.test(s) ? 'macOS'
    : /Android/.test(s) ? 'Android' : /(iPhone|iPad|CPU OS)/.test(s) ? 'iOS'
    : /Linux/.test(s) ? 'Linux' : '';
  const fam = /Edg\//.test(s) ? 'Edge' : /OPR\//.test(s) ? 'Opera' : /Firefox\//.test(s) ? 'Firefox'
    : /Chrome\//.test(s) ? 'Chrome' : /Safari\//.test(s) ? 'Safari' : '';
  const m = s.match(/(?:Edg|OPR|Firefox|Chrome|Version)\/(\d+)/);
  const type = /Mobi|iPhone|Android(?!.*Tablet)/.test(s) ? 'mobile' : /iPad|Tablet/.test(s) ? 'tablet' : 'desktop';
  return { browser: (fam + (m ? ' ' + m[1] : '')).trim(), os, type };
}

export const onRequestGet: PagesFunction<Env> = async (context) => {
  const email = await authedEmail(context.request);
  if (!email) return new Response('Forbidden — TestifySec sign-in required.', { status: 403 });
  if (!context.env.DB) return json({ error: 'D1 binding "DB" not configured.' }, 503);

  const db = context.env.DB;
  const rid = (new URL(context.request.url).searchParams.get('rid') || '').toLowerCase();
  if (!/^[0-9a-f]{16}$/.test(rid)) return json({ error: 'bad rid' }, 400);

  const rows = (sql: string, ...p: unknown[]) =>
    db.prepare(sql).bind(...p).all().then((r) => r.results as Row[]).catch(() => [] as Row[]);

  // Resolve rid -> cl_vid by recomputing the digest over the candidate set. Low volume
  // makes the scan fine; add a stored hash column if the visitor table ever gets large.
  const cands = await rows(`SELECT DISTINCT visitor_id FROM visits WHERE visitor_id<>''`);
  let vid = '';
  for (const c of cands) { if (readerId(c.visitor_id) === rid) { vid = String(c.visitor_id); break; } }
  if (!vid) return json({ rid, found: false });

  const [visits, events] = await Promise.all([
    rows(`SELECT ts, session_id, path, referer, ip, asn, network_class, bot_class, country, region, city, as_org, user_agent
            FROM visits WHERE visitor_id=? ORDER BY ts`, vid),
    rows(`SELECT ts, session_id, type, path, query, dwell_ms, scroll, vw, vh
            FROM events WHERE visitor_id=? ORDER BY ts`, vid),
  ]);

  const isInternal = visits.some((v) => String(v.path || '').startsWith('/dash'));
  const lastVisit = visits[visits.length - 1] || {};
  const isBot = String(lastVisit.bot_class || 'human') !== 'human';

  type Item = { ts: number; sid: string; kind: string; path: string; query?: string; referer?: string; network?: string; dwell?: number; scroll?: number };
  const items: Item[] = [];
  for (const v of visits) {
    items.push({
      ts: Number(v.ts), sid: String(v.session_id || ''), kind: 'load', path: String(v.path || ''),
      referer: String(v.referer || ''), network: String(v.network_class || ''),
    });
  }
  for (const e of events) {
    const ty = String(e.type);
    const kind = ty === 'search' ? 'search' : ty === 'eng' ? 'read'
      : ty === 'click' ? 'click' : ty === 'copy' ? 'copy' : 'view';
    items.push({
      ts: Number(e.ts), sid: String(e.session_id || ''),
      kind,
      path: String(e.path || ''), query: String(e.query || ''),
      dwell: Math.round(Number(e.dwell_ms || 0) / 1000), scroll: Number(e.scroll || 0),
    });
  }
  items.sort((a, b) => a.ts - b.ts);

  const groups: { sid: string; start: number; end: number; items: Item[] }[] = [];
  const idx: Record<string, number> = {};
  for (const it of items) {
    let g = idx[it.sid];
    if (g === undefined) { g = idx[it.sid] = groups.length; groups.push({ sid: it.sid, start: it.ts, end: it.ts, items: [] }); }
    const grp = groups[g];
    grp.items.push(it);
    if (it.ts < grp.start) grp.start = it.ts;
    if (it.ts > grp.end) grp.end = it.ts;
  }
  groups.sort((a, b) => b.start - a.start); // most recent session first

  const sessionCount = new Set(visits.map((v) => String(v.session_id || ''))).size;
  const device = parseUA(lastVisit.user_agent);
  const vpEvent = [...events].reverse().find((e) => Number(e.vw) > 0);
  const viewport = vpEvent ? `${Number(vpEvent.vw)}×${Number(vpEvent.vh)}` : '';

  return json({
    rid,
    found: true,
    reader: pseudonym(vid, isBot),
    internal: isInternal,
    bot: isBot,
    profile: {
      loads: visits.length,
      events: events.length,
      sessions: sessionCount,
      firstSeen: items.length ? items[0].ts : 0,
      lastSeen: items.length ? items[items.length - 1].ts : 0,
      network: String(lastVisit.network_class || ''),
      country: String(lastVisit.country || ''),
      region: String(lastVisit.region || ''),
      city: String(lastVisit.city || ''),
      ip: String(lastVisit.ip || ''),
      asn: lastVisit.asn ? `AS${Number(lastVisit.asn)}` : '',
      org: String(lastVisit.as_org || ''),
      botClass: String(lastVisit.bot_class || ''),
      browser: device.browser,
      os: device.os,
      deviceType: device.type,
      viewport,
    },
    sessions: groups.slice(0, 50).map((g) => {
      const firstLoad = g.items.find((it) => it.kind === 'load');
      return {
        sid: g.sid.slice(0, 8),
        start: g.start,
        end: g.end,
        entry: host(firstLoad ? firstLoad.referer : ''),
        items: g.items.slice(0, 200),
      };
    }),
  });
};
