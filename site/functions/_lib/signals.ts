/**
 * Shared edge signal helpers for the capture sidecar (_middleware.ts) and the
 * beacon receiver (cl/e.ts). Underscore-prefixed dir => not routed by Pages.
 *
 * Everything here is derived from data Cloudflare gives us on ALL plans (request
 * headers + the non-Enterprise subset of request.cf). We deliberately DO NOT
 * depend on Enterprise-only fields (botManagement.score/ja3/ja4) — we read them
 * if present but never require them.
 */

export type Cf = {
  asn?: number;
  asOrganization?: string;
  country?: string;
  region?: string;
  regionCode?: string;
  city?: string;
  httpProtocol?: string;
  tlsVersion?: string;
  tlsCipher?: string;
  tlsClientCiphersSha1?: string;
  tlsClientExtensionsSha1Le?: string;
  botManagement?: { score?: number; verifiedBot?: boolean; corporateProxy?: boolean };
};

// Regions requiring prior consent. Keep in sync with docusaurus.config.js.
export const REGULATED = new Set([
  'AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT','LV','LT',
  'LU','MT','NL','PL','PT','RO','SK','SI','ES','SE','IS','LI','NO','GB','CH','BR','ZA','KR','JP','IN',
]);

export function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  return header.split('; ').find((c) => c.startsWith(`${name}=`))?.split('=')[1];
}

/** Geo-gated consent check, mirrored on client + server. */
export function mayTrack(cf: Cf, cookieHeader: string | null): boolean {
  const regulated = !cf.country || REGULATED.has(cf.country);
  return !regulated || readCookie(cookieHeader, 'cl_consent') === 'granted';
}

const DATACENTER = ['amazon','aws','google cloud','googleusercontent','microsoft','azure','digitalocean','ovh','hetzner','linode','vultr','oracle','fastly','akamai','scaleway','leaseweb','contabo','choopa','alibaba','tencent','m247','datacamp','hostroyale'];
const MOBILE = ['wireless','mobile','cellular','t-mobile','verizon wireless','at&t mobility','vodafone','orange','telefonica','jio','airtel','sprint'];
const RESIDENTIAL = ['comcast','cox','charter','spectrum','verizon','at&t','centurylink','lumen','frontier','cablevision','optimum','mediacom','windstream','telmex','uninet','metronet','bell','rogers','telus','sky broadband','virgin media','deutsche telekom','broadband','comunicaciones','telecom','telecomunica'];

function inCgnat(ip: string): boolean {
  const m = ip.split('.');
  if (m.length !== 4) return false;
  const a = +m[0], b = +m[1];
  return a === 100 && b >= 64 && b <= 127; // 100.64.0.0/10
}

/** Best-effort network class from deterministic-ish signals. Honest: tags
 *  'unknown' rather than guessing an employer. Used to decide when company
 *  attribution is even worth attempting downstream. */
export function classifyNetwork(cf: Cf, ip: string): string {
  const org = (cf.asOrganization || '').toLowerCase();
  if (ip && inCgnat(ip)) return 'cgnat';
  if (org.includes('private relay')) return 'apple_relay';
  if (org.includes(' tor ') || org.includes('tor exit')) return 'tor';
  if (DATACENTER.some((k) => org.includes(k))) return 'datacenter';
  if (cf.botManagement?.corporateProxy === true) return 'corporate';
  if (MOBILE.some((k) => org.includes(k))) return 'mobile';
  if (RESIDENTIAL.some((k) => org.includes(k))) return 'residential';
  return 'unknown';
}

const BOT_UA = /(bot|crawl|spider|slurp|bingpreview|facebookexternalhit|headlesschrome|phantomjs|python-requests|python\/|curl\/|wget|go-http|java\/|okhttp|axios|node-fetch|libwww|scrapy)/i;

/** human | verified_crawler | crawler | suspected_bot. Refined to 'human' at the
 *  beacon endpoint (executing JS is strong human evidence). */
export function classifyBot(cf: Cf, ua: string, hasClientHints: boolean, networkClass: string): string {
  if (cf.botManagement?.verifiedBot) return 'verified_crawler';
  if (ua && BOT_UA.test(ua)) return 'crawler';
  if (typeof cf.botManagement?.score === 'number' && cf.botManagement.score < 30) return 'suspected_bot';
  if (networkClass === 'datacenter' && !hasClientHints) return 'suspected_bot';
  return 'human';
}

/** Self-computed TLS fingerprint (JA4-style composite) from the all-plans cf.tls*
 *  fields. Uses the SORTED extension hash (…Sha1Le) — the order-sensitive variant
 *  is broken by Chrome's 2023 ClientHello permutation. Stable per client build;
 *  a cohort/bot signal, NOT a person identifier. */
export function tlsFp(cf: Cf): string {
  const v = (cf.tlsVersion || '?').replace('TLSv', 't');
  const proto = cf.httpProtocol || '?';
  const ciph = (cf.tlsClientCiphersSha1 || '').slice(0, 12);
  const ext = (cf.tlsClientExtensionsSha1Le || '').slice(0, 12);
  return `${v}_${proto}_${ciph}_${ext}`;
}
