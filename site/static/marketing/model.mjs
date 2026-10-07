// Shared by the website runtime and journey simulator. No vendor SDKs.
export const ATTRIBUTION_DAYS = 90;
export const HANDOFF_SECONDS = 120;
export const PROPERTY_HOSTS = ['testifysec.com', 'www.testifysec.com', 'cilock.dev', 'pushgate.dev'];
const UTM_KEYS = ['source', 'medium', 'campaign', 'content', 'term'];
const token = value => typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9_.~-]{0,127}$/.test(value) ? value : '';
export function campaignFromURL(url) {
  const params = new URL(url).searchParams;
  const campaign = {};
  for (const key of UTM_KEYS) {
    const value = token(params.get(`utm_${key}`));
    if (value) campaign[key] = value;
  }
  // Click IDs are not consent, identity, or a usable campaign name. Kept out
  // of the CRM journey ledger; ad-platform conversion imports have a separate contract.
  return campaign;
}
export function updateAttribution(previous, incoming, now = Date.now()) {
  const active = previous && Number.isFinite(previous.expires_at) && previous.expires_at > now;
  const state = active ? previous : {first: null, last: null, expires_at: now + ATTRIBUTION_DAYS * 86400000};
  const clean = Object.fromEntries(UTM_KEYS.flatMap(key => token(incoming?.[key]) ? [[key, token(incoming[key])]] : []));
  // Direct, organic and internal pages never overwrite a real campaign.
  if (!Object.keys(clean).length) return state;
  const touch = { ...clean, captured_at: now };
  return {first: state.first || touch, last: touch, expires_at: now + ATTRIBUTION_DAYS * 86400000};
}
export function routeContext(property, pathname) {
  const path = pathname.replace(/\/+$/, '') || '/';
  const match = path.match(/^\/solutions\/(agent-code|platform-teams|technical-controls|private-deployment)$/);
  let journey = match?.[1] || 'unassigned';
  let product = property === 'cilock.dev' ? 'cilock' : property === 'pushgate.dev' ? 'pushgate' : 'platform';
  if (['testifysec.com', 'www.testifysec.com'].includes(property)) {
    if (path === '/cilock' || path === '/docs/cilock' || path.startsWith('/docs/cilock/')) { product = 'cilock'; journey = 'developer-start'; }
    if (path === '/pushgate' || path === '/docs/pushgate' || path.startsWith('/docs/pushgate/')) { product = 'pushgate'; journey = 'agent-code'; }
    if (path === '/product' || path === '/docs/platform' || path.startsWith('/docs/platform/')) journey = 'platform-teams';
  }
  if (journey === 'private-deployment') product = 'appliance';
  if (property === 'cilock.dev' && /^\/(install|getting-started|quickstart|free|download)/.test(path)) journey = 'developer-start';
  const page_type = path.startsWith('/blog/') ? 'article' : path === '/blog' ? 'blog' : path.includes('pricing') ? 'pricing' : path.includes('docs') || property === 'cilock.dev' && !['/', '/free', '/from-witness'].includes(path) ? 'docs' : match ? 'solution' : path === '/' ? 'home' : 'marketing';
  return {path, journey, product, page_type};
}
export function handoffURL(href, origin, state, now = Date.now()) {
  const target = new URL(href, origin);
  const current = new URL(origin);
  if (target.protocol !== 'https:' || !PROPERTY_HOSTS.includes(target.hostname) || !PROPERTY_HOSTS.includes(current.hostname) || target.hostname === current.hostname || !state?.consented) return target.href;
  // Short-lived anonymous measurement only. Not a session, credential, person
  // identifier or entitlement. Receiver consent is checked independently.
  const handoff = {v: 1, from: current.hostname.replace(/^www\./, ''), id: state.journey_id, at: now, attribution: state.attribution};
  target.searchParams.set('_tsj', btoa(JSON.stringify(handoff)));
  return target.href;
}
export function readHandoff(url, consented, now = Date.now()) {
  if (!consented) return null;
  try {
    const raw = new URL(url).searchParams.get('_tsj');
    if (!raw || raw.length > 2500) return null;
    const value = JSON.parse(atob(raw));
    if (value.v !== 1 || !PROPERTY_HOSTS.includes(value.from) || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(value.id) || !Number.isFinite(value.at) || now < value.at || now - value.at > HANDOFF_SECONDS * 1000) return null;
    const attribution = updateAttribution(null, value.attribution?.first, now);
    const last = updateAttribution(attribution, value.attribution?.last, now);
    return {journey_id: value.id, attribution: last, from: value.from};
  } catch { return null; }
}
export function eventFor(state, type, context, id, now = Date.now()) {
  if (!state.consented) return null;
  return {schema: 'testifysec.webjourney.v1', event_id: id, journey_id: state.journey_id,
    property: state.property, type, journey: context.journey, product: context.product,
    path: context.path, occurred_at: new Date(now).toISOString(), consent_version: 1,
    first_campaign: state.attribution?.first?.campaign || '', last_campaign: state.attribution?.last?.campaign || '',
    utm_source: state.attribution?.last?.source || '', utm_medium: state.attribution?.last?.medium || '',
    utm_content: state.attribution?.last?.content || ''};
}
