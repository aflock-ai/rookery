// Google Ads conversion-event wiring for cilock.dev.
//
// This module is SAFE TO SHIP DARK. Every call is a guarded no-op until BOTH:
//   1. The site-wide gtag global exists (loaded by the Advanced Consent Mode v2
//      / gtag bootstrap — PR #6078), AND
//   2. The conversion's label below is filled in (non-empty string).
// Until then `fireConversion(...)` does nothing and throws nothing, so it is
// harmless to wire into buttons/links before the Ads conversion actions exist.
//
// ─── TO ACTIVATE ───────────────────────────────────────────────────────────
// In Google Ads → Goals → Conversions, create each conversion action (Website →
// "Add manually using code"). Each one issues a conversion LABEL. The full
// send_to value is the account id + "/" + that label:
//
//     AW-16567715897/<label>
//
// Paste ONLY the <label> portion into the matching field of CONVERSION_LABELS
// below (not the whole AW-… string — the account id is prefixed for you in
// fireConversion). An empty string keeps that event inert (no-op).
// ────────────────────────────────────────────────────────────────────────────

/** Google Ads account id. The conversion label is appended as `${ID}/${label}`. */
const ADS_ACCOUNT_ID = 'AW-16567715897';

/**
 * One entry per conversion action. Fill each value from
 * Google Ads → Conversions → the action's tag (AW-16567715897/<label>).
 * Empty = inert no-op.
 */
export const CONVERSION_LABELS = {
  installCopy: '', // PRIMARY — user copied the `curl … | bash` install command.
  downloadStart: '', // user started a binary download.
  docsGettingStarted: '', // reached the getting-started / quickstart page.
  githubOutbound: '', // clicked through to the GitHub repo.
  platformSignup: '', // managed-platform signup / demo request.
} as const;

export type ConversionKey = keyof typeof CONVERSION_LABELS;

// Minimal shape of the gtag global the site loads elsewhere. Declared locally
// (not a global augmentation) so this module compiles standalone whether or not
// the gtag bootstrap is present.
type GtagFn = (command: 'event', eventName: string, params?: Record<string, unknown>) => void;

/**
 * Report a Google Ads conversion. Guarded triple no-op: does nothing unless we
 * are in a browser, `window.gtag` is a real function, AND the key's label is
 * filled. Safe to call regardless of gtag/label availability.
 *
 * @param key   which conversion action fired
 * @param value monetary value (USD) to attach for value-based bidding
 */
export function fireConversion(key: ConversionKey, value?: number): void {
  if (typeof window === 'undefined') return;
  const gtag = (window as unknown as {gtag?: GtagFn}).gtag;
  const label = CONVERSION_LABELS[key];
  if (typeof gtag !== 'function' || !label) return;
  gtag('event', 'conversion', {
    send_to: `${ADS_ACCOUNT_ID}/${label}`,
    value,
    currency: 'USD',
  });
}
