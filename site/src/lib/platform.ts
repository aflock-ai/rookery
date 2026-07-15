// Canonical hosted-platform URLs for cilock.dev CTAs.
//
// The free authenticated tier lives on the TestifySec Platform: pointing
// CI/lock or Witness at it and signing in is the whole setup — keyless Fulcio
// signing, hosted Archivista storage, and verification, at no cost. Signing in
// IS the identity, so there is no anonymous telemetry.

/** The hosted platform origin (also the value passed to `--platform-url`). */
export const PLATFORM_URL = 'https://platform.testifysec.com';

/**
 * Self-serve registration — the free-tier entry point. "Start free" CTAs target
 * this and fire the `platformSignup` Google Ads conversion (see adsConversions).
 */
export const PLATFORM_SIGNUP_URL = `${PLATFORM_URL}/auth/register`;
