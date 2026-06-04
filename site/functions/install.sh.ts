/**
 * GET /install.sh — the bootstrap installer, served from R2 (text/x-shellscript).
 *
 *   curl -fsSL https://cilock.dev/install.sh | sh
 *
 * The companion detached signature and signing cert live at /install.sh.sig and
 * /install.sh.cert (sibling route files). The installer is version-agnostic (it
 * resolves the latest release at runtime via /dl/latest/...), so it's served with a
 * short cache, not immutable.
 */

import { type Env, serveRootObject } from './_lib/dist';

export const onRequest: PagesFunction<Env> = (context) =>
  serveRootObject(context.env, context.request.method, 'install.sh', {
    cacheControl: 'public, max-age=300',
  });
