/**
 * GET /install.sh.sig — detached signature for /install.sh, served from R2.
 * Pairs with /install.sh.cert for keyless (Fulcio) verification of the installer:
 *
 *   curl -fsSLO https://cilock.dev/install.sh
 *   curl -fsSLO https://cilock.dev/install.sh.sig
 *   curl -fsSLO https://cilock.dev/install.sh.cert
 *   cosign verify-blob --certificate install.sh.cert --signature install.sh.sig install.sh
 */

import { type Env, serveRootObject } from './_lib/dist';

export const onRequest: PagesFunction<Env> = (context) =>
  serveRootObject(context.env, context.request.method, 'install.sh.sig', {
    cacheControl: 'public, max-age=300',
  });
