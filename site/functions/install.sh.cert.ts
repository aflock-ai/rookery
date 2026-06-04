/**
 * GET /install.sh.cert — Fulcio signing certificate for /install.sh, served from R2.
 * See /install.sh.sig for the verification recipe.
 */

import { type Env, serveRootObject } from './_lib/dist';

export const onRequest: PagesFunction<Env> = (context) =>
  serveRootObject(context.env, context.request.method, 'install.sh.cert', {
    cacheControl: 'public, max-age=300',
  });
