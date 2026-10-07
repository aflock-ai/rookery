import documentationRoutes from '../../docs-redirects.json';

// The map comes from TestifySec's docs-import manifest. Keep a copy here so the
// public CI/lock subtree can deploy independently of the platform repository.
const routes: Readonly<Record<string, string>> = documentationRoutes;

export function documentationDestination(source: URL): URL | null {
  const path = source.pathname.replace(/\/index(?:\.html)?\/?$/, '')
    .replace(/\.html$/, '').replace(/\/$/, '');
  const target = path === '/docs' ? '/docs' :
    Object.hasOwn(routes, path) ? routes[path] : null;
  if (!target) return null;

  const destination = new URL(target, 'https://testifysec.com');
  destination.search = source.search;
  destination.hash = source.hash;
  return destination;
}

export function redirectDocumentation(request: Request): Response | null {
  if (request.method !== 'GET' && request.method !== 'HEAD') return null;
  const destination = documentationDestination(new URL(request.url));
  if (!destination) return null;
  // Browsers inherit the source fragment when Location supplies none.
  return new Response(null, {
    status: 301,
    headers: {Location: destination.href, 'Cache-Control': 'public, max-age=3600'},
  });
}
