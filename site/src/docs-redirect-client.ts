import {documentationDestination} from '../functions/_lib/docs-redirects';

// Search results and MDX links use the client router and never reach the Pages
// middleware. Reuse its exact mapping before the legacy guide is displayed.
export function onRouteUpdate({location}: {location: Pick<URL, 'pathname' | 'search' | 'hash'>}) {
  const source = new URL(location.pathname + location.search + location.hash, 'https://cilock.dev');
  const destination = documentationDestination(source);
  if (destination) window.location.replace(destination.href);
}
