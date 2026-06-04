// Shared link normalizer for generated + hand-written tool/attestor pages.
// Fixes the stale "See also" links authored in the catalog docs:
//  - remaps moved targets,
//  - adds the correct .md/.mdx extension by resolving against the docs tree,
//  - strips links whose target doc doesn't exist (keeping the label text).
import {existsSync, statSync} from 'node:fs';
import {resolve, join} from 'node:path';

const REMAP = {
  '../guides/policy': '../concepts/policy-verification',
  '../concepts/attestation-graph': '../concepts/the-spine-of-the-graph',
};

function resolveTarget(target, fileDir) {
  const h = target.indexOf('#');
  let base = h >= 0 ? target.slice(0, h) : target;
  const anchor = h >= 0 ? target.slice(h) : '';
  if (base === '' || /^(https?:|mailto:|\/)/.test(base)) return null; // external/absolute/pure-anchor: leave
  let key = base.replace(/\.(md|mdx)$/, '');
  if (REMAP[key] !== undefined) key = REMAP[key];
  const abs = resolve(fileDir, key);
  for (const ext of ['.md', '.mdx']) if (existsSync(abs + ext)) return key + ext + anchor;
  if (existsSync(abs) && statSync(abs).isDirectory()) {
    for (const ext of ['.md', '.mdx'])
      if (existsSync(join(abs, 'index' + ext))) return key.replace(/\/$/, '') + '/index' + ext + anchor;
  }
  return false; // target doc not found
}

export function normalizeLinks(body, fileDir) {
  return body.replace(/\[([^\]]+)\]\((\.\.?\/[^)\s]+)\)/g, (m, label, target) => {
    const fixed = resolveTarget(target, fileDir);
    if (fixed === null) return m; // leave external/anchor
    if (fixed === false) return label; // strip dead link, keep text
    return `[${label}](${fixed})`;
  });
}
