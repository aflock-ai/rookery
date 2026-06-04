import React from 'react';
import type {CatalogEntry} from './types';
import {Categories, DetectionCheck, GeneratedNote, Triggers, Upstream, traceLabel} from './shared';
import styles from './styles.module.css';

// ToolMeta renders the drift-proof, catalog-derived facts for a tool page:
// upstream, category, detection triggers, recommended trace, emitted format(s),
// and (if any) the native attestor's predicate type. The hand-authored prose
// of the page (Validated invocation / Why this shape / FAQ) lives in the .mdx
// and is never touched by codegen.
export default function ToolMeta({data}: {data: CatalogEntry}): React.ReactElement {
  return (
    <div>
      <table className={styles.metaTable}>
        <tbody>
          <tr>
            <th>Upstream</th>
            <td><Upstream entry={data} /></td>
          </tr>
          {data.categories?.length ? (
            <tr>
              <th>Category</th>
              <td><Categories entry={data} /></td>
            </tr>
          ) : null}
          <tr>
            <th>Catalog source</th>
            <td>
              {data.source === 'attestor-backed'
                ? 'attestor-backed (ships a native cilock attestor)'
                : 'catalog-only (detected; output captured via a format attestor)'}
            </td>
          </tr>
          {data.emitsFormats?.length ? (
            <tr>
              <th>Emits format</th>
              <td>
                {data.emitsFormats.map((f) => (
                  <a key={f} href={`../attestors/${f}`} className={styles.badge}>{f}</a>
                ))}
              </td>
            </tr>
          ) : null}
          {data.predicateType ? (
            <tr>
              <th>Predicate type</th>
              <td><code>{data.predicateType}</code></td>
            </tr>
          ) : null}
          <tr>
            <th>Recommended trace</th>
            <td>{traceLabel(data.recommendedTrace)}</td>
          </tr>
          <tr>
            <th>Detected when</th>
            <td><Triggers triggers={data.triggers} /></td>
          </tr>
        </tbody>
      </table>
      <DetectionCheck entry={data} />
      <GeneratedNote />
    </div>
  );
}
