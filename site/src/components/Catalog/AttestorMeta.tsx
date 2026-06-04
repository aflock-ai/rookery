import React from 'react';
import type {CatalogEntry} from './types';
import {Categories, GeneratedNote, Triggers, traceLabel} from './shared';
import styles from './styles.module.css';

// AttestorMeta renders the catalog-derived metadata table for an attestor page
// (name, predicate type, lifecycle, default-on, category, recommended trace,
// and what triggers auto-attachment). Replaces the hand-maintained table; the
// page's prose (What it captures / When to use / Output shape) stays authored.
export default function AttestorMeta({data}: {data: CatalogEntry}): React.ReactElement {
  return (
    <div>
      <table className={styles.metaTable}>
        <tbody>
          <tr>
            <th>Name</th>
            <td><code>{data.name}</code></td>
          </tr>
          {data.predicateType ? (
            <tr>
              <th>Predicate type</th>
              <td><code>{data.predicateType}</code></td>
            </tr>
          ) : null}
          {data.runType ? (
            <tr>
              <th>Lifecycle</th>
              <td><code>{data.runType}</code></td>
            </tr>
          ) : null}
          <tr>
            <th>Default binary?</th>
            <td>{data.defaultOn ? 'Yes' : 'No'}</td>
          </tr>
          {data.categories?.length ? (
            <tr>
              <th>Category</th>
              <td><Categories entry={data} /></td>
            </tr>
          ) : null}
          <tr>
            <th>Recommended trace</th>
            <td>{traceLabel(data.recommendedTrace)}</td>
          </tr>
          <tr>
            <th>Auto-attaches when</th>
            <td><Triggers triggers={data.triggers} /></td>
          </tr>
        </tbody>
      </table>
      <GeneratedNote />
    </div>
  );
}
