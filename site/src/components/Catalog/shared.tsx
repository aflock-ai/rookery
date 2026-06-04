import React from 'react';
import CodeBlock from '@theme/CodeBlock';
import type {CatalogEntry, CatalogTrigger} from './types';
import styles from './styles.module.css';

const TRACE_LABEL: Record<string, string> = {
  off: 'off — no syscall tracing needed',
  light: 'light — light eBPF assist helps',
  full: 'full — benefits from full eBPF trace',
};

export function GeneratedNote(): React.ReactElement {
  return (
    <p className={styles.generatedNote}>
      The facts in this box are generated from the CI/lock binary's own catalog
      (<code>cilock tools list</code>). Do not hand-edit — run{' '}
      <code>npm run gen:catalog</code>.
    </p>
  );
}

export function Categories({entry}: {entry: CatalogEntry}): React.ReactElement | null {
  if (!entry.categories?.length) return null;
  return (
    <>
      {entry.categories.map((c) => (
        <span key={c} className={styles.badge}>
          {c === entry.primaryCategory ? `${c} (primary)` : c}
        </span>
      ))}
    </>
  );
}

export function Upstream({entry}: {entry: CatalogEntry}): React.ReactElement | null {
  const u = entry.upstream;
  if (!u) return null;
  return (
    <>
      {u.source ? <a href={u.source}>{u.name || u.source}</a> : u.name || '—'}
      {u.vendor ? ` · ${u.vendor}` : ''}
      {u.license ? ` · ${u.license}` : ''}
    </>
  );
}

export function Triggers({triggers}: {triggers: CatalogTrigger[]}): React.ReactElement {
  if (!triggers?.length) {
    return <em>Not auto-detected — attach explicitly with <code>-a</code>.</em>;
  }
  return (
    <ul className={styles.triggerList}>
      {triggers.map((t, i) => (
        <li key={i}>
          <span className={styles.badge}>{t.gate}</span>
          <span className={styles.triggerKind}>{t.kind}</span>: {t.value}
        </li>
      ))}
    </ul>
  );
}

export function DetectionCheck({entry}: {entry: CatalogEntry}): React.ReactElement | null {
  if (!entry.detectionCommand) return null;
  return (
    <>
      <p>Confirm CI/lock detects it:</p>
      <CodeBlock language="bash">{entry.detectionCommand}</CodeBlock>
    </>
  );
}

export function traceLabel(t: string): string {
  return TRACE_LABEL[t] || t;
}
