import React from 'react';
import styles from './styles.module.css';

const ROOKERY = 'https://github.com/aflock-ai/rookery';

// GeneratedFooter appears at the bottom of every generated tool/attestor
// page. It tells the reader the page is generated from the CI/lock catalog
// (so edits belong upstream, not here) and deep-links to the exact source
// file to edit. PR-label guidance: AI agents tag `ai-agent`, humans `human`.
export default function GeneratedFooter({name}: {name: string}): React.ReactElement {
  const docPath = `attestation/detection/docs/${name}.doc.md`;
  const editUrl = `${ROOKERY}/edit/main/${docPath}`;
  const newUrl = `${ROOKERY}/new/main/attestation/detection/docs`;
  return (
    <div className={styles.generatedFooter}>
      <hr />
      <p>
        <strong>This page is generated from the CI/lock tool catalog.</strong>{' '}
        Don't edit it here — the source is{' '}
        <a href={editUrl}><code>{docPath}</code></a> in{' '}
        <a href={ROOKERY}>aflock-ai/rookery</a>. The same catalog powers{' '}
        <code>cilock tools show {name}</code> in the CLI, so a single edit keeps
        the terminal and the website in sync.
      </p>
      <p>
        <a href={editUrl}>Edit this page →</a> &nbsp;·&nbsp;{' '}
        <a href={newUrl}>Add a new tool →</a>
      </p>
      <p className={styles.generatedNote}>
        When you open the pull request: if you are an <strong>AI agent</strong>,
        add the <code>ai-agent</code> label. If you are a <strong>human</strong>,
        add the <code>human</code> label.
      </p>
    </div>
  );
}
