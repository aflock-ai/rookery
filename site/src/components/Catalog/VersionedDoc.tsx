import React, {createContext, useContext, useState} from 'react';
import styles from './styles.module.css';

// VersionedDoc renders an attestor page that has multiple predicate
// versions. The latest version is shown by default; a dropdown switches to
// older versions. Every version's content stays in the DOM (panes are just
// hidden), so all versions remain indexable while the latest is what a
// reader sees first.
const VersionCtx = createContext<string>('');

export function VersionedDoc({
  versions,
  latest,
  children,
}: {
  versions: string[];
  latest: string;
  children: React.ReactNode;
}): React.ReactElement {
  const [selected, setSelected] = useState(latest);
  return (
    <VersionCtx.Provider value={selected}>
      <div className={styles.versionBar}>
        <label>
          Predicate version:{' '}
          <select value={selected} onChange={(e) => setSelected(e.target.value)}>
            {versions.map((v) => (
              <option key={v} value={v}>
                {v}
                {v === latest ? ' (latest)' : ' (legacy)'}
              </option>
            ))}
          </select>
        </label>
        {selected !== latest && (
          <span className={styles.legacyWarn}>
            You are viewing a superseded version. New builds emit {latest}.
          </span>
        )}
      </div>
      {children}
    </VersionCtx.Provider>
  );
}

export function VersionPane({
  version,
  children,
}: {
  version: string;
  children: React.ReactNode;
}): React.ReactElement {
  const selected = useContext(VersionCtx);
  return <div hidden={selected !== version}>{children}</div>;
}

export default VersionedDoc;
