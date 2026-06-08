import React, {useEffect, useState} from 'react';
import styles from './styles.module.css';

// The Trust Center renders the supply-chain provenance of a published release as
// a visual, green-checkmark panel — "exactly what happened for this build". Its
// source of truth is the material the release publishes alongside the binary
// (#5541): the signed release policy, the Fulcio + TSA trust roots, and the two
// per-binary DSSE attestation envelopes (source-git + build). It parses those
// envelopes client-side to surface the real facts (git commit, build command),
// and degrades cleanly — a version without verification material renders nothing,
// and an envelope that fails to fetch/parse falls back to the chain + receipts.

// Minimal shapes — we read defensively, never trusting structure.
type Envelope = {step: string; file: string; sha256: string};
type AttestationEntry = {binary: string; os?: string; arch?: string; envelopes: Envelope[]};
export type Verification = {
  policy?: string;
  fulcioRoots?: string;
  tsaChain?: string;
  attestations?: AttestationEntry[];
};

type BuildFacts = {
  commit?: string;
  commitMessage?: string;
  branch?: string;
  author?: string;
  commitDate?: string;
  buildCmd?: string;
};

const short = (h?: string) => (h && h.length > 12 ? h.slice(0, 12) : h) ?? '';
const base = (key: string) => key.split('/').pop() ?? key;

// Decode a DSSE envelope file into its in-toto Statement, or null on any failure.
async function fetchStatement(file: string): Promise<any | null> {
  try {
    const r = await fetch(`/dl/${file}`, {cache: 'force-cache'});
    if (!r.ok) return null;
    const dsse = await r.json();
    if (!dsse || typeof dsse.payload !== 'string') return null;
    const json = typeof atob === 'function' ? atob(dsse.payload) : '';
    return json ? JSON.parse(json) : null;
  } catch {
    return null;
  }
}

// Find the first attestation in a collection statement whose type contains `sub`.
function attestor(stmt: any, sub: string): any | null {
  const atts = stmt?.predicate?.attestations;
  if (!Array.isArray(atts)) return null;
  const hit = atts.find((a: any) => typeof a?.type === 'string' && a.type.includes(sub));
  return hit?.attestation ?? null;
}

// Pull the human-meaningful facts out of the source-git + build envelopes. Every
// field is optional — release envelope shapes can drift, and the panel must never
// hard-fail on a missing key (the git/command-run field names are verified against
// real cilock output, but we stay defensive).
function extractFacts(sourceGit: any, build: any): BuildFacts {
  const git = attestor(sourceGit, '/git/') ?? attestor(build, '/git/');
  const run = attestor(build, '/command-run/');
  const cmd = Array.isArray(run?.cmd) ? run.cmd.join(' ') : typeof run?.cmd === 'string' ? run.cmd : undefined;
  const msg = typeof git?.commitmessage === 'string' ? git.commitmessage.split('\n')[0].trim() : undefined;
  return {
    commit: git?.commithash || git?.commitdigest,
    commitMessage: msg,
    branch: git?.branch || git?.refnameshort,
    author: git?.author || git?.committername,
    commitDate: typeof git?.commitdate === 'string' ? git.commitdate.slice(0, 10) : undefined,
    buildCmd: cmd,
  };
}

function Check(): React.ReactElement {
  return (
    <svg className={styles.check} viewBox="0 0 20 20" aria-hidden="true">
      <path d="M7.6 13.3 4.3 10l-1.1 1.1 4.4 4.4 9-9-1.1-1.1z" />
    </svg>
  );
}

// The supply-chain attacks this provenance materially defends against, framed for
// a buyer who has read the news (SolarWinds, XZ, Codecov, npm/PyPI typosquats).
const DEFENDS = [
  {
    title: 'Build-server tampering',
    ex: 'SolarWinds / SUNBURST',
    how: 'Every build step is captured in a signed attestation — a tampered build can’t produce a matching one.',
  },
  {
    title: 'Stolen signing keys',
    ex: 'long-lived key exfiltration',
    how: 'Keyless signing — short-lived Fulcio certificates bound to the release workflow’s identity. There is no key to steal.',
  },
  {
    title: 'Backdated / forged signatures',
    ex: 'replay after cert expiry',
    how: 'An RFC 3161 timestamp anchors the signature to build time, so it verifies long after the 10-minute cert expires.',
  },
  {
    title: 'Source & dependency swaps',
    ex: 'XZ backdoor, dependency confusion',
    how: 'The exact source commit and every input are pinned by cryptographic digest in the provenance.',
  },
  {
    title: 'Unverified artifacts shipping',
    ex: 'Codecov-style poisoned uploads',
    how: 'The release is gated against a signed policy before publish — nothing unverified ever reaches cilock.dev.',
  },
  {
    title: 'Silent substitution at rest',
    ex: 'CDN / mirror tampering',
    how: 'The binary, envelopes, and policy are all SHA-256 pinned; re-verify offline anytime with cilock verify.',
  },
];

export default function TrustCenter({
  version,
  verification,
  platform,
  verEnv,
  binarySha256,
}: {
  version: string;
  verification: Verification;
  platform: string | null;
  verEnv: string;
  binarySha256?: string;
}): React.ReactElement | null {
  // Pick the binary to spotlight: the visitor's platform if it has envelopes,
  // else the first attested binary. (A null platform simply never matches.)
  const entry: AttestationEntry | undefined =
    verification.attestations?.find((a) => `${a.os}-${a.arch}` === platform) ??
    verification.attestations?.[0];

  const [facts, setFacts] = useState<BuildFacts | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!entry) return;
    const src = entry.envelopes.find((e) => e.step === 'source-git');
    const bld = entry.envelopes.find((e) => e.step === 'build');
    if (!src && !bld) return;
    let live = true;
    setLoading(true);
    Promise.all([src ? fetchStatement(src.file) : null, bld ? fetchStatement(bld.file) : null])
      .then(([s, b]) => {
        if (live) setFacts(extractFacts(s, b));
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [entry?.binary]);

  if (!entry && !verification.policy) return null;

  const platLabel = entry ? `${entry.os} / ${entry.arch}` : '';
  const steps = [
    {
      t: 'Source committed',
      d: facts?.commit
        ? `commit ${short(facts.commit)}${facts.branch ? ` on ${facts.branch}` : ''}`
        : 'Git provenance attested',
    },
    {t: 'Built in CI', d: facts?.buildCmd ? truncate(facts.buildCmd, 64) : 'Build command + inputs attested'},
    {t: 'Signed keyless', d: `${verEnv} platform Fulcio — no long-lived keys`},
    {t: 'Timestamped', d: 'RFC 3161 TSA — valid at signing time'},
    {t: 'Policy-verified', d: 'Gated against the signed release policy'},
    {t: 'Published', d: 'Released to cilock.dev with its receipts'},
  ];

  return (
    <section className={styles.trustCenter} aria-label="Supply chain trust center">
      <div className={styles.header}>
        <div className={styles.shield} aria-hidden="true">
          <svg viewBox="0 0 24 24">
            <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" />
            <path className={styles.shieldCheck} d="M10.6 15.4 7 11.8l1.4-1.4 2.2 2.2 4.6-4.6L16.6 9.4z" />
          </svg>
        </div>
        <div>
          <h2 className={styles.title}>Supply Chain Trust Center</h2>
          <p className={styles.subtitle}>
            Every byte of <code>{version}</code> is cryptographically accounted for, from source commit
            to the file you download. Verified, not asserted.
          </p>
        </div>
        <span className={styles.envBadge} data-env={verEnv}>
          {verEnv} signed
        </span>
      </div>

      <ol className={styles.chain}>
        {steps.map((s) => (
          <li key={s.t} className={styles.step}>
            <Check />
            <div>
              <span className={styles.stepTitle}>{s.t}</span>
              <span className={styles.stepDesc}>{s.d}</span>
            </div>
          </li>
        ))}
      </ol>

      {entry && (
        <div className={styles.factsBox}>
          <div className={styles.factsHead}>
            What happened in this build{platLabel && <span className={styles.muted}> · {platLabel}</span>}
            {loading && <span className={styles.muted}> · loading evidence…</span>}
          </div>
          <dl className={styles.facts}>
            <Fact label="Source commit" value={facts?.commit ? short(facts.commit) : undefined} mono />
            <Fact label="Message" value={facts?.commitMessage} />
            <Fact label="Branch" value={facts?.branch} mono />
            <Fact label="Author" value={facts?.author} />
            <Fact label="Date" value={facts?.commitDate} mono />
            <Fact label="Build" value={facts?.buildCmd ? truncate(facts.buildCmd, 90) : undefined} mono />
            <Fact label="Artifact SHA-256" value={binarySha256 ? short(binarySha256) + '…' : undefined} mono />
          </dl>
        </div>
      )}

      <div className={styles.defends}>
        <div className={styles.defendsHead}>What this protects you from</div>
        <div className={styles.defendsGrid}>
          {DEFENDS.map((d) => (
            <div key={d.title} className={styles.threat}>
              <div className={styles.threatTop}>
                <Check />
                <span className={styles.threatTitle}>{d.title}</span>
              </div>
              <span className={styles.threatEx}>{d.ex}</span>
              <span className={styles.threatHow}>{d.how}</span>
            </div>
          ))}
        </div>
      </div>

      <div className={styles.receipts}>
        <span className={styles.muted}>The receipts — verify any of this yourself:</span>
        {verification.policy && <a href={`/${verification.policy}`}>signed release policy</a>}
        {entry?.envelopes.map((e) => (
          <a key={e.file} href={`/dl/${e.file}`}>
            {e.step} attestation
          </a>
        ))}
        {verification.fulcioRoots && <a href={`/dl/${verification.fulcioRoots}`}>Fulcio + Root CA</a>}
        {verification.tsaChain && <a href={`/dl/${verification.tsaChain}`}>TSA chain</a>}
      </div>
    </section>
  );
}

function Fact({label, value, mono}: {label: string; value?: string; mono?: boolean}): React.ReactElement | null {
  if (!value) return null;
  return (
    <div className={styles.fact}>
      <dt>{label}</dt>
      <dd className={mono ? styles.mono : undefined}>{value}</dd>
    </div>
  );
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}
