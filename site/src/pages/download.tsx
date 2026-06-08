import React, {useEffect, useState} from 'react';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import Link from '@docusaurus/Link';
import styles from './download.module.css';

// CI/lock binaries are distributed ONLY from cilock.dev (Cloudflare R2 + the /dl
// download-analytics Functions), never GitHub. This page reads the same live
// manifest the install script and the TestifySec Platform /tools page consume,
// so it always reflects what actually published — no rebuild per release.
const MANIFEST_URL = '/dl/manifest.json';
const INSTALL_CMD = 'curl -fsSL https://cilock.dev/install.sh | bash';

// Trust model: release candidates are signed by the TestifySec STAGING platform;
// stable (GA) releases are signed by PRODUCTION keys. The published binary bakes
// in the matching platform trust, so `cilock verify` needs no --policy-* flags.
const STAGING_PLATFORM = 'https://platform.aws-sandbox-staging.testifysec.dev';
const PROD_PLATFORM = 'https://platform.testifysec.com';

type ManifestFile = {name: string; sha256: string; size: number; os?: string; arch?: string};
type AttestationEnvelope = {step: string; file: string; sha256: string};
type AttestationEntry = {binary: string; os?: string; arch?: string; envelopes: AttestationEnvelope[]};
// Per-version offline-verification material published alongside the binaries so a
// downloader can `cilock verify --platform-url ""` with NO platform/Archivista
// access. All optional — older versions predate it and the page degrades cleanly.
type Verification = {
  policy?: string;
  fulcioRoots?: string;
  tsaChain?: string;
  attestations?: AttestationEntry[];
};
type ManifestVersion = {version: string; released?: string; files: ManifestFile[]; verification?: Verification};
type Manifest = {schema: number; latest: string; updated?: string; versions: ManifestVersion[]};

const PLATFORM_LABEL: Record<string, string> = {
  'linux-amd64': 'Linux · x86-64',
  'linux-arm64': 'Linux · ARM64',
  'darwin-amd64': 'macOS · Intel',
  'darwin-arm64': 'macOS · Apple Silicon',
};

function fmtSize(bytes: number): string {
  if (!bytes) return '';
  const mb = bytes / (1024 * 1024);
  return mb >= 1 ? `${mb.toFixed(1)} MB` : `${Math.round(bytes / 1024)} KB`;
}

// Best-effort OS/arch guess from the browser, to highlight the right binary.
// arm-vs-intel on macOS isn't reliably exposed, so we default Apple to arm64
// (every Mac since 2020) and note the Intel option in the table.
function detectPlatform(): string | null {
  if (typeof navigator === 'undefined') return null;
  const ua = (navigator.userAgent || '').toLowerCase();
  const plat = (navigator.platform || '').toLowerCase();
  const isArm = /aarch64|arm64/.test(ua);
  if (/mac/.test(ua) || /mac/.test(plat)) return 'darwin-arm64';
  if (/linux/.test(ua) || /linux/.test(plat)) return isArm ? 'linux-arm64' : 'linux-amd64';
  if (/win/.test(ua) || /win/.test(plat)) return 'windows';
  return null;
}

function CopyCmd({cmd, big}: {cmd: string; big?: boolean}): React.ReactElement {
  const [copied, setCopied] = useState(false);
  return (
    <div className={`${styles.cmd} ${big ? styles.cmdBig : ''}`}>
      <pre className={styles.cmdCode}>
        <code>{cmd}</code>
      </pre>
      <button
        type="button"
        className={styles.copyBtn}
        onClick={() => {
          if (typeof navigator !== 'undefined' && navigator.clipboard) {
            navigator.clipboard.writeText(cmd).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1600);
            });
          }
        }}>
        {copied ? 'Copied ✓' : 'Copy'}
      </button>
    </div>
  );
}

function binFor(ver: ManifestVersion, platform: string): ManifestFile | undefined {
  return ver.files.find((f) => f.os && f.arch && `${f.os}-${f.arch}` === platform);
}

// The keyless policy signer identity baked into the release fan-out
// (release-fanout.yml RELEASE_POLICY_SIGNER_EMAIL + the platform Fulcio OIDC
// issuer). An offline verify pins these so the signed policy can't be swapped for
// one signed by a different Fulcio cert.
const POLICY_SIGNER_EMAIL = 'colek42@gmail.com';
const fulcioIssuerFor = (platformUrl: string) => `${platformUrl}/fulcio/oidc`;

// basename of an R2 key (e.g. "v3.0.0/fulcio-roots.pem" -> "fulcio-roots.pem").
const base = (key: string) => key.split('/').pop() ?? key;

// Build the copy-paste FULLY OFFLINE verify command from a version's published
// verification block, for a specific binary's two envelopes. `--platform-url ""`
// opts out of all platform/Archivista/discovery access; trust comes only from the
// published Fulcio roots + TSA chain + signed policy. Returns null when the block
// lacks the pieces an offline verify needs.
function offlineVerifyCmd(
  ver: ManifestVersion,
  att: AttestationEntry | undefined,
  platformUrl: string,
): string | null {
  const v = ver.verification;
  if (!v || !att || !v.fulcioRoots || !v.tsaChain || !v.policy) return null;
  const dl = `/dl/${ver.version}`;
  const policyName = base(v.policy);
  const attFiles = att.envelopes.map((e) => base(e.file));
  const lines = [
    `# download the binary + all verification material`,
    `curl -fsSLO https://cilock.dev${dl}/${att.binary}`,
    `curl -fsSL  https://cilock.dev/${v.policy} -o ${policyName}`,
    `curl -fsSLO https://cilock.dev/dl/${v.fulcioRoots}`,
    `curl -fsSLO https://cilock.dev/dl/${v.tsaChain}`,
    ...attFiles.map((f) => `curl -fsSLO https://cilock.dev${dl}/${f}`),
    `tar xzf ${att.binary} cilock`,
    ``,
    `# verify FULLY OFFLINE — no platform, tenant, or Archivista access`,
    `cilock verify ./cilock -p ${policyName} \\`,
    `  --attestations ${attFiles.join(',')} \\`,
    `  --policy-ca-roots ${base(v.fulcioRoots)} \\`,
    `  --policy-timestamp-servers ${base(v.tsaChain)} \\`,
    `  --policy-emails ${POLICY_SIGNER_EMAIL} \\`,
    `  --policy-fulcio-oidc-issuer ${fulcioIssuerFor(platformUrl)} \\`,
    `  --platform-url ""`,
  ];
  return lines.join('\n');
}

function attFor(ver: ManifestVersion, platform: string): AttestationEntry | undefined {
  return ver.verification?.attestations?.find((a) => a.os && a.arch && `${a.os}-${a.arch}` === platform);
}

function DownloadInner(): React.ReactElement {
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [platform, setPlatform] = useState<string | null>(null);

  useEffect(() => {
    setPlatform(detectPlatform());
    fetch(MANIFEST_URL, {cache: 'no-cache'})
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then((m: Manifest) => setManifest(m))
      .catch((e) => setError(String(e)));
  }, []);

  // Headline = the latest STABLE release. Until a GA exists, fall back to the
  // newest version overall (a pre-release) so the page reflects what actually
  // published instead of a stale `latest` pointer that --no-latest RCs never
  // move. Everything else (older builds + pre-releases) drops into "Other
  // releases" below — present but de-emphasized.
  const isPre = (s: string) => s.includes('-');
  const byNewest = [...(manifest?.versions ?? [])].sort((a, b) =>
    (b.released ?? '').localeCompare(a.released ?? ''),
  );
  // Prefer the manifest's authoritative `latest` pointer when it resolves to a
  // stable release (so the headline matches the install.sh default); else the
  // newest stable; else the newest version overall (a pre-release).
  const ver =
    byNewest.find((v) => v.version === manifest?.latest && !isPre(v.version)) ??
    byNewest.find((v) => !isPre(v.version)) ??
    byNewest[0];
  const headlinePre = ver ? isPre(ver.version) : false;
  const verPlatform = headlinePre ? STAGING_PLATFORM : PROD_PLATFORM;
  const verEnv = headlinePre ? 'staging' : 'production';
  const others = byNewest.filter((v) => v.version !== ver?.version);
  const binaries = (ver?.files ?? []).filter((f) => f.os && f.arch);
  const mine = ver && platform && platform !== 'windows' ? binFor(ver, platform) : undefined;
  const dlBase = ver ? `/dl/${ver.version}` : '/dl';

  return (
    <div className={styles.wrap}>
      <Heading as="h1" className={styles.title}>
        Download CI/lock
      </Heading>
      <p className={styles.lede}>
        Static, single-file binaries — signed by the TestifySec platform Fulcio + TSA and
        uploaded only after the release pipeline verifies each one against the signed release
        policy. Served (and counted) from cilock.dev, never GitHub.
      </p>

      {/* Story 1 — fastest path: one command. */}
      <section className={styles.section}>
        <Heading as="h2" className={styles.sectionTitle}>
          Quick install
        </Heading>
        <p className={styles.sectionHint}>
          Auto-detects your OS/arch, resolves the latest version from the manifest, and verifies
          the SHA-256 against the signed checksums before installing.
        </p>
        <CopyCmd cmd={INSTALL_CMD} big />
        <p className={styles.muted} style={{marginTop: '0.6rem'}}>
          Prefer Homebrew, Docker, or a SHA-pinned GitHub Action?{' '}
          <Link to="/getting-started/installation">See all install methods →</Link>
        </p>
      </section>

      {/* Story 2 — the right binary for me. */}
      <section className={styles.section}>
        <Heading as="h2" className={styles.sectionTitle}>
          {ver ? (
            <>
              {headlinePre ? 'Latest pre-release' : 'Latest release'} — {ver.version}
              {headlinePre && <span className={styles.preBadge}>pre-release</span>}
            </>
          ) : (
            'Latest release'
          )}
        </Heading>

        {headlinePre && (
          <p className={styles.sectionHint}>
            No stable release yet — this is the most recent release candidate. Pin it explicitly
            with <code>CILOCK_VERSION={ver?.version}</code>.
          </p>
        )}

        {error && (
          <p className={styles.muted}>
            Couldn't load the live manifest ({error}). Browse all artifacts directly at{' '}
            <a href="/dl/manifest.json">/dl/manifest.json</a>, or use the quick-install command
            above.
          </p>
        )}
        {!manifest && !error && <p className={styles.status}>Loading the latest release…</p>}

        {mine && ver && (
          <div className={styles.detected} style={{marginBottom: '1.5rem'}}>
            <div>
              <div className={styles.detectedLabel}>Detected for your machine</div>
              <div className={styles.detectedName}>{PLATFORM_LABEL[platform!] ?? platform}</div>
              <div className={styles.detectedArch}>
                {mine.name} · {fmtSize(mine.size)}
              </div>
            </div>
            <a className={styles.dlBtn} href={`${dlBase}/${mine.name}`}>
              Download
            </a>
          </div>
        )}
        {platform === 'windows' && (
          <p className={styles.muted}>
            Windows isn't shipped today (the <code>omnitrail</code> attestor is Linux/macOS-only).
            Use WSL2 and grab the <code>linux-amd64</code> build below.
          </p>
        )}

        {binaries.length > 0 && (
          <>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Platform</th>
                  <th>File</th>
                  <th>Size</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {binaries.map((f) => {
                  const key = `${f.os}-${f.arch}`;
                  return (
                    <tr key={f.name} className={key === platform ? styles.rowMine : undefined}>
                      <td>{PLATFORM_LABEL[key] ?? key}</td>
                      <td>
                        <code>{f.name}</code>
                      </td>
                      <td className={styles.size}>{fmtSize(f.size)}</td>
                      <td>
                        <a href={`${dlBase}/${f.name}`}>Download</a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <div className={styles.assetLinks}>
              <span className={styles.muted}>Also in this release:</span>
              <a href={`${dlBase}/checksums-sha256.txt`}>checksums-sha256.txt</a>
              <a href="/policy/release-v1.policy.json">signed release policy</a>
              {ver?.files.some((f) => f.name.endsWith('-sbom.spdx.json')) && (
                <a href={`${dlBase}/${ver.version.replace(/^v/, 'cilock-')}-sbom.spdx.json`}>SBOM</a>
              )}
              <a href="/dl/manifest.json">full manifest</a>
            </div>
          </>
        )}
      </section>

      {/* Other releases — previous builds + pre-releases, present but de-emphasized. */}
      {others.length > 0 && (
        <section className={styles.section}>
          <Heading as="h2" className={styles.sectionTitle}>
            Other releases
          </Heading>
          <p className={styles.sectionHint}>
            Previous builds and release candidates. Pre-releases are not the default install —
            expand a version to grab a specific binary.
          </p>
          {others.map((v) => {
            const pre = isPre(v.version);
            const base = `/dl/${v.version}`;
            const bins = v.files.filter((f) => f.os && f.arch);
            const day = v.released ? v.released.slice(0, 10) : '';
            return (
              <details key={v.version} className={styles.verItem}>
                <summary className={styles.verSummary}>
                  <code>{v.version}</code>
                  {pre && <span className={styles.preBadge}>pre-release</span>}
                  {day && <span className={styles.muted}> · {day}</span>}
                </summary>
                <div className={styles.verFiles}>
                  {bins.map((f) => (
                    <a key={f.name} href={`${base}/${f.name}`}>
                      {PLATFORM_LABEL[`${f.os}-${f.arch}`] ?? `${f.os}-${f.arch}`}
                    </a>
                  ))}
                  <a href={`${base}/checksums-sha256.txt`}>checksums</a>
                </div>
              </details>
            );
          })}
        </section>
      )}

      {/* Story 3 — verify what I downloaded. */}
      <section className={styles.section}>
        <Heading as="h2" className={styles.sectionTitle}>
          Verify it's the real thing
        </Heading>
        <p className={styles.sectionHint}>
          {headlinePre ? 'Release candidates are' : 'Stable releases are'} signed by the TestifySec{' '}
          <strong>{verEnv}</strong> platform (Fulcio + RFC&nbsp;3161 TSA). This binary bakes in the
          matching trust, so <code>cilock verify</code> needs no <code>--policy-*</code> flags — it
          pulls the build's signed evidence from the platform and checks it against the release
          policy published with the binary:
        </p>
        <CopyCmd
          cmd={
            mine
              ? `tar xzf ${mine.name} cilock\ncurl -fsSLO https://cilock.dev${dlBase}/release-policy.json\ncilock verify ./cilock --policy release-policy.json --platform-url ${verPlatform} --enable-archivista`
              : `tar xzf cilock-<version>-<os>-<arch>.tar.gz cilock\ncurl -fsSLO https://cilock.dev/dl/<version>/release-policy.json\ncilock verify ./cilock --policy release-policy.json --platform-url ${verPlatform} --enable-archivista`
          }
        />
        <p className={styles.muted} style={{marginTop: '0.6rem'}}>
          Release candidates are signed by the TestifySec <strong>staging</strong> platform; stable
          releases are signed by <strong>production</strong> keys. The <code>--platform-url</code>{' '}
          above is the <strong>{verEnv}</strong> platform that signed this release.
        </p>
        <div className={styles.verifyBox} style={{marginTop: '1rem'}}>
          <strong>What that proves</strong>
          <ul className={styles.trustPoints}>
            <li>The binary was built by the official TestifySec release pipeline — the workflow's identity is bound into the signing certificate.</li>
            <li>Signed by the <strong>TestifySec {verEnv} Platform Fulcio</strong>, chained to its Platform Root CA.</li>
            <li>Countersigned by an <strong>RFC 3161 TSA</strong> — the short-lived signing cert verifies as valid at signing time, long after it expires.</li>
            <li>It's the exact artifact the publish gate verified — nothing unverified ever reaches cilock.dev.</li>
          </ul>
          <p className={styles.muted} style={{marginTop: '0.75rem', marginBottom: 0}}>
            No <code>cilock</code> yet, or want an independent check?{' '}
            <Link to="/getting-started/verify-the-cilock-binary">
              SHA-256 + openssl verification →
            </Link>
          </p>
        </div>
      </section>

      {/* Story 3b — verify FULLY OFFLINE (no platform/tenant/Archivista). */}
      {ver?.verification && (() => {
        // Prefer the detected platform; else the first binary that has envelopes.
        const offlinePlatform =
          (platform && platform !== 'windows' && attFor(ver, platform) && platform) ||
          ver.verification.attestations?.[0] &&
            `${ver.verification.attestations[0].os}-${ver.verification.attestations[0].arch}`;
        const att = offlinePlatform ? attFor(ver, offlinePlatform) : undefined;
        const cmd = offlineVerifyCmd(ver, att, verPlatform);
        const v = ver.verification;
        if (!cmd) return null;
        return (
          <section className={styles.section}>
            <Heading as="h2" className={styles.sectionTitle}>
              Verify it offline (no platform needed)
            </Heading>
            <p className={styles.sectionHint}>
              For air-gapped or zero-trust verifiers. Every proof travels with the release: the
              per-binary DSSE attestation envelopes, the {verEnv} platform Fulcio + Root CA, and the
              RFC&nbsp;3161 TSA chain. <code>cilock verify --platform-url ""</code> checks the binary
              against the signed release policy using only those published files — no platform,
              tenant, or Archivista access:
            </p>
            <CopyCmd cmd={cmd} />
            <div className={styles.assetLinks} style={{marginTop: '0.9rem'}}>
              <span className={styles.muted}>Verification material:</span>
              {v.policy && <a href={`/${v.policy}`}>signed release policy</a>}
              {v.fulcioRoots && <a href={`/dl/${v.fulcioRoots}`}>fulcio-roots.pem</a>}
              {v.tsaChain && <a href={`/dl/${v.tsaChain}`}>tsa-chain.pem</a>}
              {att?.envelopes.map((e) => (
                <a key={e.file} href={`/dl/${e.file}`}>{base(e.file)}</a>
              ))}
            </div>
            <p className={styles.muted} style={{marginTop: '0.6rem'}}>
              Both the <code>source-git</code> and <code>build</code> envelopes are required — the
              policy has both steps. Full walkthrough:{' '}
              <Link to="/getting-started/verify-a-release-offline">Verify a release offline →</Link>
            </p>
          </section>
        );
      })()}

      {/* Story 4 — CI users. */}
      <section className={styles.section}>
        <Heading as="h2" className={styles.sectionTitle}>
          In GitHub Actions
        </Heading>
        <p className={styles.sectionHint}>
          Don't download in CI — use the Action. It fetches its own full-attestor binary at
          runtime and wraps your commands.
        </p>
        <CopyCmd cmd={`- uses: aflock-ai/cilock-action@v1\n  with:\n    command: go build ./...`} />
        <p className={styles.muted} style={{marginTop: '0.6rem'}}>
          <Link to="/tutorials/github-actions-pipeline">GitHub Actions pipeline tutorial →</Link>
        </p>
      </section>

      {/* License — CI/lock is open source. */}
      <section className={styles.section}>
        <Heading as="h2" className={styles.sectionTitle}>
          License
        </Heading>
        <p className={styles.sectionHint}>
          CI/lock is free and open source under the{' '}
          <a href="https://github.com/aflock-ai/rookery/blob/main/LICENSE">
            Apache License 2.0
          </a>
          . You can use, modify, and redistribute it — including building your own binary from{' '}
          <Link to="/ecosystem/rookery">rookery</Link>. The default release ships the{' '}
          <code>file</code> and <code>fulcio</code> signers; everything else is opt-in.
        </p>
      </section>

      {manifest?.updated && (
        <p className={styles.status} style={{marginTop: '2.5rem'}}>
          <span className={styles.dot} /> Live manifest · updated {manifest.updated}
        </p>
      )}
    </div>
  );
}

export default function DownloadPage(): React.ReactElement {
  return (
    <Layout
      title="Download CI/lock"
      description="Download CI/lock — static, platform-signed binaries for Linux and macOS (amd64/arm64), verified against the signed release policy before publish. Served from cilock.dev.">
      <DownloadInner />
    </Layout>
  );
}
