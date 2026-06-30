import React, {useState} from 'react';
import Layout from '@theme/Layout';
import Head from '@docusaurus/Head';
import Heading from '@theme/Heading';
import Link from '@docusaurus/Link';
import {fireConversion} from '../lib/adsConversions';
import dl from './download.module.css';
import styles from './from-witness.module.css';

// Message-match landing page for the "from the team that built Witness" ad
// traffic (Google Ads Tier-1 brand-adjacent + Tier-4 adjacent-tool groups).
// The first five words of the H1 must mirror the ad headline or Quality Score
// (and the cheapest CPC inventory we have) suffers.
const INSTALL_CMD = 'curl -fsSL https://cilock.dev/install.sh | bash';
const GITHUB_URL = 'https://github.com/aflock-ai/rookery';

// Copy-able install command that fires the PRIMARY Ads conversion
// (`installCopy`) on copy. Mirrors the download page's CopyCmd, plus the
// conversion hook. fireConversion is a guarded no-op until a label is filled,
// so this is safe to ship before the Ads conversion action exists.
function InstallCmd(): React.ReactElement {
  const [copied, setCopied] = useState(false);
  return (
    <div className={`${dl.cmd} ${dl.cmdBig}`}>
      <pre className={dl.cmdCode}>
        <code>{INSTALL_CMD}</code>
      </pre>
      <button
        type="button"
        className={dl.copyBtn}
        onClick={() => {
          if (typeof navigator !== 'undefined' && navigator.clipboard) {
            navigator.clipboard.writeText(INSTALL_CMD).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1600);
            });
          }
          // Primary conversion: copying the install command is the truest
          // dev-CLI intent signal. $20 value for value-based bidding.
          fireConversion('installCopy', 20);
        }}>
        {copied ? 'Copied ✓' : 'Copy'}
      </button>
    </div>
  );
}

function FromWitnessInner(): React.ReactElement {
  return (
    <div className={dl.wrap}>
      <Heading as="h1" className={dl.title}>
        From the team that built Witness.
      </Heading>
      <p className={dl.lede}>
        CI/lock is TestifySec's second in-toto implementation — it speaks the exact same
        DSSE/in-toto envelopes, so either tool verifies the other's evidence.
      </p>

      {/* Primary CTA — install command (fires the primary conversion on copy). */}
      <section className={dl.section}>
        <Heading as="h2" className={dl.sectionTitle}>
          Install CI/lock
        </Heading>
        <p className={dl.sectionHint}>
          One command. Auto-detects your OS/arch, resolves the latest version, and verifies the
          signed SHA-256 checksums before installing.
        </p>
        <InstallCmd />
        <div className={styles.ctaRow}>
          <a
            className={styles.secondaryCta}
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            onClick={() => fireConversion('githubOutbound', 5)}>
            View on GitHub →
          </a>
          <Link className={styles.tertiaryCta} to="/download">
            All download options
          </Link>
        </div>
      </section>

      {/* Three scannable blocks. */}
      <section className={dl.section}>
        <div className={styles.blocks}>
          <div className={styles.block}>
            <Heading as="h3" className={styles.blockTitle}>
              Same evidence
            </Heading>
            <p className={styles.blockBody}>
              Drop-in compatible with what you already produce. CI/lock reads and writes the same
              DSSE/in-toto envelopes as Witness, so there's no re-tooling your attestations — either
              tool verifies the other's evidence.
            </p>
          </div>

          <div className={styles.block}>
            <Heading as="h3" className={styles.blockTitle}>
              What's new
            </Heading>
            <p className={styles.blockBody}>
              CI/lock wraps any CI/CD command and records <em>what actually ran</em> — source, env,
              argv, and input/output digests. Keyless signing with Fulcio + an RFC&nbsp;3161 TSA,
              verifiable fully offline. And a <strong>human-signed policy gate</strong> that blocks
              the release until a human signs off — the thing cosign and the SLSA generators don't
              give you.
            </p>
          </div>

          <div className={styles.block}>
            <Heading as="h3" className={styles.blockTitle}>
              Same ecosystem, more attestors
            </Heading>
            <p className={styles.blockBody}>
              50+ attestors via the{' '}
              <Link to="/ecosystem/rookery">rookery</Link> factory, all{' '}
              <a href={`${GITHUB_URL}/blob/main/LICENSE`} target="_blank" rel="noopener noreferrer">
                Apache-2.0
              </a>{' '}
              and self-hostable — with an optional managed{' '}
              <a href="https://platform.testifysec.com" target="_blank" rel="noopener noreferrer">
                TestifySec Platform
              </a>{' '}
              if you'd rather not run the trust infrastructure yourself.
            </p>
          </div>
        </div>
      </section>

      {/* Trust / optics line — Witness is our donated CNCF project; CI/lock
          complements it, it does not replace it. */}
      <p className={styles.optics}>
        Witness is our donated CNCF project — CI/lock complements it, it doesn't replace it.
      </p>
    </div>
  );
}

export default function FromWitnessPage(): React.ReactElement {
  return (
    <Layout
      title="CI/lock — from the team that built Witness"
      description="CI/lock is TestifySec's second in-toto implementation. It speaks the same DSSE/in-toto envelopes as Witness, so either tool verifies the other's evidence — plus keyless Fulcio + RFC 3161 signing and a human-signed release gate.">
      <Head>
        <meta property="og:title" content="CI/lock — from the team that built Witness" />
        <meta
          property="og:description"
          content="The same DSSE/in-toto envelopes as Witness, so either tool verifies the other's evidence — plus a human-signed release gate that cosign and SLSA generators don't give you."
        />
        <meta property="og:type" content="website" />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="CI/lock — from the team that built Witness" />
        <meta
          name="twitter:description"
          content="The same DSSE/in-toto envelopes as Witness, so either tool verifies the other's evidence — plus a human-signed release gate."
        />
      </Head>
      <FromWitnessInner />
    </Layout>
  );
}
