import React, {useState} from 'react';
import Layout from '@theme/Layout';
import Head from '@docusaurus/Head';
import Heading from '@theme/Heading';
import Link from '@docusaurus/Link';
import {fireConversion} from '../lib/adsConversions';
import {PLATFORM_SIGNUP_URL} from '../lib/platform';
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
        CI/lock builds on the in-toto™ specification and the Witness attestation foundation.
        Record your workflows with CI/lock, and check compatibility before migrating existing policies.
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
          <Link
            className={styles.secondaryCta}
            to={PLATFORM_SIGNUP_URL}
            onClick={() => fireConversion('platformSignup', 100)}>
            Start for free on the platform →
          </Link>
          <a
            className={styles.secondaryCta}
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            onClick={() => fireConversion('githubOutbound', 5)}>
            View on GitHub →
          </a>
          <Link className={styles.tertiaryCta} to="/ecosystem/witness">
            Witness compatibility
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
              CI/lock can verify legacy Witness collections. Witness does not verify all CI/lock-native
              predicates. Check your evidence format, signer trust, and policy requirements in the
              compatibility guide before switching tools.
            </p>
          </div>

          <div className={styles.block}>
            <Heading as="h3" className={styles.blockTitle}>
              What's new
            </Heading>
            <p className={styles.blockBody}>
              CI/lock wraps any CI/CD command and records <em>what actually ran</em> — source, env,
              argv, and input/output digests. Keyless signing with Fulcio + an RFC&nbsp;3161 TSA,
              verifiable fully offline. Use signed policies to check the evidence your workflow requires.
              Pushgate applies requirements at the Git push boundary; the platform manages gates across repositories.
            </p>
          </div>

          <div className={styles.block}>
            <Heading as="h3" className={styles.blockTitle}>
              Free hosted tier
            </Heading>
            <p className={styles.blockBody}>
              Already signing with Witness? Point CI/lock at the{' '}
              <a
                href={PLATFORM_SIGNUP_URL}
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => fireConversion('platformSignup', 100)}>
                hosted TestifySec Platform
              </a>{' '}
              and sign in — keyless Fulcio signing, hosted Archivista storage,
              and attestation verification are free with an account. Your
              envelopes verify unchanged; you just stop operating the trust
              infrastructure. <Link to="/free">What's free →</Link>
            </p>
          </div>
        </div>
      </section>

      {/* Trust / optics line — Witness is our donated CNCF project; CI/lock
          complements it, it does not replace it. */}
      <p className={styles.optics}>
        Witness is an open-source project within in-toto. CI/lock adds TestifySec’s enterprise attestation tooling. See the Witness compatibility guide before migrating.
      </p>
    </div>
  );
}

export default function FromWitnessPage(): React.ReactElement {
  return (
    <Layout
      title="CI/lock — from the team that built Witness"
      description="Move from Witness to CI/lock with a clear view of evidence, policy, and signer compatibility.">
      <Head>
        <meta property="og:title" content="CI/lock — from the team that built Witness" />
        <meta
          property="og:description"
          content="Understand compatibility when moving from Witness to CI/lock, TestifySec’s enterprise attestation tooling."
        />
        <meta property="og:type" content="website" />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="CI/lock — from the team that built Witness" />
        <meta
          name="twitter:description"
          content="Understand compatibility when moving from Witness to CI/lock, TestifySec’s enterprise attestation tooling."
        />
      </Head>
      <FromWitnessInner />
    </Layout>
  );
}
