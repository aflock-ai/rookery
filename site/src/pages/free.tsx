import React from 'react';
import Link from '@docusaurus/Link';
import Head from '@docusaurus/Head';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import {fireConversion} from '../lib/adsConversions';
import {PLATFORM_URL, PLATFORM_SIGNUP_URL} from '../lib/platform';
// Reuse the homepage's design primitives (hero, section, cta*, platform*) so the
// free-tier page reads as one system with index.tsx; free.module.css adds only
// the page-specific bits.
import styles from './index.module.css';
import f from './free.module.css';

const DESCRIPTION =
  "Turn your security process into compliance evidence — free with a TestifySec account. Download CI/lock, connect your repos and pipelines, and our AI agent uses your code and your testing as the answer key: keyless Fulcio signing, hosted attestation storage with 7-day retention, attestation and policy verification, and single-pass Security Essentials scans on the open-source 120B model, at no cost.";

// "Start free" → self-serve registration, firing the platformSignup Ads
// conversion. One component so every CTA on the page is identical.
function StartFree({
  className,
  children,
  value = 100,
}: {
  className: string;
  children: React.ReactNode;
  value?: number;
}): React.ReactElement {
  return (
    <Link
      to={PLATFORM_SIGNUP_URL}
      className={className}
      onClick={() => fireConversion('platformSignup', value)}>
      {children}
    </Link>
  );
}

function Hero(): React.ReactElement {
  return (
    <header className={styles.hero}>
      <div className={styles.heroInner}>
        <div className={styles.heroCopy}>
          <div className={styles.platformEyebrow}>Free with a TestifySec account</div>
          <Heading as="h1" className={styles.heroTitle}>
            Turn your security process into compliance evidence.
          </Heading>
          <p className={styles.heroSub}>
            Stop fielding questions from GRC teams —{' '}
            <strong>
              our AI agent uses your code and your testing as the answer key
            </strong>
            . Download CI/lock, connect your repos and pipelines, and sign in
            once from the CLI (the approve page creates your workspace if you
            don't have one). The platform is where it comes together: keyless
            Fulcio signing, hosted attestation storage with 7-day retention,
            and full attestation and policy verification, at no cost.
          </p>
          <div className={styles.heroCtas}>
            <StartFree className={styles.ctaPrimary}>Start for free →</StartFree>
            <Link to="/getting-started/installation" className={styles.ctaSecondary}>
              Install CI/lock
            </Link>
            <Link
              to="/guides/store-attestations-in-archivista"
              className={styles.ctaTertiary}>
              How storage works →
            </Link>
          </div>
          <p className={f.consentNote}>
            Signing in is the consent and the identity — there is no anonymous
            telemetry. Offline signing with your own keys stays free forever;
            the platform is optional, never required.
          </p>
        </div>
        <div className={styles.heroDemo}>
          <pre className={styles.heroTerminal}>
            <code>
{`# 1. Download CI/lock
curl -fsSL https://cilock.dev/install.sh | bash

# 2. Sign in — defaults to ${PLATFORM_URL};
#    the approve page creates your workspace if you have none
cilock login

# 3. Your next build: signed with a keyless Fulcio cert +
#    RFC 3161 timestamp, stored in the hosted platform
cilock run --step build -- go build -o ./my-service .

# 4. Verify anywhere — point at the artifact; its sha256 subject
#    is computed for you, trust comes from the platform
cilock verify ./my-service`}
            </code>
          </pre>
        </div>
      </div>
    </header>
  );
}

// Two evidence-first entry lanes (GRC / CI-CD), converging on the platform.
// The browser-first path is kept below as the deliberately secondary option.
function PersonaLanes(): React.ReactElement {
  return (
    <section className={`${styles.section} ${styles.sectionDark}`}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          Start where you work.
        </Heading>
        <p className={styles.sectionLede}>
          Your security process is already producing the answers. CI/lock signs
          it into evidence wherever it happens — production or pipeline.
        </p>
        <div className={f.laneGrid}>
          <div className={f.feature}>
            <div className={f.laneRole}>GRC engineer</div>
            <div className={f.featureTitle}>Scan what's running</div>
            <p className={f.featureBody}>
              Stop chasing engineers for answers. Point CI/lock at production —
              CSPM, STIG, FIPS scans — and get signed evidence about what{' '}
              <em>is</em>, not what a spreadsheet says it should be.
            </p>
            <pre className={f.laneCmd}>
              <code>
{`# Wrap a production-side scan — signed evidence of what IS
cilock run --step cspm -- prowler aws`}
              </code>
            </pre>
          </div>
          <div className={f.feature}>
            <div className={f.laneRole}>CI/CD developer</div>
            <div className={f.featureTitle}>Instrument your pipelines</div>
            <p className={f.featureBody}>
              Your pipeline instrumentation <em>is</em> the audit trail. Wrap
              builds with cilock or cilock-action and every run emits signed
              provenance about how it's built.
            </p>
            <pre className={f.laneCmd}>
              <code>
{`# One step in your workflow — signed provenance per run
- uses: aflock-ai/cilock-action@v1
  with:
    command: go build ./...`}
              </code>
            </pre>
          </div>
        </div>
        <p className={styles.threatTakeaway}>
          Both lanes land in the same place:{' '}
          <strong>the platform brings your evidence together</strong> —
          storage, verification, and Security Essentials scans.
        </p>
        <p className={f.browserPath}>
          Prefer to start in the browser?{' '}
          <StartFree className={f.browserPathLink}>
            Start for free →
          </StartFree>{' '}
          sign up, scan your code and docs from the platform, and bring CI/lock
          in when you're ready.
        </p>
      </div>
    </section>
  );
}

function Included(): React.ReactElement {
  const items = [
    {
      title: 'Keyless signing (Fulcio)',
      body: 'Short-lived identity certificates minted from your OIDC login. No signing keys to generate, store, rotate, or leak — the platform runs the Fulcio CA and an RFC 3161 timestamp authority for you.',
    },
    {
      title: 'Hosted attestation storage — 7-day retention',
      body: 'Every DSSE + in-toto envelope you produce is stored, indexed, and queryable in hosted Archivista, retained for 7 days on the free tier. You do not run the store, the database, or the blob backend.',
    },
    {
      title: 'Attestation + policy verification',
      body: 'Verify any artifact against a signed policy. The platform holds the Fulcio and TSA trust roots, so `cilock verify` works without you distributing roots or pinning keys by hand.',
    },
    {
      title: 'Security Essentials scans',
      body: 'Single-pass Security Essentials scans over your evidence, run on the open-source 120B model — the same scan the paid tiers run with multiple passes and larger model classes.',
    },
  ];
  return (
    <section className={styles.section}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          What you get, free.
        </Heading>
        <p className={styles.sectionLede}>
          The free tier is the real product, not a crippled trial. It is the
          same signing, storage, and verification the paid platform runs —
          scoped to 7-day retention and single-pass scans on the open-source
          120B model.
        </p>
        <div className={f.featureGrid}>
          {items.map((it) => (
            <div key={it.title} className={f.feature}>
              <div className={f.featureTitle}>{it.title}</div>
              <p className={f.featureBody}>{it.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function AlreadyOSS(): React.ReactElement {
  return (
    <section className={`${styles.section} ${styles.sectionDark}`}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          Already using the OSS?
        </Heading>
        <p className={styles.sectionLede}>
          CI/lock and Witness produce the same DSSE + in-toto envelopes, and
          Archivista is the same evidence store the platform hosts. If you
          already sign with Witness or self-host Archivista, the free tier is
          what you get when you stop operating the trust infrastructure
          yourself — point the tool at the platform and sign in.
        </p>
        <ul className={styles.useList}>
          <li>
            <strong>Witness users</strong> — point Witness's Archivista URL at
            the hosted platform and sign in; your envelopes verify unchanged.
          </li>
          <li>
            <strong>Self-hosting Archivista</strong> — keep your own store, or
            push new evidence to the hosted one and drop the ops burden.
          </li>
          <li>
            <strong>Air-gapped / your own keys</strong> — offline signing stays
            free forever; the platform never becomes a dependency.
          </li>
        </ul>
        <div className={styles.heroCtas}>
          <StartFree className={styles.ctaPrimary}>Start for free →</StartFree>
          <Link to="/from-witness" className={styles.ctaSecondary}>
            Coming from Witness?
          </Link>
        </div>
      </div>
    </section>
  );
}

function FreeVsPaid(): React.ReactElement {
  return (
    <section className={styles.sectionPlatform}>
      <div className={styles.sectionInner}>
        <div className={styles.platformEyebrow}>Honest about the wall</div>
        <Heading as="h2" className={styles.sectionTitle}>
          Free floor, paid ceiling.
        </Heading>
        <p className={styles.sectionLede}>
          Signing, storage, and verification are free with an account. The paid
          TestifySec Platform adds longer retention, multi-pass scanning, the
          frontier and balanced model classes, the compliance frameworks, and
          multi-team operation.
        </p>
        <div className={styles.platformGrid}>
          <div className={styles.platformCol}>
            <div className={styles.platformColTitle}>Free with an account</div>
            <ul className={styles.platformList}>
              <li>Keyless Fulcio signing + RFC 3161 timestamps</li>
              <li>Hosted attestation storage — 7-day retention</li>
              <li>Attestation + signed-policy verification</li>
              <li>
                Security Essentials scans — single-pass, on the open-source
                120B model
              </li>
            </ul>
          </div>
          <div className={styles.platformCol}>
            <div className={styles.platformColTitle}>Paid — TestifySec Platform</div>
            <ul className={f.paidList}>
              <li>
                <strong>Longer / unlimited retention</strong> — your evidence
                history, kept
              </li>
              <li>
                <strong>Multi-pass Union-of-3 scanning</strong> — three
                independent passes, unioned
              </li>
              <li>
                <strong>Frontier + balanced model classes</strong> for
                higher-fidelity analysis
              </li>
              <li>
                <strong>Full compliance frameworks</strong> — SSP generation
                and FedRAMP control mapping
              </li>
              <li>
                <strong>Multi-tenant organizations</strong> — multiple teams,
                shared policy, and role-based access
              </li>
            </ul>
          </div>
        </div>
        <div className={styles.platformCtas}>
          <StartFree className={styles.ctaPrimary}>Start for free →</StartFree>
          <Link to="https://testifysec.com/pricing" className={styles.ctaSecondary}>
            See pricing
          </Link>
          <Link
            to="https://testifysec.com/#contact"
            className={styles.ctaTertiary}
            onClick={() => fireConversion('platformSignup', 100)}>
            Book a demo →
          </Link>
        </div>
      </div>
    </section>
  );
}

function FinalCta(): React.ReactElement {
  return (
    <section className={`${styles.section} ${styles.sectionAccent}`}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          Your next build can answer for itself.
        </Heading>
        <p className={styles.sectionLede}>
          Download CI/lock, sign in, and your next build is signed, stored, and
          verifiable — no keys, no infrastructure, no card.
        </p>
        <div className={styles.heroCtas}>
          <StartFree className={styles.ctaSecondary}>Start for free →</StartFree>
          <Link to="/getting-started/installation" className={f.accentLink}>
            Install CI/lock →
          </Link>
        </div>
      </div>
    </section>
  );
}

export default function FreePage(): React.ReactElement {
  return (
    <Layout
      title="Start free — hosted signing, storage & verify"
      description={DESCRIPTION}>
      <Head>
        <meta property="og:title" content="Start free — TestifySec Platform" />
        <meta property="og:description" content={DESCRIPTION} />
        <meta property="og:type" content="website" />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="Start free — TestifySec Platform" />
        <meta name="twitter:description" content={DESCRIPTION} />
      </Head>
      <Hero />
      <main>
        <PersonaLanes />
        <Included />
        <AlreadyOSS />
        <FreeVsPaid />
        <FinalCta />
      </main>
    </Layout>
  );
}
