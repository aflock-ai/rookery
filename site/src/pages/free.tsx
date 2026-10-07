import React from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import { fireConversion } from '../lib/adsConversions';
import { PLATFORM_SIGNUP_URL } from '../lib/platform';
import styles from './index.module.css';
import f from './free.module.css';

export default function FreePage(): React.ReactElement {
  return (
    <Layout title="Start with signed evidence" description="Record your first workflow with CI/lock. Connect to TestifySec for hosted signing and evidence storage, then explore Pushgate and the platform.">
      <main>
        <header className={styles.hero}>
          <div className={styles.sectionInner}>
            <p className={styles.platformEyebrow}>Start with CI/lock</p>
            <Heading as="h1" className={styles.heroTitle}>Your first workflow. A verifiable record.</Heading>
            <p className={styles.heroSub}>Capture signed evidence from a build, test, or scan you already run. Use the open-source CLI independently, or connect it to a TestifySec account for hosted signing and storage.</p>
            <div className={styles.heroCtas}>
              <Link to="/getting-started/first-attestation" className={styles.ctaPrimary}>Create your first attestation</Link>
              <Link to={PLATFORM_SIGNUP_URL} className={styles.ctaSecondary} onClick={() => fireConversion('platformSignup', 100)}>Create a TestifySec account</Link>
            </div>
          </div>
        </header>
        <section className={styles.section}>
          <div className={styles.sectionInner}>
            <Heading as="h2" className={styles.sectionTitle}>A small first step.</Heading>
            <div className={f.featureGrid}>
              {[
                ['Install CI/lock', 'Choose the installation method for your environment and verify the release.', '/getting-started/installation'],
                ['Record a workflow', 'Wrap one build, test, or scan. Inspect the signed evidence it produces.', '/getting-started/first-attestation'],
                ['Connect to the platform', 'Configure your signing identity and evidence storage. Review the trust boundary before sharing results.', '/getting-started/connect-to-the-platform'],
              ].map(([title, body, href]) => <div className={f.feature} key={title}><Heading as="h3" className={f.featureTitle}>{title}</Heading><p className={f.featureBody}>{body}</p><Link to={href}>Read the guide →</Link></div>)}
            </div>
          </div>
        </section>
        <section className={`${styles.section} ${styles.sectionDark}`}>
          <div className={styles.sectionInner}>
            <Heading as="h2" className={styles.sectionTitle}>Keep going from the same evidence.</Heading>
            <div className={f.laneGrid}>
              <div className={f.feature}><Heading as="h3" className={f.featureTitle}>Check the push with Pushgate.</Heading><p className={f.featureBody}>Require evidence before a push enters your repository through the gate.</p><Link to="https://pushgate.dev/pricing">Explore Pushgate plans →</Link></div>
              <div className={f.feature}><Heading as="h3" className={f.featureTitle}>Manage trust with the platform.</Heading><p className={f.featureBody}>Manage repository gates, policies, and evidence across your team. Connect technical test results to compliance controls.</p><Link to="https://testifysec.com/pricing">Explore platform plans →</Link></div>
            </div>
            <p className={styles.sectionLede}>Current plan limits and commercial terms live on the product pricing pages. CI/lock’s open-source license does not require a paid platform plan.</p>
          </div>
        </section>
      </main>
    </Layout>
  );
}
