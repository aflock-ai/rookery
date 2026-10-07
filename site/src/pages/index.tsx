import React from "react";
import Link from "@docusaurus/Link";
import Head from "@docusaurus/Head";
import Layout from "@theme/Layout";
import Heading from "@theme/Heading";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import useBaseUrl from "@docusaurus/useBaseUrl";
import CastPlayer from "../components/CastPlayer";
import styles from "./index.module.css";
import {productFamily} from "../data/product-family.generated";

function Hero() {
  return (
    <header className={styles.hero}>
      <div className={styles.heroInner}>
        <div className={styles.heroCopy}>
          <Heading as="h1" className={styles.heroTitle}>
            Record the work. Prove what ran.
          </Heading>
          <p className={styles.heroSub}>
            CI/lock is TestifySec’s enterprise attestation tooling, built on the in-toto™
            specification. Capture signed evidence from the builds, tests, and scans your developers
            and agents already run.
          </p>
          <div className={styles.heroCtas}>
            <Link to="/getting-started/installation" className={styles.ctaPrimary}>
              Install CI/lock
            </Link>
            <Link to="/getting-started/first-attestation" className={styles.ctaSecondary}>
              Capture your first result
            </Link>
            <Link to="https://github.com/aflock-ai/rookery" className={styles.ctaTertiary}>
              View on GitHub →
            </Link>
          </div>
        </div>
        <div className={styles.heroDemo}>
          {/* A REAL Claude Code session, recorded with asciinema and replayed
              by the asciinema-player (real selectable text — far lighter than a
              GIF). A pinned CI dependency had its tag force-pushed into a
              credential harvester; the developer asks Claude to check whether
              it's safe before shipping. Claude runs it under CI/lock and the
              kernel tells the truth. The <pre> is the no-JS / SSR fallback. */}
          <CastPlayer
            src={useBaseUrl("/img/ci-credential-harvester.cast")}
            label="A Claude Code session catching a compromised CI dependency with CI/lock — eBPF tracing and secret scanning catch the credential theft and the policy blocks the release"
            poster="npt:1:20"
            autoPlay
            controls
            fallback={
              <pre className={styles.heroTerminal}>
                <code>
                  {`❯ We pin build-helper@v1.0.3 in CI. Before we ship, check
  whether it's safe and gate the release.

⏺ cilock run --step ci-task --trace -a environment,secretscan -- ./build-helper.sh
  ⎿ cilock: tracing mode = eBPF (kernel-side capture)
     ⚠ process tree: cat /proc/self/environ · cat aws-credentials
     ⚠ connect() 169.254.169.254:80  (cloud metadata SSRF)
     ⚠ secretscan: github-pat leaked

⏺ cilock verify -p ci.policy.signed.json ...
  ⎿ ✗ Verification failed — credential leak detected in CI step

⏺ A force-pushed tag slipped past SHA-pinning, but cilock caught
  the credential theft at the kernel and the policy blocked it.`}
                </code>
              </pre>
            }
          />
        </div>
      </div>
    </header>
  );
}

function EvidenceWorkflows() {
  const cards = [
    {
      title: "Record a build.",
      body: "Keep a signed record of the inputs, execution, and outputs behind an artifact.",
      href: "/tutorials/github-actions-pipeline",
      cta: "Explore build evidence",
    },
    {
      title: "Keep the test result.",
      body: "Capture evidence from your existing checks so reviewers can inspect what ran and what it returned.",
      href: "/getting-started/first-attestation",
      cta: "Capture your first result",
    },
    {
      title: "Verify against requirements.",
      body: "Evaluate the supplied evidence against a policy. Inspect the result before making a decision.",
      href: "/concepts/policy-verification",
      cta: "Understand verification",
    },
  ];
  return (
    <section className={styles.section}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          Your existing tools. Evidence you can inspect.
        </Heading>
        <p className={styles.sectionLede}>
          Start with a command you already run. Make its result available to the people and systems
          that need to verify it.
        </p>
        <div className={styles.familyGrid}>
          {cards.map((card) => (
            <article className={styles.familyCard} key={card.title}>
              <Heading as="h3">{card.title}</Heading>
              <p>{card.body}</p>
              <Link to={card.href}>{card.cta} →</Link>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

function ConnectedProducts() {
  const iconBase = useBaseUrl("/img/product-logos/");
  return (
    <section className={`${styles.section} ${styles.sectionPlatform}`}>
      <div className={styles.sectionInner}>
        <div className={styles.platformEyebrow}>{productFamily.category}</div>
        <Heading as="h2" className={styles.sectionTitle}>
          One connected workflow. Three clear jobs.
        </Heading>
        <p className={styles.sectionLede}>
          CI/lock records the work. Use its evidence at a Pushgate checkpoint, then manage your
          gates and technical control evidence in the TestifySec platform.
        </p>
        <div className={styles.familyGrid}>
          {productFamily.products.map((product) => (
            <article className={styles.familyCard} key={product.id}>
              <img src={`${iconBase}${product.id}.svg`} alt="" width="36" height="36" />
              <span className={styles.familyLabel}>
                {product.name}
                {product.id === "cilock" ? " · You are here" : ""}
              </span>
              <Heading as="h3">{product.job}</Heading>
              <p>{product.description}</p>
              <Link to={product.id === "cilock" ? "/getting-started/installation" : product.href}>
                {product.id === "cilock" ? "Get started" : product.cta} →
              </Link>
            </article>
          ))}
        </div>
        <p className={styles.familyFootnote}>
          Platform capabilities, deployment options, and pricing live on{" "}
          <Link to="https://testifysec.com/product">testifysec.com</Link>. Find technical guides for
          all three products in the <Link to="https://testifysec.com/docs">documentation hub</Link>.
        </p>
      </div>
    </section>
  );
}

function NextSteps() {
  return (
    <section className={styles.section}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          Go deeper when you need to.
        </Heading>
        <div className={styles.familyGrid}>
          <article className={styles.familyCard}>
            <Heading as="h3">Open foundations.</Heading>
            <p>
              CI/lock shares Witness’s attestation foundation and adds capabilities and commercial
              support from TestifySec. Compatibility depends on the evidence type.
            </p>
            <Link to="/ecosystem/witness">Read the compatibility guide →</Link>
          </article>
          <article className={styles.familyCard}>
            <Heading as="h3">Understand the boundaries.</Heading>
            <p>
              Learn what an attestation establishes, how policy verification works, and where your
              evidence sources matter.
            </p>
            <Link to="/concepts/attestations">Explore the evidence model →</Link>
          </article>
          <article className={styles.familyCard}>
            <Heading as="h3">Choose your next check.</Heading>
            <p>Find tool support, commands, and setup instructions in the reference.</p>
            <Link to="/tools/">Browse supported tools →</Link>
          </article>
        </div>
        <p className={styles.familyFootnote}>in-toto is a trademark of The Linux Foundation.</p>
      </div>
    </section>
  );
}

const HOMEPAGE_DESCRIPTION =
  "CI/lock is enterprise attestation tooling built on the in-toto specification. Capture and verify signed evidence from the commands your developers and agents run.";

const STRUCTURED_DATA = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareApplication",
      name: "CI/lock",
      applicationCategory: "DeveloperApplication",
      operatingSystem: "Linux, macOS, Windows",
      url: "https://cilock.dev",
      description: HOMEPAGE_DESCRIPTION,
      license: "Apache-2.0",
      offers: {
        "@type": "Offer",
        price: "0",
        priceCurrency: "USD",
      },
    },
    {
      "@type": "Organization",
      name: "TestifySec",
      url: "https://www.testifysec.com",
    },
  ],
};

export default function Home(): React.ReactElement {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title} — Record the work. Prove what ran.`}
      description={HOMEPAGE_DESCRIPTION}
    >
      <Head>
        <script type="application/ld+json">{JSON.stringify(STRUCTURED_DATA)}</script>
      </Head>
      <Hero />
      <main>
        <EvidenceWorkflows />
        <ConnectedProducts />
        <NextSteps />
      </main>
    </Layout>
  );
}
