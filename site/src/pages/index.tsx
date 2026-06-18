import React from 'react';
import Link from '@docusaurus/Link';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import CastPlayer from '../components/CastPlayer';
import UseCaseCarousel from '../components/UseCaseCarousel';
import styles from './index.module.css';

function Hero() {
  return (
    <header className={styles.hero}>
      <div className={styles.heroInner}>
        <div className={styles.heroCopy}>
          <Heading as="h1" className={styles.heroTitle}>
            Trusted telemetry for every checkpoint between commit and production.
          </Heading>
          <p className={styles.heroSub}>
            CI/lock <strong>collects trusted telemetry</strong> across every
            stage of your software's life — build, security scan, deploy,
            runtime, and compliance. Wrap any command that produces structured
            output and CI/lock signs the result into in-toto evidence: what
            executed, on what inputs, in what environment, and what it
            produced. Verifiable, policy-checkable, portable.
          </p>
          <div className={styles.heroCtas}>
            <Link to="/getting-started/installation" className={styles.ctaPrimary}>
              Get started
            </Link>
            <Link
              to="https://github.com/aflock-ai/rookery"
              className={styles.ctaSecondary}>
              View on GitHub
            </Link>
            <Link
              to="/tutorials/defending-against-supply-chain-attacks"
              className={styles.ctaTertiary}>
              Read the threat story →
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
            src="/img/ci-credential-harvester.cast"
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

function FourPillars() {
  const cards = [
    {
      title: 'Build provenance',
      body: 'Sign every CI/CD run. SLSA-aligned in-toto attestations from GitHub Actions and GitLab CI, signed with a Fulcio identity certificate and RFC 3161 timestamp.',
      tags: ['SLSA', 'GitHub Actions', 'GitLab CI', 'in-toto'],
      href: '/tutorials/github-actions-pipeline',
    },
    {
      title: 'Security scan evidence',
      body: 'Wrap SAST, DAST, SBOM generation, SARIF emitters, and secret scanners — OWASP ZAP, Nuclei, Semgrep, gosec, Trivy, Grype, Gitleaks. Prove they ran on this artifact with the exact output, before it ships.',
      tags: ['SAST', 'DAST', 'SBOM', 'SARIF'],
      href: '/tools',
    },
    {
      title: 'Runtime + cluster integrity',
      body: 'Capture signed evidence of cluster state and runtime security — Falco events, Linkerd service-mesh mTLS, kube-bench CIS benchmarks. Release-gate on "no insecure edges" or "zero critical Falco events," not just on what scanners flagged.',
      tags: ['Falco', 'Linkerd', 'kube-bench', 'Kubernetes'],
      href: '/tools/linkerd',
    },
    {
      title: 'Continuous compliance',
      body: 'Production-side scans — Prowler CSPM, OpenSCAP/STIG, InSpec, testssl.sh FIPS — produce signed evidence auditors verify without re-running anything. The TestifySec Platform maps every attestation to NIST 800-53, FedRAMP, and SOC 2 controls automatically.',
      tags: ['FedRAMP', 'SOC 2', 'FIPS 140', 'CSPM'],
      href: '/guides/store-attestations-in-archivista',
    },
  ];
  return (
    <section className={styles.section}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          Four checkpoints, one evidence model.
        </Heading>
        <p className={styles.sectionLede}>
          The DSSE + in-toto envelopes CI/lock emits are the same shape across
          every stage. Policy verification at release time consumes evidence
          collected at build time, scan time, runtime, and audit time without
          translation.
        </p>
        <div className={styles.cardGrid}>
          {cards.map((c) => (
            <Link key={c.title} to={c.href} className={styles.card}>
              <div className={styles.cardTitle}>{c.title}</div>
              <p className={styles.cardBody}>{c.body}</p>
              <div className={styles.cardTags}>
                {c.tags.map((t) => (
                  <span key={t} className={styles.tag}>
                    {t}
                  </span>
                ))}
              </div>
              <div className={styles.cardLink}>Learn more →</div>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

function ThreatStory() {
  return (
    <section className={`${styles.section} ${styles.sectionDark}`}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          Why this exists.
        </Heading>
        <p className={styles.sectionLede}>
          Two pressures push the same direction. Supply-chain attacks have
          moved past tag-pinning hygiene, and the regulatory environment now
          demands machine-readable evidence of every step, not just a passing
          CI badge.
        </p>
        <div className={styles.threatGrid}>
          <div className={styles.threatItem}>
            <div className={styles.threatDate}>March 19, 2026</div>
            <p>
              An attacker force-pushed 75 of 76 version tags in{' '}
              <code>aquasecurity/trivy-action</code>. Every pipeline pinned to a
              tag silently ran credential-harvesting code on its next trigger.
              Secrets were swept from <code>/proc/&lt;pid&gt;/environ</code>,
              encrypted, and exfiltrated to a typosquat domain.
            </p>
          </div>
          <div className={styles.threatItem}>
            <div className={styles.threatDate}>March 24, 2026</div>
            <p>
              <code>litellm==1.82.7</code> and <code>1.82.8</code> shipped to
              PyPI with a credential stealer hidden in a <code>.pth</code> file
              that executed on every Python interpreter startup. No{' '}
              <code>import litellm</code> required. SSH keys, cloud
              credentials, Kubernetes tokens, shell history — all gone.
            </p>
          </div>
        </div>
        <p className={styles.threatTakeaway}>
          Same playbook. Same defense gap: CI trusted code it shouldn't have,
          with credentials it shouldn't have had, and there was no signed
          record of what actually ran.{' '}
          <strong>CI/lock is the structural fix.</strong>
        </p>
        <div className={styles.threatGrid} style={{marginTop: '2.5rem'}}>
          <div className={styles.threatItem}>
            <div className={styles.threatDate}>FedRAMP 20x</div>
            <p>
              The FedRAMP modernization framework moves continuous monitoring
              from quarterly PDFs to <strong>machine-readable, key-based,
              automated verification</strong>. CI/lock emits signed in-toto
              attestations that satisfy the "key indicator" + "continuous
              evidence" requirements without manual reconstruction.
            </p>
          </div>
          <div className={styles.threatItem}>
            <div className={styles.threatDate}>EU Cyber Resilience Act</div>
            <p>
              The CRA requires manufacturers of products with digital elements
              to maintain an SBOM, document vulnerability handling, and prove
              secure development practices for the full product lifecycle.
              CI/lock's <code>sbom</code>, <code>vex</code>, and per-step
              attestors produce that proof as a byproduct of normal CI, not
              as a separate audit exercise.
            </p>
          </div>
          <div className={styles.threatItem}>
            <div className={styles.threatDate}>NIST 800-204D · SLSA · CMMC</div>
            <p>
              <a href="https://csrc.nist.gov/pubs/sp/800/204/d/final">
                NIST SP 800-204D
              </a>{' '}
              (DevSecOps integration strategies — TestifySec contributed),
              SLSA build-track requirements, and the DoD's CMMC level-2/3
              controls all converge on the same primitive: signed, structured
              evidence of build, source, and runtime state. One pipeline
              observer, multiple compliance regimes.
            </p>
          </div>
          <div className={styles.threatItem}>
            <div className={styles.threatDate}>AI-agent governance</div>
            <p>
              AI agents now write code, modify CI, and ship releases. The
              structural fix is the same as for supply-chain attacks:{' '}
              <strong>human-controlled cryptographic gates</strong>. The agent
              can produce evidence; only a human-signed policy decides whether
              the artifact ships. CI/lock's signed policies + functionary
              constraints + VSAs are the primitive.{' '}
              <a href="https://aflock.ai">aflock</a> applies this pattern
              end-to-end for agent-driven workflows.
            </p>
          </div>
        </div>
        <p className={styles.threatTakeaway}>
          Whether the trigger is a supply-chain attack, a federal audit
          deadline, or an AI agent with the CI keys, the answer is the same:{' '}
          <strong>signed evidence at every checkpoint</strong>, gated by
          policies humans cryptographically authored.
        </p>
      </div>
    </section>
  );
}

function ThreeLayers() {
  return (
    <section className={styles.section}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          Three independent layers of defense.
        </Heading>
        <p className={styles.sectionLede}>
          SHA pinning alone isn't enough. The action you pinned to can be
          compromised by a maintainer, a stolen credential, or a typo-squat.
          CI/lock catches supply-chain attacks at three layers, so an attacker
          has to bypass all three to succeed.
        </p>
        <div className={styles.layerGrid}>
          <div className={styles.layer}>
            <div className={styles.layerNum}>1</div>
            <div className={styles.layerName}>Prevention</div>
            <p>
              Restrict actions to an approved catalog and enforce SHA pinning
              with a signed Rego policy. Untrusted refs never execute.
            </p>
          </div>
          <div className={styles.layer}>
            <div className={styles.layerNum}>2</div>
            <div className={styles.layerName}>Content detection</div>
            <p>
              <code>secretscan</code> runs Gitleaks on stdout and recursively
              decodes base64, hex, and URL-encoded payloads through three
              layers. Credential patterns trigger a build fail.
            </p>
          </div>
          <div className={styles.layer}>
            <div className={styles.layerNum}>3</div>
            <div className={styles.layerName}>Behavioral detection</div>
            <p>
              <code>--trace</code> records every file each process opens.
              OPA Rego policies match credential-harvesting filesystem
              patterns even when stdout is clean.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

function Quickstart() {
  return (
    <section className={`${styles.section} ${styles.sectionDark}`}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          60 seconds to your first signed attestation.
        </Heading>
        <pre className={styles.quickstart}>
          <code>
{`# 1. Install — platform-signed, verified-before-publish, from cilock.dev
brew install aflock-ai/tap/cilock          # macOS / Linux
# or: curl -fsSL https://cilock.dev/install.sh | bash

# 2. Wrap a command
cilock run --step build \\
           --signer-file-key-path cosign.key \\
           --outfile build.attestation.json \\
           -- go build ./...

# 3. Verify an artifact against a signed policy
#    (-s/-f names the subject; the attestations are the evidence)
cilock verify --policy release.policy.json \\
              --publickey policy-pubkey.pem \\
              --subjects sha1:$COMMIT \\
              --attestations build.attestation.json`}
          </code>
        </pre>
        <p className={styles.quickstartFollowup}>
          Ready for the full walkthrough?{' '}
          <Link to="/getting-started/installation">Installation</Link> ·{' '}
          <Link to="/getting-started/first-attestation">First attestation</Link>{' '}
          ·{' '}
          <Link to="/tutorials/github-actions-pipeline">
            GitHub Actions pipeline
          </Link>
        </p>
      </div>
    </section>
  );
}

function IntotoAndWitness() {
  return (
    <section className={styles.section}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          A new in-toto implementation. We built witness too.
        </Heading>
        <p className={styles.sectionLede}>
          <Link to="https://in-toto.io">in-toto</Link> is a specification —
          signed DSSE envelopes wrapping attestation Statements with subjects
          and predicates. Implementations of the spec produce evidence the
          broader ecosystem can verify.
        </p>
        <p className={styles.sectionLede}>
          <Link to="https://witness.dev">Witness</Link> was our first
          implementation. TestifySec built it, donated it to the{' '}
          <Link to="https://in-toto.io">CNCF in-toto</Link> ecosystem, and it
          is now community-maintained. CI/lock is our second implementation,
          built to address structural choices we'd revisit:
        </p>
        <div className={styles.divergenceGrid}>
          <div className={styles.divergence}>
            <div className={styles.divergenceTitle}>
              Modular core, scoped imports
            </div>
            <p>
              Each attestor and signer is a separate Go module in the{' '}
              <Link to="/ecosystem/rookery">rookery</Link> monorepo. You depend
              on what you use, not on the kitchen sink.
            </p>
          </div>
          <div className={styles.divergence}>
            <div className={styles.divergenceTitle}>
              Attestor factory, not a frozen binary
            </div>
            <p>
              CI/lock isn't one binary you take or leave. The rookery builder
              composes a custom binary from any subset of attestors and
              signers — for air-gapped builds, compliance-heavy environments,
              or evidence types we don't ship by default.
            </p>
          </div>
          <div className={styles.divergence}>
            <div className={styles.divergenceTitle}>
              SDLC-wide, not CI-only
            </div>
            <p>
              Witness is structured around the CI step. CI/lock treats the CI
              step as one shape of attested execution among several —
              dev-time, CI, and continuous production scans share the same
              evidence model.
            </p>
          </div>
          <div className={styles.divergence}>
            <div className={styles.divergenceTitle}>
              Bidirectionally interoperable
            </div>
            <p>
              We aren't forking the format. CI/lock and witness produce the
              same DSSE + in-toto envelopes. Attestations produced by either
              tool verify under the other.
            </p>
          </div>
        </div>
        <p className={styles.sectionLede}>
          <strong>We're not replacing in-toto.</strong> We're contributing
          another implementation that prioritizes a cleaner module boundary
          and an explicit factory model. → <Link to="/ecosystem/witness">CI/lock and Witness</Link>{' '}
          · <Link to="/ecosystem/rookery">CI/lock and Rookery</Link>
        </p>
      </div>
    </section>
  );
}

function BuildYourOwn() {
  return (
    <section className={`${styles.section} ${styles.sectionAccent}`}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          Build your own evidence collector.
        </Heading>
        <p className={styles.sectionLede}>
          CI/lock is one binary, built from <Link to="/ecosystem/rookery">rookery</Link>.{' '}
          Your binary is one <code>go build</code> away.
        </p>
        <ul className={styles.useList}>
          <li>
            <strong>Compliance-heavy environments</strong> — add{' '}
            <code>inspec</code>, <code>kube-bench</code>, <code>nessus</code>,{' '}
            <code>oscap</code>, <code>prowler</code> to the binary.
          </li>
          <li>
            <strong>Air-gapped builds</strong> — drop cloud signers entirely,
            keep <code>file</code> + <code>vault-transit</code>.
          </li>
          <li>
            <strong>Custom evidence</strong> — write your own attestor as a Go
            module. The rookery builder picks it up.
          </li>
        </ul>
        <Link to="/ecosystem/rookery" className={styles.ctaSecondary}>
          Read the rookery builder docs
        </Link>
      </div>
    </section>
  );
}

function ManagedPlatform() {
  return (
    <section className={`${styles.section} ${styles.sectionPlatform}`}>
      <div className={styles.sectionInner}>
        <div className={styles.platformEyebrow}>For teams who'd rather not operate it</div>
        <Heading as="h2" className={styles.sectionTitle}>
          TestifySec Platform — CI/lock, managed.
        </Heading>
        <p className={styles.sectionLede}>
          The same CI/lock attestations, but the Fulcio CA, TSA, evidence store,
          policy distribution, and audit reporting are operated by TestifySec
          and mapped to the compliance frameworks your auditors actually use.
        </p>
        <div className={styles.platformGrid}>
          <div className={styles.platformCol}>
            <div className={styles.platformColTitle}>CI/lock + rookery (OSS)</div>
            <ul className={styles.platformList}>
              <li>Signed evidence at every SDLC stage</li>
              <li>DSSE + in-toto envelopes, witness-compatible</li>
              <li>Bring your own Fulcio, TSA, Archivista</li>
              <li>You distribute and rotate signing policies</li>
              <li>Apache 2.0, self-hosted</li>
            </ul>
          </div>
          <div className={styles.platformCol}>
            <div className={styles.platformColTitle}>
              + TestifySec Platform (managed)
            </div>
            <ul className={styles.platformList}>
              <li>
                Auto-mapped to <strong>NIST 800-53, FedRAMP, SOC 2, FIPS 140</strong>
              </li>
              <li>Managed Fulcio CA + RFC 3161 TSA (10-min identity certs)</li>
              <li>Centralized signed-policy distribution</li>
              <li>
                <strong>GitHub integration</strong> — org-wide attestation policy,
                PR-level evidence checks, and Advanced Security findings mapped
                back to controls
              </li>
              <li>
                <strong>GRC platform integration</strong> — Vanta, Drata, and
                Secureframe dashboards stay accurate without manual uploads
              </li>
              <li>
                Auditor-ready evidence packs — "answer the auditor in 30
                seconds, not three weeks"
              </li>
              <li>Network-restricted / air-gapped operation, vendor support</li>
            </ul>
          </div>
        </div>
        <div className={styles.platformCtas}>
          <Link to="https://testifysec.com/#contact" className={styles.ctaPrimary}>
            See it live in a demo →
          </Link>
          <Link to="https://testifysec.com/pricing" className={styles.ctaSecondary}>
            Pricing
          </Link>
          <Link
            to="/ecosystem/testifysec-platform"
            className={styles.ctaTertiary}>
            How it relates to CI/lock →
          </Link>
        </div>
      </div>
    </section>
  );
}

function Limits() {
  return (
    <section className={styles.section}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          What CI/lock doesn't do.
        </Heading>
        <p className={styles.sectionLede}>
          CI/lock is forensic and policy-driven, not a runtime IPS. We're
          explicit about the limits because trust costs more to recover than
          it costs to set:
        </p>
        <ul className={styles.useList}>
          <li>
            <strong>Detection is post-execution.</strong> If a step exfiltrates
            secrets, the exfiltration already happened. CI/lock blocks the
            release and provides forensic evidence.
          </li>
          <li>
            <strong>Network egress is observed, not blocked.</strong> The trace
            attestor captures every <code>connect</code>, <code>sendto</code>,
            and <code>bind</code> syscall — destination IP, port, address family,
            DNS lookups, and TLS SNI hostname extracted from the ClientHello —
            and policy can fail the build on a bad destination. It does not
            actively block in-flight traffic the way an inline proxy would.
          </li>
          <li>
            <strong>
              <code>--trace</code> is Linux-only and opt-in.
            </strong>{' '}
            Without it, behavioral detection is off.
          </li>
          <li>
            <strong>Novel exfiltration techniques can evade pattern matching</strong>{' '}
            at the content layer. Behavioral detection covers many of these;
            both layers together catch most known playbooks.
          </li>
          <li>
            <strong>CI/lock operates in CI/CD and SDLC tooling.</strong> It
            does not protect developer laptops or production servers as a
            runtime agent.
          </li>
        </ul>
      </div>
    </section>
  );
}

function NextSteps() {
  return (
    <section className={`${styles.section} ${styles.sectionDark}`}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.sectionTitle}>
          Start anywhere.
        </Heading>
        <div className={styles.nextGrid}>
          <Link to="/getting-started/installation" className={styles.nextCard}>
            <div className={styles.nextLabel}>Install</div>
            <div className={styles.nextDesc}>
              brew, curl, Docker, or a SHA-pinned GitHub Action.
            </div>
          </Link>
          <Link
            to="/tutorials/defending-against-supply-chain-attacks"
            className={styles.nextCard}>
            <div className={styles.nextLabel}>Threat walkthrough</div>
            <div className={styles.nextDesc}>
              How CI/lock catches the 2026 Trivy and LiteLLM playbooks end-to-end.
            </div>
          </Link>
          <Link to="/concepts/attestations" className={styles.nextCard}>
            <div className={styles.nextLabel}>Concepts</div>
            <div className={styles.nextDesc}>
              Attestations, attestors, policies, functionaries, and OPA Rego.
            </div>
          </Link>
          <Link
            to="https://github.com/aflock-ai/attestor-compliance-examples/tree/main/43-trivy-attack-detection"
            className={styles.nextCard}>
            <div className={styles.nextLabel}>Detection demo</div>
            <div className={styles.nextDesc}>
              Real attack, real defense. The Trivy / LiteLLM detection test repo.
            </div>
          </Link>
        </div>
      </div>
    </section>
  );
}

export default function Home(): React.ReactElement {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title} — Trusted telemetry for every checkpoint between commit and production`}
      description="CI/lock collects trusted telemetry across every checkpoint between commit and production — CI/CD builds, security scans (SAST/DAST/SBOM), runtime + cluster integrity (Falco, Linkerd mTLS, kube-bench), and continuous compliance (CSPM, FIPS, STIG). Signed as in-toto evidence for FedRAMP 20x, the EU Cyber Resilience Act, NIST 800-204D, SLSA, CMMC, and human-controlled cryptographic gates for AI-agent workflows. Witness-compatible, built on the rookery attestor factory.">
      <Hero />
      <main>
        <UseCaseCarousel />
        <FourPillars />
        <ThreatStory />
        <ThreeLayers />
        <Quickstart />
        <IntotoAndWitness />
        <BuildYourOwn />
        <ManagedPlatform />
        <Limits />
        <NextSteps />
      </main>
    </Layout>
  );
}
