import React, {useState} from 'react';
import Link from '@docusaurus/Link';
import Heading from '@theme/Heading';
import CastPlayer from '../CastPlayer';
import styles from './styles.module.css';

type Slide = {
  persona: string;
  title: string;
  body: string;
  cast: string;
  poster: string;
  label: string;
  href: string;
  cta: string;
};

// Three slides, one per ICP persona. The casts are real Claude Code sessions
// (see /use-cases). Only the active slide mounts a player, so we never autoplay
// three terminals at once.
const SLIDES: Slide[] = [
  {
    persona: 'DevOps',
    title: 'Gate the release on signed evidence',
    body: 'A developer asks Claude to check the release. CI/lock verifies the signed vulnerability-scan attestation against a Witness policy — approved key, approved source — and the gate passes. One command, in or out of CI.',
    cast: '/img/release-gate-pass.cast',
    poster: 'npt:0:15',
    label: 'A Claude Code session verifying a release against a Witness policy that passes',
    href: '/use-cases/release-gates#the-gate-passes',
    cta: 'See the release-gate use case →',
  },
  {
    persona: 'Security',
    title: 'Rebuild a compromised package from your own source',
    body: 'LiteLLM was backdoored on PyPI. Claude stands up an internal supply chain: build the wheel from a forked source under eBPF tracing, scan it, verify the chain against a signed policy, and install it — with zero network egress and no .pth injection, all captured at the kernel.',
    cast: '/img/hero-demo.cast',
    poster: 'npt:1:15',
    label: 'A Claude Code session building LiteLLM from a forked source with CI/lock under eBPF tracing',
    href: '/use-cases',
    cta: 'Explore the use cases →',
  },
  {
    persona: 'GRC',
    title: 'Signed compliance evidence, mapped to controls',
    body: 'A CIS Ubuntu 24.04 scan becomes a signed, tamper-evident attestation — 220 pass / 113 fail, mapped to NIST 800-53 and FedRAMP. A signed policy blocks the release on high-severity failures, and an auditor reads the report instead of re-running the scan. The compliance scanners are compiled in with the Apache-2.0 rookery builder.',
    cast: '/img/grc-compliance.cast',
    poster: 'npt:1:05',
    label: 'A Claude Code session running a CIS compliance scan with a custom cilock-grc binary, gated by a signed policy and mapped to NIST 800-53 and FedRAMP',
    href: '/use-cases/compliance-gate',
    cta: 'See the compliance use case →',
  },
];

export default function UseCaseCarousel(): React.ReactElement {
  const [active, setActive] = useState(0);
  const slide = SLIDES[active];
  const go = (i: number) => setActive((i + SLIDES.length) % SLIDES.length);

  return (
    <section className={styles.section}>
      <div className={styles.sectionInner}>
        <Heading as="h2" className={styles.title}>
          Three teams, one evidence model.
        </Heading>
        <p className={styles.lede}>
          Real Claude Code sessions driving the real CI/lock CLI. Pick the seat
          you sit in.
        </p>

        <div className={styles.tabs} role="tablist" aria-label="Use cases by role">
          {SLIDES.map((s, i) => (
            <button
              key={s.persona}
              role="tab"
              aria-selected={i === active}
              className={`${styles.tab} ${i === active ? styles.tabActive : ''}`}
              onClick={() => setActive(i)}>
              {s.persona}
            </button>
          ))}
        </div>

        <div className={styles.stage}>
          <button
            className={`${styles.arrow} ${styles.arrowLeft}`}
            aria-label="Previous use case"
            onClick={() => go(active - 1)}>
            ‹
          </button>

          <div className={styles.slide}>
            <div className={styles.copy}>
              <span className={styles.chip}>{slide.persona} engineer</span>
              <Heading as="h3" className={styles.slideTitle}>
                {slide.title}
              </Heading>
              <p className={styles.slideBody}>{slide.body}</p>
              <Link to={slide.href} className={styles.slideLink}>
                {slide.cta}
              </Link>
            </div>
            <div className={styles.player}>
              <CastPlayer
                key={slide.cast}
                src={slide.cast}
                poster={slide.poster}
                label={slide.label}
                autoPlay
                controls
              />
            </div>
          </div>

          <button
            className={`${styles.arrow} ${styles.arrowRight}`}
            aria-label="Next use case"
            onClick={() => go(active + 1)}>
            ›
          </button>
        </div>

        <div className={styles.dots} role="tablist" aria-label="Select use case">
          {SLIDES.map((s, i) => (
            <button
              key={s.persona}
              aria-label={`Show ${s.persona} use case`}
              aria-selected={i === active}
              className={`${styles.dot} ${i === active ? styles.dotActive : ''}`}
              onClick={() => setActive(i)}
            />
          ))}
        </div>
      </div>
    </section>
  );
}
