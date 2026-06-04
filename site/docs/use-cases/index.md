---
title: Use cases
description: Real Claude Code sessions driving CI/lock to secure software supply chains — release gates that pass, gates that block a non-compliant build, and more.
sidebar_position: 0
---

# Use cases

Each use case below is a **real, unedited [Claude Code](https://claude.com/claude-code) session** in which a
developer asks Claude to do supply-chain work and Claude runs the real `cilock`
CLI to do it. The recordings are replayed as selectable terminal text (not
video), so you can read every command and every result.

- **[Rebuild a compromised package](./litellm-supply-chain.mdx)** — LiteLLM was
  backdoored on PyPI, so build it yourself from a forked source under eBPF, verify
  the chain against a signed policy, install it with zero egress, and use it.
- **[Catch a compromised CI dependency](./credential-harvester.mdx)** — a
  force-pushed tag turns a pinned action into a credential harvester; CI/lock's
  eBPF tracing and secret scanning catch it and a signed policy blocks the
  release.
- **[Signed compliance evidence (GRC)](./compliance-gate.mdx)** — a CIS Ubuntu
  scan becomes a signed attestation mapped to NIST 800-53 / FedRAMP; a policy
  blocks the release on high-severity failures. The compliance scanners are
  compiled in with the rookery builder.
- **[Release gates](./release-gates.mdx)** — verifying a signed attestation
  against a Witness policy: one build that passes the gate, and one that the
  gate blocks.
