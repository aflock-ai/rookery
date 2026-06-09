---
slug: signed-record-we-didnt-have-in-march
title: The signed record we didn't have in March
authors: [cole]
tags: [supply-chain, cilock, ai-agents]
date: 2026-06-09
description: Two March attacks had the same shape — CI ran code it shouldn't have, with credentials it shouldn't have had, and nobody could prove what executed. That's the gap CI/lock closes.
---

I've spent a decade on this problem. I helped build Witness, we donated it to the CNCF and in-toto, and I helped write the reference architecture people point at when they talk about securing the software supply chain. The good news is the rest of the industry is converging on the premise: provenance and attestation are where software trust is heading. The harder part is getting there. So when I tell you the tooling still wasn't good enough, I'm including my own.

In March, two attacks landed within days of each other.

<!-- truncate -->

The first hit `aquasecurity/trivy-action`. An attacker force-pushed 75 of 76 version tags — rewrote the history under tags people had already pinned. If your pipeline referenced one of those tags, and most did, your next run pulled credential-harvesting code. It read secrets out of `/proc/<pid>/environ`, encrypted them, and sent them to a typosquat domain. The advice we'd all given — "pin to a tag, don't float on latest" — is exactly what got people hit.

The second was `litellm`. Two malicious releases on PyPI carried a stealer in a `.pth` file, which Python executes on interpreter startup. You didn't have to import anything. If the package was ever on the machine, the code already ran.

Two different ecosystems, one shape: CI executed code it had no reason to trust, holding credentials it had no reason to hold, and afterward nobody could produce a signed record of what actually ran. You could read the workflow file. You couldn't prove what executed.

## The same gap, now with agents

If that threat model feels abstract, look at how code gets written this week. An AI agent writes it. The agent edits the workflow. The agent opens the PR and, in plenty of shops, the agent triggers the release. The human in the loop is skimming a diff late at night, or there's no human at all — just another agent reviewing the first one.

I'm not anti-agent. We build with them every day. But "the agent did it" is not provenance, and the permissions you hand an agent are the permissions a poisoned dependency inherits. The fix isn't to slow the agent down. It's to put a gate at the end that the agent cannot open by itself.

## What CI/lock actually does

Wrap any command:

```bash
cilock run -- go build -o app ./...
```

CI/lock records what ran: the command, the inputs it read, the environment, the artifacts it produced. It signs that record — keyless, so there are no long-lived keys to leak — and you get your first signed attestation in about 60 seconds.

Then you gate on it:

```bash
cilock verify ./app --policy release.policy
```

The policy is signed by a human, with their key. It says what's allowed to ship. The agent can do everything else — run the build, gather the evidence, draft the release — but it can't sign the policy, so it can't decide what ships. That line, between "did the work" and "decided what ships," is the whole point.

It's Apache 2.0, and it speaks Witness in both directions, so it drops into what you already have instead of asking you to rip anything out. It runs where your agent already runs: Claude Code, Codex, Cursor.

## Built for how we ship now

The tooling we built to secure the supply chain assumed a human with time to read the docs and wire up signing by hand. That doesn't survive contact with an agent that's already three commits deep. CI/lock is what Witness taught me, rebuilt for that: same lineage, with the bug fixes we found auditing the upstream code. What's new is who it's for. The first-class user is your agent.

So CI/lock talks back. When something's wrong, the error tells you the next command instead of a stack trace — not logged in, it hands you the `cilock login` line. The catalog of what it can do is queryable as JSON, so an agent reads it and acts instead of guessing.

Point your agent at a goal like "get this build to SLSA Level 3" and it can take you there. CI/lock is the engine: it emits SLSA Provenance and in-toto evidence at every step, signs it, and verifies it against Rego policy you write. The evidence then flows into the [TestifySec platform](https://testifysec.com), which maps it onto the frameworks you answer to — FedRAMP, SOC 2, NIST 800-53. A compliance report stops being a project you dread and becomes a read of evidence you already have.

And the part people dread most is already done: you don't stand up Fulcio, a timestamp authority, or any Sigstore plumbing. The platform hosts it. In CI you don't even log in — signing uses your runner's ambient OIDC token, keyless, no secrets. `cilock login` only matters when you want attestations stored on the platform. No CA to operate, no keys to rotate.

## If you're already running Witness

You don't have to switch tools to get any of this. CI/lock is the in-tree continuation of Witness: anything you produced with Witness verifies under CI/lock unchanged, and CI/lock's shared-format attestations verify back under Witness. Here's what the next iteration adds.

| What it does | Witness | CI/lock (in-tree continuation) |
| --- | --- | --- |
| Attestation format | The donated in-toto/Witness project and the reference implementation. The DSSE/in-toto format the rest of the ecosystem reads. | The same format. Anything Witness produced verifies under CI/lock, with legacy type aliases registered at startup, and CI/lock's shared attestors verify back under Witness. |
| Trust setup (Fulcio, TSA, Archivista, keyless CI) | Ships all of it as first-class, including a GitHub Actions OIDC path. You point each endpoint at its host with its own flag. | Same endpoints, same flags, all still overridable. Adds one `--platform-url` that derives the hosted Archivista, Fulcio, TSA, and OIDC audience, and in GitHub Actions it signs keylessly off the runner's ambient OIDC token, with no login and no stored secret. |
| Capturing what actually ran | The `commandrun` attestor traces the wrapped process with ptrace. The portable, root-free path. | Keeps that exact ptrace path as a first-class mode, and adds an eBPF kprobe backend that traces at the kernel boundary. Default `auto`: probe eBPF, fall back to ptrace, record which backend ran. |
| Integrity over the build's files | The `product` and `material` attestors record each file as its own in-toto subject with a digest set. Fully policy-actionable. | The same per-file digests still flow through, and the file set is additionally committed to an RFC 6962 Merkle root, so one artifact gets a verifiable inclusion proof and a 29,000-file `npm install` doesn't balloon into a 10 MB envelope. Older envelopes stay verifiable. |
| Support and backing | A CNCF and in-toto project, maintained by a global open-source community. | Open source as well, with a commercial SLA from TestifySec behind it, a US company, for teams that need a vendor and a support contract on the hook for their build tooling. |

None of this is a break from Witness. Same lineage, same envelopes, same policy model, moving forward for a world where an agent is the one wrapping the build at 2am. We contribute fixes back upstream where they apply, because a stronger Witness is good for everyone. If you're running Witness today, CI/lock drops in next to it and reads what you already have.

## Try it on your next build

Most security engineers I talk to aren't missing conviction. They're missing a first step. "Secure your supply chain" is a mandate, not an instruction, and the world of SBOMs and signing and provenance is hard to walk into.

So here's the first step: wrap one command, sign one build, read the record it leaves behind. Once you have a signed account of what ran, everything downstream — policy, gating, the audit evidence — has something real to stand on. You don't need any of it to start.

You need one signed build. [Get started](/getting-started/installation).
