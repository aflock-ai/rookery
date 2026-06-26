<!--
Copyright 2026 The Rookery Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
-->

# `platformauth` — a shared, single-session login library for cilock + jctl

**Status:** Proposed (design for review)
**Scope:** `cilock` (rookery) and `jctl` (judge-api) authentication to the Judge platform
**Audience:** cilock + jctl maintainers
**Supersedes / unifies:** the dual credential model that produced GHSA #5988 (#6014) and the `~/.jctl` config-parsing coupling

---

## 1. Problem

cilock and jctl both authenticate to the **same** Judge platform, but each carries its **own**, divergent credential model:

| | cilock | jctl |
|---|---|---|
| Store | `~/.config/cilock/credentials.json` | `~/.jctl/config.yaml` |
| Token at rest | **cleartext** in a 0600 file | **scrubbed into the OS keyring** (metadata only on disk) |
| Trust pin (`TrustBundleSPKI`) | yes (policy-signer TOFU pin) | **never** — jctl has no `verify`, so no concept of it |
| Login flow | browser-loopback OIDC | device-code OIDC |

Three concrete problems fall out of this split:

1. **Security asymmetry (GHSA #5988 / #6014).** cilock can reuse a jctl session (it reads `~/.jctl` directly). But a jctl-sourced credential cannot carry cilock's trust-on-first-use pin, so `cilock verify` against a discovery-served policy-signer trust bundle was silently re-adoptable — a compromised platform could swap the trust anchor. The interim fix (#6047) makes this **fail closed**; this design removes the asymmetry at its source.
2. **A hidden coupling.** cilock **hand-parses jctl's config schema** (`internal/auth/store.go`, the `jctlContext` struct, kept in sync only by a comment). A jctl YAML/keyring change silently breaks cilock's read-through. The tools are *not* independent today.
3. **Duplicated, divergent login code.** Two OIDC implementations, two stores, two session models, two `whoami`/`logout` behaviors — drift is inevitable.

### What is *not* shared

cilock and jctl do **not** overlap on verification. `cilock verify` is local, offline-capable, cryptographic supply-chain policy verification (DSSE / in-toto / SLSA / witness policy). jctl has **no `verify` command** — it is the platform-control CLI (auth, `get products|tenants|ssp`, `trigger ssp`, mcp). The platform evaluates compliance server-side; jctl is its remote control. **The only thing the two tools share is the platform session.** That is the entire surface this library unifies.

---

## 2. Principles (the constraints this design satisfies)

In priority order:

1. **Secure** — no credential may be un-validatable or un-pinnable-yet-trusted; trust decisions must not depend on which tool obtained the session; fail closed. At-rest posture must not regress.
2. **Independent of each other** — cilock must not depend on jctl, nor jctl on cilock. Neither reaches into the other's private files. Either installs and runs standalone.
3. **Same platform, one session** — both authenticate the same Judge platform; the user logs in **once** and both tools use that session.
4. **DRY login** — one login implementation, one session model, one store.
5. **Keep both tools stable** — cilock's signing/verify core and jctl's CLI surface stay intact throughout; migration is staged and reversible.

---

## 3. Architecture

### 3.1 One library, in rookery

A new package **`github.com/aflock-ai/rookery/platformauth`** owns the entire platform-auth surface: login flows, the session/credential model + capabilities, the on-disk store, the platform endpoints, and token validation (audience / expiry / https-or-loopback / trust-pin).

**Both tools depend on the library, never on each other:**

```
        platformauth  (rookery — public, independent)
          ^        ^
          |        |
       cilock     jctl
     (rookery)  (judge-api)
```

This direction is already established and safe:
- `judge-api/go.mod` already requires `github.com/aflock-ai/rookery/*` (jctl → rookery is a normal import).
- rookery imports **nothing** from judge-api (verified: the only `testifysec/judge` strings in rookery are example slugs in help text, not imports).

So rookery stays the independent, public, lower module; jctl reaches *down* into it. **cilock and jctl never import each other** — that is the "independent of each other" property.

### 3.2 One session, one keyring-backed store

`platformauth` owns a **single** session store, replacing both `~/.config/cilock/credentials.json` and `~/.jctl/config.yaml`:

- **Location:** a common, discoverable path (proposed: `~/.config/judge/`), keyed by normalized platform URL, with a `current_platform` pointer (the active-platform concept both tools already have).
- **At-rest posture: adopt jctl's keyring scrub.** The bearer token lives in the **OS keyring**; only non-secret metadata (platform URL, tenant/product binding, expiry, capabilities, the trust pin) lives in the file. **This is a security *improvement* for cilock**, which moves off cleartext-at-rest. (It is also why the rejected "materialize jctl into cilock's cleartext store" approach was backwards — we are going the opposite direction.)
- **Log in once, both tools use it.** `login` (from either tool, both calling the shared code) writes the shared store; every cilock/jctl invocation reads it. Neither tool parses the other's private files; they share a *store through the library*, not each other's internals.

### 3.3 The session model is capability-declaring (fail-closed)

A resolved session carries an explicit, declared capability set; trust decisions branch on a **declared capability**, never on the source string:

- Capabilities: `CanPinTrust`, `CarriesIdentity`, `EnforcesExpiry`, `AudienceValidated`.
- `Require(cap)` is **fail-closed by construction** — an undeclared/unknown capability reads as `false` → the consumer refuses. A provider can only fail *open* by actively lying in one auditable `Capabilities()` method, versus today's bug class where absence is silent and scattered across field reads.
- A **session is an auth bearer, not a verification trust-anchor.** `cilock verify`'s policy-signer trust decision gates on `CanPinTrust`; an un-pinnable session fails closed (or demands explicit `--policy-ca-roots` / `--trust-discovery`). With one shared session source, the *source asymmetry* dissolves — but the capability gate stays as the durable, legible safety property.

This capability seam already exists in cilock as of **Phase 1** (PR #6048) and is behavior-neutral there; this design promotes it into `platformauth`.

---

## 4. Security properties

- **Closes GHSA #5988 / #6014 structurally** — a single session source with uniform, declared capabilities; verify-trust is gated, not source-coupled. #6047 is the fail-closed interim that this generalizes.
- **No at-rest regression — an improvement** — token in keyring, metadata in file; cilock stops storing cleartext bearers.
- **No new fail-open surface** — `Require` defaults to refuse on any undeclared capability; the only way to fail open is a one-line auditable misdeclaration, reviewable in one place per provider.
- **Audience + expiry validation centralized** — the `--token` audience gate (GHSA #5991, login-audience confused-deputy guard) and the JWT `exp` pre-flight live once, applied uniformly. (Note: the existing audience check fails *open* on an undecodable `aud`; centralizing it makes that one behavior auditable and tunable in a single spot rather than per-tool.)
- **No source-string trust branching** — verified in Phase 1; preserved here.

---

## 5. Phased plan (keeps both tools stable)

| Phase | What | Tool(s) | Risk | Status |
|---|---|---|---|---|
| **0** | `SetTrustBundleSPKI → (persisted, err)` + verify refuses un-pinnable silent adoption (the fail-closed interim) | cilock | low | **#6047** (in review queue) |
| **1** | Provider-interface credential seam — **behavior-neutral** (capability declaration + one `Resolve`; `Lookup*` become shims; zero existing tests changed) | cilock | none | **#6048** (draft, stacked on #6047) |
| **2** | Route `verify.go` TOFU + `whoami`/`doctor` through `Require(CapCanPinTrust)` — generalizes #6047's guard into the declared capability; surface provenance + fix logout-lies | cilock | = #6047 | next |
| **3** | **Extract `platformauth` into rookery** — promote the session model + the keyring-backed shared store + the login flow into the shared package; cilock adopts it (its bespoke store becomes a thin adapter, then is removed) | cilock | refactor, flag-gated | — |
| **4** | **Migrate jctl onto `platformauth`** + the shared store — *the risky one, see §6* | jctl | **high** | — |
| **5** | Delete cilock's `~/.jctl` parsing; the provider model collapses to one platform-session source | cilock | cleanup | — |

The "one login, both tools" payoff only fully lands at the **end of Phase 4** (both tools writing the shared store), so Phases 3 and 4 ship close together, with a transition that reads the legacy stores during migration.

---

## 6. The jctl migration (Phase 4) — the one genuinely risky step

jctl is the widely-used platform CLI; `~/.jctl/config.yaml` + keyring is baked into people's scripts and CI. The migration **must**:

1. **Keep jctl's CLI surface identical** — `jctl auth login | whoami | logout | revoke | workflow | tiers` behave exactly as before. Only the storage backend changes.
2. **Read the legacy store during a transition window** — on first use after upgrade, if `~/.jctl/config.yaml` (+ keyring) holds a valid session and the shared store does not, **migrate it in place**. **Never force a re-login.**
3. **Preserve the keyring scrub** — the shared store keeps jctl's posture (secret in keyring, metadata in file). No regression to cleartext.
4. **Be reversible** — flag-gated (`JUDGE_SHARED_SESSION` or similar); old path remains as fallback until the window closes.
5. **Telemetry-gated cutover** — see §7.

Because this touches a tool other teams depend on, **Phase 4 lands only after this doc has maintainer sign-off.**

---

## 7. Open decisions

1. **When does jctl-only `cilock verify` flip from warn → refuse?** (The Phase-2/#6047 behavior change.) Existing pipelines that verify against discovery-served trust on a jctl session will need `--trust-discovery` / `--policy-ca-roots` or `cilock login`. **Decide with data, not a guess:** the credential-resolution telemetry emit point (`telemetry.go`) gains a `source` field; measure jctl-verify prevalence over one release window; flip to hard-refuse if rare, ship a warn-with-grace if common. #6047 holds the fail-closed default in the meantime.
2. **Shared store path + format.** Proposed `~/.config/judge/` with keyring-backed tokens. Confirm the path and whether jctl's existing context model (multiple named contexts) maps onto the per-platform-URL keying or needs a context layer in the shared store.
3. **Login verbs.** This design **keeps `cilock login` and `jctl auth login` as separate verbs** (different default flows — browser-loopback vs device-code — and separately-shipped binaries). They call the same library; we do **not** merge the verbs.

---

## 8. Explicitly NOT doing

- **Not** merging the two login commands into one binary/verb.
- **Not** materializing a session token into a cleartext flat file (the inverse of the secure direction).
- **Not** making cilock depend on jctl, or jctl on cilock — both depend only on `platformauth`.
- **Not** flipping all four capabilities to hard-refuse at once; expiry/audience are surfaced first, refused only after telemetry.
- **Not** changing what `cilock verify` or jctl's commands *do* — only where the session comes from.

---

## 9. Latent follow-ups (out of scope, tracked)

- The hand-duplicated `jctlContext` schema (the coupling) is **deleted** by this design once jctl writes the shared store (Phase 5) — no separate `jctlinterop` package needed.
- Confirm `jctl auth logout` scrubs both the file and the keyring entry under the shared store.
