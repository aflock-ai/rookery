# Formal model: cilock policy verification (Lean 4)

A Lean 4 model of what `cilock verify` decides: `Policy.VerifyWithExternals`
(`attestation/policy/policy.go`) and the verified source that feeds it. It
covers DSSE signature checks against the policy's keys, roots and timestamp
authorities, functionaries and certificate constraints, the hardening flags,
the timestamp constraint, the signed-subject anchor, the step gate (Rego and AI
are one opaque predicate), attestationsFrom, artifactsFrom pruning, externals,
commit binding, the subject fan-out guard, the lazy witness and `about`.

The model has two verdicts over the same pieces:

- **`verifyAsBuilt`** is the code at the commit the citations pin. Its
  attestationsFrom Rego context is read before artifactsFrom pruning.
- **`verifyFixed`** is the same pipeline iterated to a joint fixed point:
  every step is re-gated with a context read from the surviving collections,
  until the survivors repeat. It is the proposed semantics for
  testifysec/judge#9813. The soundness theorems are proved for it, and the
  as-built verdict is refuted where it differs.

The exported theorem is `policy_sound` (`CilockPolicy/TrustProofs.lean`). It
says: under the `Assumptions` bundle, a passing verify means the policy was
admissible and there is a joint fixed point on which every step has a survivor.
Every survivor is named for its step, anchored on a seed by a signed subject,
signed by a credential a functionary admits (for a certificate: its root vouched
for it, and its TSA-proven time is inside the validity window and not after the
clock), gated with Rego that read only survivors, and chained to a surviving
upstream collection on every artifactsFrom edge. A master theorem (`cilock_sound`,
formal/cilock) is meant to consume it.

The spec is the asset, not the proofs. If the engine changes, the model can be
rebuilt from `CilockPolicy/Verify.lean` and its citations in a day. The proofs
then say which properties still hold.

## Build and gates

```bash
cd formal/cilock-policy
lake build                            # Lean 4.34.1 via elan; no Mathlib
jade check formal-citations           # recompute every cite: hash
go test ./attestation/policy -run 'TestFormal(Differential|Holdout)'   # from the rookery root
```

A clean build (`rm -rf .lake/build && lake build`) takes **13.3 s wall** (measured 2026-09-24) on an
M-series Mac. `CilockPolicy/Audit.lean` prints `#print axioms` for 62
results. Every one lists only `propext`, `Quot.sound` and `Classical.choice`.

Every Go citation is a `-- cite: <path>:<start>-<end> sha256:<hex>` line at the
end of its comment block. The path is
relative to the rookery root, and the hex is the SHA-256 of those lines.
`jade check formal-citations` fails when the cited Go changes. Re-read the code,
update the model, then run `--fix`.

## Differential test

`lake exe cilock-policy-eval` is the model as a program. It reads JSON cases
and prints verdicts. `attestation/policy/formal_diff_test.go` runs the real
engine (batch and streamed arms) and the Lean binary on the same cases and
fails on any disagreement. It uses random cases (`-formal-diff-n`,
`-formal-diff-seed`) plus the counterexample traces, including allowedUntracked
under enforce, under warn, excused by a glob, and not excused by `/*`, and the
hardened-git SHA-1 subject arm (bare, case-folded digest, git namespace; null
OID, foreign or case-variant namespace, no segment boundary, not hardened). The
engine runs under `EnforcedHardening()`, read from the engine, never a
hand-copied flag list: such a list missed EnforceAllowedUntracked, and the test
then agreed with a model that ignored the flag. The engine runs for
real from the verified source's output down. The source (DSSE and the subject
guard) is a fake that applies the same two rules. It uses raw-key signers
only, and a fixed three-module Rego catalog mirrored in `Main.lean`. The
engine ships the #9813 fix (#9860), so the reference is `--fix9813`
(`verifyShipped`: the attestationsFrom ∪ artifactsFrom acyclicity validator,
then the round-bounded fix). As a sensitivity check, the test requires the
pre-#9860 as-built model (no flag) to disagree with the engine on the #9813
trace.

`TestFormalDifferentialGlobs` runs `cilock-policy-eval --glob` against the two
matchers the verdict reads: the cert-constraint matcher (`certGlob`, RE2 since
#9867) and the allowedUntracked matcher (`untrackedAllowed`, the same RE2
translation with `/` as separator). It enumerates every pattern of up to three
tokens over `a b * ** ? /` against every value of up to four characters over
`a b /`, about 44,700 questions. For the allowedUntracked matcher it adds the
whole grammar the RE2 translation reads (`sepGlob`, Verify.lean: classes and
negated classes, ranges, escapes, nested braces, and `}` and `,` outside
braces): every pattern of up to three characters over
`a * ? / { } , [ ] ! - \` that the engine compiles, against every clean value
of up to three characters over `a b / , } -`, plus pinned realistic patterns
(`vendor/**/*.go`, `/tmp/build/cilock{,.exe}`, `**/[!.]*.go`). That is 296,353
questions, and none disagree. `v6_re2_grammar` checks the headline answers by
`decide`.

Run against the gobwas matcher allowedUntracked used before, the same
enumeration disagrees on 2,496 cases. 2,312 are gobwas admitting a path the
model refuses: the `**` overlap (`a**a` matched `a`, `/**/` matched `/`,
`vendor/**/x.go` matched `vendor/x.go`) and gobwas's reading of an unclosed
`{` (`a{a` matched `aa`), which the RE2 translation refuses to compile. 184 are
gobwas refusing a path the pattern describes: a run of three `*` (`a***`
refused `a`) and an empty alternative (`*{}` refused `a`). Which patterns are
valid is not modelled; the differential only asks about patterns the engine
compiles.

## Files

| file | what |
|---|---|
| `Types.lean` | shared vocabulary: digest, subject, certificate, credential, signature, TSA token, collection, envelope |
| `Policy.lean` | policy, step, functionary, certificate constraint, hardening, options |
| `Trust.lean` | DSSE, functionary validation, certificate constraint, timestamp constraint, triage |
| `Verify.lean` | subject anchor, gate, step phase, artifact pruning, externals, both verdicts |
| `Assumptions.lean` | the named cryptographic and third-party hypotheses, over the evidence being verified |
| `NonVacuity.lean` | a certificate policy with a TSA where a verify passes and the Assumptions hold |
| `Lemmas.lean`, `Soundness.lean` | pruning facts; Theorem 1 for the fixed semantics |
| `TrustProofs.lean` | `policy_sound`, Theorems 2 and 4, V7 |
| `Vacuity.lean` | V1, V2 at the functionary level |
| `Linking.lean`, `LinkingOptions.lean`, `Order.lean` | Theorems 3, 5, 6, 7; L1-L6; V2-V5 |
| `Launder.lean`, `TrustCounterexamples.lean`, `LinkingCounterexamples.lean` | kernel-decided traces |
| `Holdout.lean` | three real policies, encoded after the model |
| `Bound9813.lean`, `BoundProof.lean` | the #9813 fix's round loop (1c49f05539): its bound for step lists in topological order, a counterexample outside the ordered validator, and the gap to the shipped one |
| `Audit.lean` | `#print axioms` |
| `Main.lean` | the differential-test entry point |

## Results

"proved" means for the fixed semantics unless noted. Traces are `decide`d by
the kernel.

| # | statement | result |
|---|---|---|
| 1 | pass ⇒ every step has a survivor that is authorized, anchored, gated, chained, and (under enforce) consumes no untracked material | **proved** (`policy_sound`). Not vacuous: the Assumptions range over the evidence, and `assumptions_inhabited` exhibits them holding for a certificate policy with a TSA that passes (an unscoped TsaNotFuture is refuted by `unscoped_tsaNotFuture_refuted`). **Refuted for as-built**: `Launder.flooded_passes` (#9813). Also: a raw key needs no timestamp, and evidence timestamps are compared with expiry only through `TsaNotFuture` (`timestamp_after_expiry_passes`) |
| 2 | no cross-step reuse | proved (`no_cross_step`) |
| 3 | subject binding | proved: a matchable SIGNED subject's algorithm:value key is a normalized seed (`anchor_sound`). The algorithm label is compared (`l2_algorithm_label_compared`; the #9816 gap, fixed by #9863) |
| 4 | expired never passes; unmatched signer never contributes | proved (`expired_fails_*`, `untrusted_never_triaged`, `unknown_key_no_verifier`) |
| 5 | attestationsFrom well-founded | proved (`attestationsFrom_wellFounded`): cyclic or self-referencing policies fail before any search |
| 6 | order independence | proved (`order_independent`), assuming Rego is blind to input.steps order (the engine sorts by Reference; References assumed unique) |
| 7 | flood resistance | proved for evidence no step authorizes, in both directions, for both verdicts (`flood_resistant*`). **Refuted** for authorized-but-pruned evidence as-built (#9813), and PASS→FAIL with the fan-out guard on (`fanout_flood_flips`, documented, opt-in) |
| L1 | anchor soundness | proved (`anchor_sound`): no BackRef hop exists |
| L2 | exact digest match | proved for subjects since #9863 (`l2_algorithm_label_compared`; refuted before, #9816); proved-by-trace no downgrade on artifact hops (`l2_no_downgrade`) |
| L3 | no transitive laundering | proved (`no_laundering`); refuted as-built (#9813) |
| L4 | BackRef non-forgeability | proved per collection (`l4_backrefs_irrelevant`); BackRefs are never followed (`l4_backref_not_followed`) |
| L5 | termination and bounds | pruning always reaches its fixed point within fuel (`prune_fixed`). An artifactsFrom cycle passes the joint fixed point, and since #9860 the engine refuses it at validation (`l5_artifact_cycle_passes`). A non-settling joint iteration fails closed (`l5_oscillation_fails_closed`) |
| L6 | flood independence on the link graph | as Theorem 7 |
| V1 | no arbitrary signer | literal form **refuted**: an all-`"*"` functionary passes the static validator and admits anyone from the root (`v1_all_star_admits_anyone`). Proved: under enforce there is no IMPLICIT wildcard (`listOk_nonvacuous`, `fValidate_enforce`). With a flag off: `r3_181_off_admits`, `r3_184_off_admits` |
| V2 | hardening monotone | proved per functionary (`fValidate_mono`) and at verdict level for the monotone class (`hardening_monotone`). Benign counterexample with a timestamp constraint (`v2_timestamp_counterexample`) |
| V3 | commit binding | proved for witnesses and externals (`commit_bound`, `external_commit_bound`) |
| V4 | about only widens reach | proved: it changes no per-collection decision; outside v0.2 it is refused (`about_irrelevant`, `about_needs_v02`) |
| V5 | lazy = eager | proved (`lazy_eq_eager`) |
| V6 | allowedUntracked enforced | **holds since #9862** under EnforceAllowedUntracked (EnforcedHardening, the cilock CLI and Judge default): an untracked material refuses; warn passes it; a glob excuses it; `*` stays in one segment (`v6_untracked_material`). `a**a` does not excuse `a` (`v6_overlap_not_allowed`), which the engine matches since it left gobwas. requireAll holds (`requireAll_consumes`) |
| V7 | timestamps | proved (`timestamp_sound`, `verifier_times_tsa`, `triage_skew_irrelevant`). Only TSA-verified times of functionary-matched signatures count. The earliest is judged, the bounds are exact, and the skew option is never read |
| #9813 bound | the fix converges within len(steps)+1 rounds | **proved** for policies whose step list is a topological order of attestationsFrom ∪ artifactsFrom (`validateAcyclic`): `fix9813_converges`. **Not proved** for every policy the shipped validator accepts: `unionAcyclic` takes an acyclic graph in any order, and `bound_scope_gap` is such a policy outside the theorem; its result is the unique joint fixed point, so it decides exactly as `verifyFixed` (`jointFixed_unique`, `verifyFix9813_eq_verifyFixed`). **Refuted** under the old validator: a combined cycle that settles on PASS after m+1 rounds is refused at 3 (`Bound9813.m3_refused`, `m3_converges_later`, `bound_counterexample_validators`); reproduced on the engine |

VSA emission, VSA-as-evidence and Rego/AI internals belong to the sibling
evaluator model (formal/cilock-evaluators).

## Holdout

Three real policies were set aside before modelling:
`scripts/dr/verification.policy.json` and `deploy/dist/self-host-minimal.policy.json`
(testifysec/judge), and this repository's `deploy/cilock/release.policy.json`.
Their functionaries were encoded afterwards, together with a GitHub Actions
keyless certificate shape. All 7 predictions match the engine
(`attestation/policy/formal_holdout_test.go`). One prediction was
**`deploy/cilock/release.policy.json` is refused by default `cilock verify`**:
as held out it left dnsnames/emails/organizations empty, and
RejectEmptyConstraintEmptyField is on by default. #9866 then set those lists to
`"*"`; `release_prediction` keeps the held-out policy and
`release_prediction_after_9866` shows the shipped one is admitted.

## Not modelled

- Certificate chain building, KMS keys, and RFC 3161 parsing are abstracted
  to observations (`Cert.chainsTo`, `Sig.ok`, `TsToken.ok`) that the
  Assumptions interpret.
- Step map key ≠ Step.Name (refused under EnforceStepNameCoherence). The model
  takes them equal. RejectDuplicateRegoPackage is a Rego concern.
- Globs: `*` and `?` only; `{…}` and `[…]` are literal.
- Legacy URI aliases, detached manifests, inventories and the inclusion-proof
  seed bridge (`cilock/cli/inclusion_bridge.go`).
- The artifact pass updates in place in name order; the model updates all
  steps from the state at the start of the pass. Both converge to the same
  greatest fixed point. That equivalence is argued, not mechanized.
- The external-assignment bound of 64, AI and Rego-timeout refusals (#9872),
  and the empty-result diagnostic probe (it only adds rejections).
- Step.RequiredArtifacts (#9946) and ExternalAttestation.CommitSubject
  (#10067): every step and external here leaves them empty.
- allowedUntracked path cleaning: material paths are taken as already clean,
  so the engine's refusal of a path that only cleans to a covered one is not
  modelled. `{…}`, `[…]` and `\` in its globs are literal here.
- The per-round gate memo (#9860): it replays verdicts and changes none.
- The SLSA provenance check (#9827, `checkSLSAProvenance`): a further
  refusal on a collection or external known by the pre-#9827
  `provenance/v1.0` type (by name), or on SLSA v1 provenance whose builder.id
  claims a workflow identity no satisfying signer's Build Signer URI carries. It can only reject. It is modelled on its own, and bound by a
  differential, in `formal/ci-provenance` (`BuilderIdentity.lean`); it is not
  composed into `verifyFixed` here.
- `data.rookery.predicateType` (#9827): Rego is an opaque predicate here, so
  the signed type the verifier hands it is part of that opaque input.
