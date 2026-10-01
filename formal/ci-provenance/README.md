# ci-provenance: ALPS levels and SLSA build provenance, in Lean 4

A model of what provenance CI/lock produces in CI actually guarantees, level by
level, with every assumption a hypothesis of the theorem that needs it. Lean
4.34.1, no Mathlib.

```bash
lake build                      # proofs + the ciprov-eval executable + the axiom audit
jade check formal-citations     # every hashed code citation still matches the code
```

`CiProvenance/Audit.lean` prints `#print axioms` for 42 headline theorems; all
depend only on `propext`, `Quot.sound` and `Classical.choice`. No `sorry`, no
`native_decide`.

## Files

| File | What it holds |
| --- | --- |
| `Alps.lean` | The ALPS 0.1 verifier `deriveAlps`, the deployment, trust base and adversary, and `emit`: what a deployment shows a verifier. |
| `AlpsProofs.lean` | Per-level guarantees and the counterexamples that show each hypothesis is load-bearing. |
| `Slsa.lean` | SLSA Build L1-L3 over CI/lock-in-CI provenance. |
| `Subjects.lean` | Provenance subjects equal the product digests, per algorithm; value-only matching (#9816). |
| `Verdict.lean` | The alps-evidence ancestry verdict, the function the differential test runs. |
| `Actors.lean` | What each actor observes, forges and withholds, tied to `emit`. |
| `Eval.lean`, `Main.lean` | `ciprov-eval`: JSON cases in, results out, for differential testing. |

## Results

"Designed" rows are about cilockd, which is not built; their theorems are over
the interface in `docs/design/cilockd/cilockd.md` (PR #9042) and say so.

| Level | Theorem | Assumptions | Status |
| --- | --- | --- | --- |
| ALPS 1, who | `alps1_who` | honest CA, honest TSA | proved |
| ALPS 1, what | `alps1_guarantee` | + `HarnessFaithful` | proved |
| ALPS 1 without a faithful harness | `alps1_unfaithful_harness` | every signer honest | refuted: accepted ALPS 1 evidence lies about model mix, exit code and products |
| ALPS 1 today | `asBuilt_is_alps1`, `asBuilt_content_is_harness_report` | honest trust base | proved: the code reaches exactly ALPS 1, and every content field is the harness's report |
| ALPS 2 | `alps2_sound` | honest CA, TSA, observer | proved: sandbox enforced, agent holds no key, execution record true, no harness assumption |
| ALPS 2, lax boundary check | `alps2_lax_boundary` | | refuted: a boundary reference the agent signed reaches ALPS 2 on a bare workstation |
| ALPS 2, products | `alps2_products` / `alps2_products_need_sibling_closed` | + sibling mutation closed | proved / refuted without it |
| ALPS 3 (designed) | `alps3_sound` | whole trust base | proved: daemon, uid separation, measured binary, attested key, agent holds no key, execution true |
| ALPS 3, products (designed) | `alps3_products` / `alps3_products_need_sibling_closed` | + sibling mutation closed (T18) | proved / refuted without it |
| ALPS 3, macOS 14-26 and `--user` (designed) | `no_attested_key_not_alps3`, `same_uid_daemon_not_alps3` | honest trust base | proved: never ALPS 3 |
| ALPS 3 trust roots (designed) | `alps3_needs_daemon_trust`, `alps3_needs_hw_root_trust` | | refuted without them |
| Model attribution, any level | `deriveAlps_ignores_attribution`, `alps3_attribution_needs_harness` | | no level certifies it; always the harness's claim |
| SLSA L1 | `slsa_l1` | none | proved: provenance exists |
| SLSA L2 | `slsa_l2`, `cilockInJob_is_l2` | honest CA, TSA | proved: signed by the hosted workflow identity; the job's own steps can still forge |
| SLSA L3 | `slsa_l3`, `isolatedBuilder_is_l3` | honest CA, platform, and a signer the steps cannot become | proved for an isolated builder |
| SLSA L3 for CI/lock in the job | `naive_l3_accepts_step_forgery` | every signer honest | refuted: a build step mints its own leaf for the same workflow identity and signs provenance for an artifact never built (#9822) |
| Subject binding | `provenance_subject_is_product_digest`, `seed_match_binds_product` | product attestor is the only producer; no other `file:` subject | proved, algorithm by algorithm |
| Subject binding, broken assumptions | `file_key_collision_overwrites`, `second_producer_overwrites`, `value_match_crosses_algorithms` | | refuted |

## SLSA L3 through the isolated provenance workflow (`SlsaL3Workflow.lean`)

`l3Accept` is the reference for `cilock verify --slsa-level 3`, whose decision
function is `Accept` in `attestation/slsa/l3`. The adversary controls every step and input of
the caller workflow, any trigger event, and tags in the builder repository.

| Claim | Theorem | Assumptions | Status |
| --- | --- | --- | --- |
| Accepted ⇒ signer is the pinned workflow commit on a hosted runner, writer-triggered, for the expected repository; builder.id, repo, commit and run are its certificate's; every subject is in a build collection of the same run, repo and commit | `l3_sound`, `l3_signer_not_controlled` | trusted roots' CAs issue only for real jobs; GitHub event semantics | proved |
| Platform Fulcio (default) / public Sigstore (option) | `l3_sound_platform`, `l3_sound_public` | that root's CA honest | proved |
| Tag-pinned reusable workflow | `tag_pinned_swapped` | | refuted: the moved tag's code signs, accepted |
| Caller inputs flow into builder/source fields | `caller_inputs_into_fields` | | refuted unless the verifier cross-checks every field against the certificate |
| Outputs of another run mixed in | `other_run_outputs_mixed_in` | | refuted unless subjects are linked by run, repo and commit |
| `pull_request_target` / fork run | `pull_request_target_accepted` | | refuted unless the trigger is writer-only |
| Inline L2 provenance accepted as L3 | `inline_l2_accepted_as_l3` | | refuted |
| builder.id compared without the extension | `builder_id_without_extension` | | refuted |
| Self-hosted runner chosen by the caller | `self_hosted_runner_accepted` | | refuted unless `RunnerEnvironment` is checked |
| Trusting both roots | `both_roots_need_both` | | refuted unless both CAs are honest |
| No expected source repository | `other_repo_reaches_l3` | | refuted: any repository calling the pinned workflow reaches L3 unless `pol.repo` is checked |

The soundness theorem does not assume the provenance workflow's code is
faithful: the verifier's cross-checks force every field it proves. The
workflow's code matters for the claim that only it signed, so it must never run
caller-supplied code. `TestL3AcceptMatchesLeanModel` (`attestation/slsa/l3`)
diffs the shipped `Accept` against `l3Accept`. Half its cases are the honest scene
with one field mutated, so deleting any one of `Accept`'s 19 checks, or widening
the trigger allowlist, makes the two disagree (checked by sabotaging each in turn).

What the model does not cover, and the Go does outside `Accept`: parsing the
certificate (issuer must be GitHub Actions, no empty extension, the run in Run
Invocation URI must be the source repository's), parsing the statement (exactly
one source commit, sha256 subjects), requiring every caller-supplied subject
to be among the accepted statement's subjects, the SLSA verifying-artifacts
expectations (buildType is provenance.yml's; externalParameters holds only
`workflow.{repository,path,ref}`, equal to the signer's Build Config URI), and
the level itself, which comes from the trusted-builder catalog
(`attestation/slsa/trusted-builders.json`) keyed by builder.id. Only
attestation collections count as build evidence, so a provenance statement
cannot link its own subjects.
The model allows that self-link (the provenance job is a job of the same run), so
`l3_sound`'s linking clause proves same-run, not "built by a different job".

## builder.id against the signer's Build Signer URI (`BuilderIdentity.lean`)

`checkSLSAProvenance` (attestation/policy/slsa_builder.go, #9827) is the
verify-time half of `builder_id_without_extension`. It refuses the pre-#9827
`v1.0` type by name (Cole, 2026-09-29: no deprecation window). For SLSA
provenance v1, a builder.id that names a CI workflow identity must equal a
satisfying signer's Fulcio Build Signer URI. `BuilderIdentity.refusal` is that
decision, with the refusal named (legacy-type, malformed, ambiguous-key,
unbacked). `BuilderIdentity.decode` reads the body by exact key, as Rego reads
`input.runDetails.builder.id`, and refuses an object on that path that also
spells the key in another case: encoding/json's struct decode matches keys
case-insensitively and keeps the last, so without the refusal the check and
the policy would judge different builder ids. The results are:

- `non_provenance_passes`: every other predicate type passes.
- `claim_is_backed`: an admitted workflow claim names a satisfying signer's URI.
- `malformed_refused`: an undecodable builder is refused.
- `ambiguous_refused`: a builder.id path key spelled in two cases is refused.
- `legacy_refused`, `legacy_never_admitted`: provenance known by the pre-#9827
  `v1.0` type is refused, by name, whatever its body and signers.
- `no_signer_no_claim`: with no satisfying signer, no workflow claim is admitted.

`TestFormalDifferentialSLSABuilderIdentity` (attestation/policy) runs 3,000
generated cases through the Go and through `ciprov-eval` (`fn:
builderIdentity`) and compares both the verdict and the named reason. There are
0 mismatches, and every reason occurs. Making the Go claim match
case-sensitive turns it red.
Boundary: lower-casing is ASCII here, while Go's `strings.ToLower` also folds
a few non-ASCII runes (the Kelvin sign to `k`). Such a builder.id is outside
the generator. In that case Go checks more than the model, never less.
A key repeated in its exact spelling is refused by the Go, but `Json.parse`
keeps only one of the two, so exact repeats are outside the generator too and
are pinned by `TestCheckSLSABuilderIdentityRefusesCollidingKeys` instead.

## builder.id against the signer's Build Signer URI (`BuilderIdentity.lean`)

`checkSLSAProvenance` (attestation/policy/slsa_builder.go, #9827) is the
verify-time half of `builder_id_without_extension`. It refuses the pre-#9827
`v1.0` type by name (Cole, 2026-09-29: no deprecation window). For SLSA
provenance v1, a builder.id that names a CI workflow identity must equal a
satisfying signer's Fulcio Build Signer URI. `BuilderIdentity.refusal` is that
decision, with the refusal named (legacy-type, malformed, ambiguous-key,
unbacked). `BuilderIdentity.decode` reads the body by exact key, as Rego reads
`input.runDetails.builder.id`, and refuses an object on that path that also
spells the key in another case: encoding/json's struct decode matches keys
case-insensitively and keeps the last, so without the refusal the check and
the policy would judge different builder ids. The results are:

- `non_provenance_passes`: every other predicate type passes.
- `claim_is_backed`: an admitted workflow claim names a satisfying signer's URI.
- `malformed_refused`: an undecodable builder is refused.
- `ambiguous_refused`: a builder.id path key spelled in two cases is refused.
- `legacy_refused`, `legacy_never_admitted`: provenance known by the pre-#9827
  `v1.0` type is refused, by name, whatever its body and signers.
- `no_signer_no_claim`: with no satisfying signer, no workflow claim is admitted.

`TestFormalDifferentialSLSABuilderIdentity` (attestation/policy) runs 3,000
generated cases through the Go and through `ciprov-eval` (`fn:
builderIdentity`) and compares both the verdict and the named reason. There are
0 mismatches, and every reason occurs. Making the Go claim match
case-sensitive turns it red.
Boundary: lower-casing is ASCII here, while Go's `strings.ToLower` also folds
a few non-ASCII runes (the Kelvin sign to `k`). Such a builder.id is outside
the generator. In that case Go checks more than the model, never less.
A key repeated in its exact spelling is refused by the Go, but `Json.parse`
keeps only one of the two, so exact repeats are outside the generator too and
are pinned by `TestCheckSLSABuilderIdentityRefusesCollidingKeys` instead.

## Binding to the Go

- **Citations are hashed.** Every citation of code in this tree is
  `-- cite: <path>:<start>-<end> sha256:<hash>`, with rookery-relative paths and
  the hash over the bytes `sed -n '<start>,<end>p' <path>` prints.
  `jade check formal-citations` (in the monorepo) re-hashes them and fails on
  drift. The hash anchors the citation and the span is a hint: code that only
  moved still matches (exactly one span of that length may match), and
  `--fix` rewrites the hint. The ALPS spec page, the design docs and the contract live outside this
  tree, so they appear as unhashed `-- see (monorepo, outside this tree)` references.
- **Differential tests.** `TestVerdictMatchesLeanModel`
  (`plugins/attestors/alps-evidence`), `TestSubjectsMatchLeanModel`
  (`plugins/attestors/slsa`) and `TestL3AcceptMatchesLeanModel`
  (`attestation/slsa/l3`) run random cases through the Go function and
  through `ciprov-eval`, and fail on the first disagreement. Each checks that it
  exercised every reachable outcome. They skip when `lake` is absent.
- `deriveAlps` and `deriveSlsa` have no Go counterpart: no shipped verifier
  derives either level. They are the reference a future verifier diffs against.

## Follow-ups

- Provision Lean on CI so the differential tests run instead of skipping.
