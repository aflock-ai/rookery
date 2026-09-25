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

## Binding to the Go

- **Citations are hashed.** Every citation of code in this tree is
  `-- cite: <path>:<start>-<end> sha256:<hash>`, with rookery-relative paths and
  the hash over the bytes `sed -n '<start>,<end>p' <path>` prints.
  `jade check formal-citations` (in the monorepo) re-hashes them and fails on
  drift. The ALPS spec page, the design docs and the contract live outside this
  tree, so they appear as unhashed `-- see (monorepo, outside this tree)` references.
- **Differential tests.** `TestVerdictMatchesLeanModel`
  (`plugins/attestors/alps-evidence`) and `TestSubjectsMatchLeanModel`
  (`plugins/attestors/slsa`) run random cases through the Go function and
  through `ciprov-eval`, and fail on the first disagreement. Each checks that it
  exercised every reachable outcome. They skip when `lake` is absent.
- `deriveAlps` and `deriveSlsa` have no Go counterpart: no shipped verifier
  derives either level. They are the reference a future verifier diffs against.

## Follow-ups

- Provision Lean on CI so the differential tests run instead of skipping.
