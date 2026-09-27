# Formal model: the semgrep attestor's fail-closed contract (Lean 4)

A Lean 4 model of what the native `semgrep` attestor (`semgrep/v0.1`) may
sign. Design: [`docs/design/semgrep-attestor.md`](../../../../docs/design/semgrep-attestor.md)
§3.5–3.6. The attestor records facts and makes no pass/fail verdict; a rego
policy decides. What is security-relevant is that the signed evidence never
overstates a scan, so that is what the model states.

This model lands with the design, before the code (doc-first). It holds the
**required** behaviour only. The Go does not exist on main yet, so nothing
here carries a `-- cite:` line. The attestor's PR adds the as-built
citations, the vectors, and the differential test that binds this model to
`Attest` and `buildSummary`.

## Results

| theorem | status | what it says |
|---|---|---|
| `select_attest_iff` | proved | a report is signed exactly when no product is broken and exactly one is a good report |
| `select_soft_iff` | proved | the outcome is soft ("Semgrep did not run") exactly when every product is foreign, so a broken or good report is never skipped |
| `broken_refuses` | proved | any broken report (cut off, digest mismatch, required member absent, ambiguous member) refuses the step |
| `two_goods_refuse` | proved | two good reports refuse the step: signing one would drop the other's findings |
| `select_perm` | proved | product order never decides the outcome (Go iterates a map) |
| `scanComplete_iff` | proved | `scanComplete` is true exactly when `errors[]` is empty, at any level |
| `bucketTotal_eq_live` | proved | the six severity buckets partition exactly the live findings |
| `live_add_ignored` | proved | live + ignored = total: no finding is dropped from the roll-up |
| `finding_subject_live` | proved | every `semgrep:finding:` subject names a live finding |
| `file_subject_recorded` | proved | every `semgrep:file:` subject carries a digest cilock recorded for a live finding's file |

Every theorem depends only on Lean's core axioms (`propext`, `Quot.sound`,
`Classical.choice`); `SemgrepAttestor/Audit.lean` prints them on every build.

Not modeled: parsing. Which bytes classify as foreign, broken or good is
defined by one parse of the report, and the attestor's `-tags audit` fuzzer
checks on every input that the classification never reads less than the
stock `encoding/json` decoder, and that each signed summary equals the one a
stock decode of the verbatim report yields (design doc §3.5, step 3).

## Build

```bash
cd subtrees/rookery/formal/semgrep-attestor
lake build        # Lean 4.34.1 via elan; no Mathlib
```
