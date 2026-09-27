# attestor-evidence: what the catalog lane's attestors may claim, in Lean 4

Design: `docs/design/catalog-attestor-evidence.md`.

Three attestor behaviours decide what a signed predicate claims about the world.
Each is modelled here with its invariant as a theorem, and exported as vectors
that a Go differential test replays against the shipping function. Lean 4.34.1,
no Mathlib.

```bash
lake build                          # proofs, the axiom audit, and the eval executable
lake exe attestor-evidence-eval     # one JSON line per vector: {"slice", "in", "out"}
```

`AttestorEvidence/Audit.lean` prints `#print axioms` for every headline
theorem; all depend only on `propext`, `Quot.sound` and `Classical.choice`. No
`sorry`, no `native_decide`.

## Results

| Slice | Theorem | Statement |
| --- | --- | --- |
| SBOM backref | `version_backref_needs_container` | A backref taken from `metadata.component.version` needs a component of type `container`. |
| SBOM backref | `version_backref_is_exact` | That backref is exactly the version bytes after `sha256:`, 64 lowercase hex: bound to what the SBOM carried, never normalised. |
| SBOM backref | `purl_wins` | A purl digest always takes precedence. |
| Program record | `rooted_takes_dir_volume`, `absolute_unchanged` | On Windows the measured name is the one `joinExeDirAndFName` hands CreateProcess: a rooted name takes Dir's volume, an absolute one is used as given. |
| Program record | `oldConcat_measures_a_decoy` | Counterexample: the replaced rule measured `C:\work\tools\t.exe` while `C:\tools\t.exe` ran. |
| Program record | `not_setid_needs_established_absence`, `read_error_is_unknown` | "Not set-id" only when no mode bit is set and a descriptor read of `security.capability` answered ENODATA or EOPNOTSUPP. Any other outcome is unknown. |
| Program record | `record_never_verified` | P1a never claims an execution binding. |
| Script capture | `exec_is_sh_c`, `capture_mode_never_changes_exec` | The action always runs `sh -c <text>`, whatever the capture mode. |
| Script capture | `read_only_plain_sh`, `functions_abstain` | The text is read as words only for `[sh, -c, text]` with no shell syntax, no shell function in the environment, and no leading assignment. |
| Script capture | `sensitive_value_refused`, `shape_refused`, `passes_iff` | A body carrying a sensitive value of 8 bytes or more, or a credential shape, is refused before it is embedded. |
| Vectors | `sbomVectors_hold`, `programVectors_hold`, `oldRule_wrong_on_five`, `setIdVectors_hold`, `shVectors_hold`, `guardVectors_hold` | Decide-checked rows the eval executable prints. |

## What is abstract, and what binds it

- Text is a list of Unicode scalar values. Every length the Go compares with
  `len()` is compared here as `utf8Len`, the UTF-8 byte count, so the guard's
  8-byte floor and the SBOM's 64-byte digest mean bytes (`éééé` is 8). Prefix,
  containment and ASCII-separator splitting agree with the byte view for valid
  UTF-8. Invalid UTF-8 is outside the model; the Go tests cover it.
- The purl parser (`imageDigestFromPURL`, on main) is modelled by its output.
- `GetFullPathNameW` is modelled only where the join depends on it: a
  drive-relative name on another drive resolves against that drive's current
  directory.
- The guard's credential shapes and sensitive-name globs are predicates. Their
  tables are the Go code's. The guard rows hold under both the model's
  predicates and the real tables.
- That `sh` parses syntax-free text into exactly its blank-separated words is an
  assumption about the shell, not a theorem. #10139's test runs those words
  through a real `/bin/sh` and compares.

Each code PR adds a `// formal:differential attestor-evidence <Test>` Go test
that runs `attestor-evidence-eval` and replays its slice through the Go
function: `backRefsFromExtraction` (#10192), `windowsJoinExeDir` and
`fileCapabilityOf` (#9683), `shCommandWords` and `scriptguard.Check` (#10139).
The theorems are about that Go only while those tests agree.
