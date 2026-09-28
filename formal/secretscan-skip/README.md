# secretscan own-output skip: a Lean 4 model

A machine-checked model of the one place a secretscan attestation declines to
read a working-tree file: cilock's own output
(`plugins/attestors/secretscan/own_output.go`, `skipAsOwnOutput`, landing with
#10174 and #10175). Two kinds of file qualify, each by what it is and never by
its name: the file this process writes its stdout or stderr to (same device
and inode), and a signed DSSE envelope over an attestation collection. Either
is skipped only when git positively says the file is untracked, the path is
not at or under a submodule gitlink, and git asked from the file's own
directory names the same repository (a nested repository means a scan). The
envelope reason, a shape guess, further applies only on a diff scope's
working-tree walk: never to a product the wrapped command recorded, never under
a tree scope; the stream reason, an identity
proof, applies to recorded products too, since that is how cilock's redirected
output reaches the scanner.

The security claim is that a skip never hides anything a push carries. A push
carries commits and the index is what the next commit carries; both are read
from the object store by `scanCommittedBlobs`, which never consults this
filter. So the invariant the Go code must hold, and this model proves, is that
**a skipped file is in neither the index nor HEAD as itself**, not merely under
the name it was reached by.

Lean `v4.34.1` (pinned in `lean-toolchain`). Core only, no Mathlib.

## Build and run

```bash
lake build                                         # model, proofs, audit, oracle (~5 s clean)
go test ./plugins/attestors/secretscan -run TestFormalDifferentialSecretscanSkip -v   # from the rookery root
```

The differential test builds every case as a real file system and git state in
a temp directory, writes the ground-truth facts down from the construction,
and compares the real `skipAsOwnOutput` with the oracle
(`secretscan-skip-oracle`, JSON Lines on stdin, `skip` or `scan` per line).

## Layout

| File | What it models |
| --- | --- |
| `Model.lean` | `Facts` (ground truth about one path), `WellFormed` (with no symlink along the path and no submodule above it, the spelled name is the file's name in the same repository), the Go decision `skip` over its observables, and the earlier rules `skipRound0` / `skipRound1` / `skipRound2`. |
| `Theorems.lean` | The results below. |
| `Oracle.lean`, `OracleMain.lean` | The model as an executable for the differential test. |
| `Audit.lean` | `#print axioms` for every result. |

## Results

| Theorem | Statement |
| --- | --- |
| `skip_implies_untracked` | Under `WellFormed`, a skipped file is untracked as itself: `tracked = false`. |
| `tracked_never_skipped` | A staged or committed file is always scanned. |
| `skip_proven` | A skip needs a path inside the working directory, a git work tree with a born HEAD, a path that resolves, no symlink anywhere along it, no submodule gitlink at or above it, and git's "untracked" for the spelling. |
| `gitlink_never_skipped` | A path at or under a submodule gitlink is always scanned: the parent's index lists only the gitlink. |
| `nested_repo_never_skipped` | A file owned by a nested repository that is not a submodule is always scanned. |
| `tree_scope_skipped_only_by_stream` | Under a tree (or products) scope only stream identity skips; an envelope is scanned. |
| `round2_skipped_nested_repo_tracked`, `current_scans_nested_repo` | Refuted: the round-2 rule skipped a stream file committed in a nested repository; the current rule scans it. |
| `round2_skipped_tree_scope_envelope`, `current_scans_tree_scope_envelope` | Refuted: the round-2 rule skipped an untracked envelope found by a tree-scope walk; the current rule scans it. |
| `recorded_product_skipped_only_by_stream`, `recorded_non_stream_scanned` | A product the wrapped command recorded is skipped only by stream identity; an envelope-shaped recorded product is always scanned. `current_skips_recorded_own_stream` shows the stream skip still reaches cilock's redirected output. |
| `skip_implies_own` | A skipped file is this process's stream, or an envelope whose surrounding text is clean. |
| `symlink_never_skipped`, `symlink_to_stream_never_skipped` | A symlink anywhere along the path, the last component included, means a scan. |
| `no_git_never_skipped`, `outside_never_skipped` | No git answer, or a path outside the working directory, means a scan. |
| `dirty_residual_scanned`, `not_own_never_skipped` | A finding beside an envelope, or content that is neither the stream nor an envelope, means a scan. |
| `skip_iff` | The whole decision as one equation. |
| `round1_skipped_tracked`, `round1_breaks_untracked` | Refuted: the round-1 rule (`os.Lstat` on the last component, git asked about the spelling) skipped the tracked `tracked-dir/report.log` reached as `alias/report.log` through a symlinked directory (Codex, #10174 round 2). |
| `round0_skipped_tracked`, `round0_breaks_untracked` | Refuted: the first rule (`os.Stat`, which follows a final symlink) skipped a tracked stream file reached through an untracked link. |
| `round2_skipped_gitlink_tracked`, `round2_breaks_untracked` | Refuted: the round-2 rule (heads 3b04d70fe0 / 8e59cd8082) skipped a stream file committed inside a submodule, because the parent's index names only the gitlink (Codex, #10174 round 3). |
| `round2_skipped_recorded_product` | Refuted: the round-2 rule skipped a recorded product shaped as an envelope with a secret in its payload; the residual scan reads only text outside the envelope, so the secret was never scanned (Codex, #10175 round 3). |
| `current_scans_parent_symlink`, `current_scans_final_symlink`, `round1_scans_final_symlink`, `current_scans_gitlink`, `current_scans_recorded_product` | The current rule scans every counterexample. |

All audited results use only Lean's core axioms (`propext`, `Quot.sound`,
`Classical.choice`), or none. There is no `sorry`, no `native_decide` and no
user axiom.

## Assumptions

- **`WellFormed`** is the one relation assumed between the file system and
  git: with no symlink along the path, the spelled name is the real file's
  name, so git's answer for one is its answer for the other. The differential
  test constructs only real states, which satisfy it; the oracle answers
  `ill-formed` for any case that does not, and that is a mismatch.
- **`rel` comes from the walk, not from a user.** The candidate path is the
  name the product or discovery walk produced, so on a case-insensitive file
  system it carries the on-disk case. A spelling that differs only in case
  from a tracked name would pass `realMatches` (`EvalSymlinks` keeps the
  spelled case) and miss git's lookup; the model does not cover that, because
  the Go never receives such a spelling.
- `residualDirty` covers only text outside the envelope. A secret inside the
  payload of a skipped envelope is not scanned; that is accepted only for a
  discovered untracked file (see the forger note above), which is why a
  recorded product never takes the envelope skip.
- `underGitlink`, `recordedProduct`, `treeScope` and `nestedRepo` are optional
  in the oracle's input and default to false, so the round-2 driver still runs.
- `tracked` is ground truth in the repository that OWNS the file: the
  submodule's or nested repository's own index and HEAD, not the parent's.
- The observables (`os.Lstat` regular, `os.SameFile`, `filepath.EvalSymlinks`,
  `git ls-files --cached`, `git ls-tree -r HEAD`) are modelled by what they
  return, not by how. `realMatches` is "`EvalSymlinks(wd/rel)` equals
  `EvalSymlinks(wd)/rel`", which holds exactly when no component of `rel` is a
  symlink.
- Envelope recognition and the residual scan are inputs (`envelope`,
  `residualDirty`): which bytes are an envelope is a parsing question, not the
  security one. That a skipped envelope may itself carry a secret in fields a
  forger controls is accepted by design, because the file is untracked: anyone
  who can write it can already hide it from a diff scope with
  `.git/info/exclude` (`TestDiffScopeAlreadySkipsAnIgnoredUntrackedFile`).

## Differential results

Against #10175 at f8dac412d1 (round 3): 888 real cases (every construction
decided as a recorded product and as a walk file, under a diff scope and a
tree scope; shapes include a checked-out submodule, a gitlink directory with
no checkout, and a nested repository), 7 skips, 0 mismatches. Disabling the
gitlink check, the nested-repository (`foreignOwner`) check, or the envelope
route/scope restriction each turns the driver red. The gitlink check is
distinguishable only by the gitlink directory with no checkout: in a
checked-out submodule the nested-repository check already scans the file.

## Not proved

- That git's index and HEAD are what the push carries: that is
  `scanCommittedBlobs`' job, outside this filter.
- A race between the untracked check and a later `git add`: the skip is made
  at scan time, and a file staged afterwards is read again by the next scan.
