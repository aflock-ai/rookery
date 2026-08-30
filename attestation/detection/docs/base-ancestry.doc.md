---
title: base-ancestry
description: Record where the tested commit sits relative to its base branch — head, the base the clone saw, their merge-base, and whether the head includes that base — so a gate can enforce "current with base" against the provider's live base.
sidebar_position: 5
---

`base-ancestry` answers one question about the commit under test: does it
include the base branch it claims to be built on? It records the head commit,
the base ref, the base commit the local clone could see for that ref, the
merge-base of the two, and the relationship those hashes imply.

It is the client half of Pushgate's **Current with base** rule. The attestor
signs what the LOCAL commit graph showed at test time; the platform reads the
provider's CURRENT base with its own repository-scoped identity and joins the
two. A base that advanced after the tests ran shows up as a mismatch between
the attested base and the provider's, and the gate can refuse the push with a
precise reason instead of GitHub's broad "mergeable" state.

## Validated invocation

Run it beside `git` — the git attestor is what binds the collection to the
exact head commit — from a clone that has fetched the base branch:

```bash
cilock run \
  --step push-tests \
  --platform-url "$PLATFORM_URL" \
  --attestations git,alps-evidence,base-ancestry \
  --attestor-base-ancestry-base-ref main \
  -- go test ./...
```

`alps-evidence` rides along for a reason unrelated to the base: passing ANY
explicit attestor list disables cilock's workload auto-detection, and that
attestor is what the Pushes ledger reduces to attribute a push to a coding
agent. A `push-tests` list that stops at `git,base-ancestry` mints evidence
with no agent record, and every push it gates reads `agent=NULL`.

`--attestor-base-ancestry-base-ref` names the base branch. Omit it and the
attestor falls back to `GITHUB_BASE_REF` (set by GitHub Actions on
`pull_request` events), then to the remote's recorded default branch
(`refs/remotes/origin/HEAD`, written by `git clone`). With none of the three
the predicate records `relationship: unknown` and a warning saying so.
`--attestor-base-ancestry-remote` changes the remote whose tracking refs
supply the base (default `origin`).

## What gets captured

- `head`: the commit under test (HEAD of the working directory).
- `base_ref` and `base_ref_source`: the base branch by short name, and who
  chose it — `flag`, `env:GITHUB_BASE_REF`, or `remote-head`.
- `base_resolved_from`: the full local ref the base commit was read from,
  normally `refs/remotes/origin/<base>`. A local branch of the same name is the
  fallback and is named as such, because it may never have been fetched.
- `base`: the base commit **as the clone saw it** — not the provider's current
  base, which only the platform can observe.
- `merge_base`: `git merge-base head base`.
- `relationship`: `current` (the base is an ancestor of the head), `behind`
  (the head is an ancestor of the base), `diverged` (each side has commits the
  other lacks — a statement about the graph, not about conflicts), or
  `unknown`.
- `shallow`: whether the clone has grafted history.
- `observed_at`: when the graph was read.
- `remotes`: configured remote URLs with credentials stripped, the same
  repository identity the git attestor records.
- `warnings`: why a relationship could not be established. Never empty when
  `relationship` is `unknown`.

No subjects, backrefs, materials, or products are emitted.

## Why this shape

The rule needs two independent observations of the same fact. The client can
only sign what its clone contained; the platform can only read what the
provider serves now. Neither alone proves that the tested commit includes the
current base: the client's base may be stale, and the platform has no signed
record of what was tested. Keeping this predicate strictly local means it needs
no provider credential, cannot be confused by one, and stays honest about what
it is — an observation of a graph at a moment.

`unknown` is a first-class answer rather than a failure. A shallow clone, an
unfetched base, or no base ref at all each yield a signed predicate that says
the relationship could not be established and why. A gate in Enforce mode
refuses it; one in Observe mode shows it; neither can mistake it for `current`.

## Validate it locally

Build the in-tree binary and run the attestor in a throwaway clone with an
ephemeral key, once per state you want to see:

```bash
cd subtrees/rookery/cilock && GOWORK=off go build -o /tmp/cilock ./cmd/cilock
openssl genpkey -algorithm ed25519 -out /tmp/key.pem
cd /path/to/a/clone && git fetch origin main
/tmp/cilock run --step base-ancestry-check --workload manual --platform-url '' \
  --signer-file-key-path /tmp/key.pem --enable-archivista=false \
  --attestations git,base-ancestry --attestor-base-ancestry-base-ref main \
  --outfile /tmp/attestation.json -- true
```

Decode the collection and read the `base-ancestry` entry. Advance `origin/main`
past the head (`git fetch` after a merge upstream) and rerun to see `diverged`;
`git clone --depth 1` a repository to see `shallow: true` with `unknown`.

## How a verifier consumes this

Pushgate's evaluate endpoint reduces the predicate out of the verified
collection for the pushed commit, then compares four things: the predicate's
`head` equals the pushed commit; its `base_ref` equals the pull request's
target branch (or the repository's configured base); its `base` equals the
base commit the platform read from the provider; and its `merge_base` equals
that base. All four hold only when the exact commit being pushed includes the
base as it stands now. The joined result travels in the signed verdict as
`base_ancestry` — with `target_source` saying whether a pull request, a
configured base, or nothing selected the target — and is reported on the push
ledger. The attestor itself proves nothing on its own: without the platform's
read of the provider it is one side of a comparison.

## Notes

- The remote-tracking ref is preferred over a local branch of the same name
  because it is what the clone last **fetched**; the local branch is only what
  the developer last checked out. `base_resolved_from` says which was used.
- Criss-cross histories have several merge-bases. The relationship is decided
  by whether the base itself is among them; the first is recorded and a
  warning notes the ambiguity.
- A base ref whose object is missing from the store (a partial clone, a
  hand-written ref) yields `unknown` with a warning naming the ref.
- The attestor never contacts the provider and never reads credentials.

## Gotchas

- `current` means current with the base **the clone saw**. If the base
  advanced upstream after the last fetch, the platform's join reports it, not
  this predicate. Fetch before testing to keep the two in step.
- A rebase changes the head SHA, so the collection this predicate travels in no
  longer matches the pushed commit. Re-run CI/lock after rebasing; that is the
  rule working as designed.
- `diverged` does not mean the merge would conflict, and `current` does not
  mean reviews, checks, or policy passed. Those are separate observations.
- Passing `--attestations` replaces cilock's default set, so name `git`
  explicitly beside `base-ancestry`; without it nothing binds the collection
  to the commit.

## FAQ

### Can the platform trust `base` as the provider's current base?

No, and it is not meant to. `base` is the client's view. The platform reads
the provider itself and compares; a difference is exactly what the rule exists
to catch.

### What happens on the first push of a branch, before a pull request exists?

The attestor still records the relationship against whatever base it chose.
Whether that is enforced depends on the gate: with no pull request and no
configured base, Pushgate reports "not evaluated" rather than guessing a
target.

### Why not read the base from the `git` predicate?

The git attestor records the head commit and its parents, which is not enough
to say whether an arbitrary base is an ancestor. Ancestry needs the merge-base,
and overloading the git predicate with a base-relative field would blur what a
verified `commithash` subject means.

## See also

- `git` — binds the collection to the exact head commit; run it beside this.
- `github-review` — records pull request head and base SHAs as the API showed
  them, without proving ancestry.
