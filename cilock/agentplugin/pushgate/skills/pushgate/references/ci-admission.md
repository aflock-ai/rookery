# Let a Pushgate verdict replace PR-tier CI

When a repository's pushes go through Pushgate, the platform has already
judged each pushed commit against the assigned policy and stored a signed
verdict (a VSA) for it. PR-tier CI that re-runs the same checks is paying twice.
The recommended pattern:

1. **Push through Pushgate.** The agent mints the steps the assigned release
   names and pushes. Pushgate stores one signed VSA per commit per assigned
   policy.
2. **One cheap CI job verifies that VSA** for the pull request's head commit.
   If it passes, the heavy PR-tier jobs skip.
3. **The merge queue, or post-merge CI, still runs the full suite.** The merged
   tree never passed through Pushgate, so nothing there is skipped.

You set this up for your human. **You do not sign the admission policy**; a
human does, like any other policy.

## What a verdict looks like, and the traps

- **One VSA per assigned policy.** A push evaluated against two releases leaves
  two VSAs for the commit, and other platform checks may leave more, some of
  them `FAILED`. The admission policy must pin **which** release's verdict
  admits: the VSA's signed `policy.uri` (the release) and `policy.digest`
  (its exact revision). "Some VSA passed" is not the rule.
- **The commit is a SHA-1 subject.** The VSA names its commit as
  `https://pushgate.dev/v0.1/commithash:<sha>` with a `sha1` digest. SHA-1 is
  not collision-resistant, so cilock refuses to match a standalone attestation
  by a SHA-1 subject unless the policy **declares** it: set `commitSubject` to
  that exact prefix on the external attestation. Without it, verify reports the
  VSA was found and refused, and names `commitSubject` as the remedy.
- **The signer is the platform, not you or your human.** The external's
  functionary is the platform verdict signer under the platform's Fulcio root.
  `cilock verify`'s errors name the signer it saw; `cilock doctor` shows the
  platform you are connected to.
- **Hardened constraints need explicit wildcards.** A certificate constraint
  field left as an empty list is refused as vacuous. Write `"*"` for any field
  you do not pin, and pin the ones that identify the signer (email, issuer,
  root).
- **Pin the repository and tenant** in the rule as well: the VSA's signed
  `repository`, `repository_id` and `tenant` fields. A verdict for another
  repository must never admit.

## The policy, in outline

A policy with no steps and one required external attestation is valid:

- `externalAttestations.<name>.predicateType`: the VSA predicate type the
  platform currently signs (read it off a real verdict; do not guess a version).
- `commitSubject`: `https://pushgate.dev/v0.1/commithash:`.
- `functionaries`: the platform verdict signer.
- `regopolicies`: deny unless `verificationResult` is `PASSED`, `policy.uri`
  and `policy.digest` match the release, and `repository`, `repository_id` and
  `tenant` match.

`cilock policy draft --hydrate-local` fills the platform trust roots from
discovery, so you never copy certificates by hand. Then:

1. `cilock policy validate -p <draft>`.
2. Prove it before your human signs it: with the throwaway local key the loop
   allows, sign a scratch copy and run `cilock verify -p <scratch> -k <pub>
   --subjects sha1:<commit> --enable-archivista` twice: once for a commit that
   was pushed through Pushgate (must pass), once for one that was not (must
   fail with "not found"). A policy that only ever says yes proves nothing.
3. Hand the draft to your human to sign. They run `cilock sign --human -f
   <draft> -o <signed>`, which opens their browser to log in to the platform
   and signs as them. On a machine where you are enrolled, a plain `cilock
   sign` refuses a policy and prints that command. Never run it yourself and
   never complete the login.

## The CI job

- **Credentials:** your human runs `cilock trust github <owner/repo> --verify`
  once. CI then reads Archivista with the job's GitHub OIDC token
  (`permissions: id-token: write`); no secret is stored. Prefer a trust scoped to
  read only.
- **Command:** `cilock verify -p <signed policy> --subjects sha1:<head sha>
  --enable-archivista --archivista-oidc --format json`, pinning the policy's
  human signer with `--policy-emails` and `--policy-fulcio-oidc-issuer`. Gate on
  the **exit code**. Never pipe `cilock verify` into another command: the pipe's
  status replaces verify's and hides a failure.
- **Take the verifier and the signed policy from the PR's base commit**, not
  from the PR, so a pull request cannot admit itself by editing either.
- **Fail closed.** Any error, a missing policy, or a fork PR (no OIDC) means
  "not admitted": run full CI.

## Finding a commit's verdicts by hand

- `cilock pushgate status --commit <sha>` says whether Pushgate ever saw the
  commit. `not_found` means no VSA can exist for it: push it through the
  Pushgate remote.
- The verify error lists the subjects it searched and every candidate it found,
  with each candidate's signed subjects and the reason it was refused. Read it
  before changing the policy.
