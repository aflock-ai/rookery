---
name: pushgate
description: Push through Pushgate with cilock. Enroll this agent, record signed evidence with `cilock run`, act on a `pushgate-challenge` refusal, and draft and prove a Pushgate policy for a human to sign. Use when a git push is refused by Pushgate, when a repository pushes through Pushgate (pushgate.dev), when asked to attest tests or scans with cilock, or when asked to create a Pushgate or witness policy draft. Do not use it to sign, publish, or activate a policy; those are a human's acts.
---

# Pushgate with cilock

**Pushgate** sits in front of a Git remote. It refuses a push unless signed
evidence for the exact commit satisfies the policy a human assigned to the
repository. **cilock** is the CLI that produces that evidence. It wraps a
command, records attestations, and signs them as your enrolled agent identity.
It also helps you draft policies.

This skill tells you the loop and the rules. It does not carry flags, predicate
fields, attestor lists, or rule templates. Those change between releases, so
the CLI prints them: `cilock <command> --help`, `cilock policy guide`, and the
error messages. When this skill and the CLI disagree, the CLI wins. This skill
ships inside cilock. Run `cilock skill show` to read the copy that matches the
binary you have.

## Rules you never break

1. **Humans sign policies. Agents sign attestations.** Never sign, publish,
   or activate (assign) a policy. Never complete a
   passkey prompt or click a final Sign or Apply button, even when you control
   a browser in their session.
2. **Never substitute identity.** Do not remove agent enrollment, borrow the
   human's `cilock login` session, or use a file key in place of the enrolled
   agent or the human's platform signature. The one sanctioned key is the
   throwaway local key `cilock policy prove` uses for an offline proof. It
   never leaves the machine and is never presented as the policy.
3. **Never weaken a rule to make it pass.** If a rule refuses real evidence,
   report the refusal and let the human choose: fix the code, or relax the
   rule themselves.
4. **Evidence comes only from cilock.** A command you ran outside `cilock run`
   or `cilock attest` may inform you, but it is not evidence.
5. **Never print credentials.** A Pushgate remote URL can carry a push
   credential. Do not print `git remote -v` unredacted, paste a remote URL, or
   echo a token.

If the loop stalls on one of these (for example, enrollment is refused or
expired), stop and tell the human. Do not route around it.

## The loop

Before you start, run `cilock version`. If a command below is missing, your
cilock is older than this skill. Tell the human; do not improvise a substitute.

1. **Enroll this agent** (once per lifetime):
   `cilock enroll agent --repo <owner/name>`. A browser opens and **the human**
   approves it with a passkey. You can start the ceremony, but you cannot
   finish it. Then run `cilock agent status`. It must name a principal and an
   expiry. Exit 0 alone proves nothing, because it also exits 0 when nothing
   is enrolled. The identity is time-bound and cannot be extended. When it
   expires, the human runs a new ceremony.
2. **Configure Git signing:** `cilock git configure` (this repository only).
   The Pushgate remote itself comes from the setup document your human gets
   from Pushgate. Follow that document; never invent a remote URL.
3. **Commit, attest, push.** Evidence binds to a commit, so commit first. Then
   produce evidence for that commit with `cilock run --step <step> -- <command>`
   (or `cilock attest --step <step> ...` for an at-rest snapshot). Then push.
   Do not re-run the gate from a Git `pre-push` hook.
   - Check cilock's own exit code. `cilock run ... | tee log` reports tee's
     exit, not cilock's, so a failed step looks like success; use
     `set -o pipefail` or no pipe. A step whose command fails is still signed
     and uploaded, and the gate refuses it.
   - `command exit: 127` (or 126) means the shell could not run the command:
     the tool or the project's dependencies are not installed. Fix that
     before recording the step again.
4. **Read a refusal.** A refused push prints a line containing
   `pushgate-challenge: {...}`. Parse that JSON, not the prose above it.
   - `evaluated: false`: the platform never judged you. **Push the same commit
     again.** Do not re-run cilock and do not amend.
   - `evaluated: true`: run each `missing_evidence[].command` for the named
     `commit`, then push. A `command` of `null` is not a pass. Check `type`.
   - `release-step-failed`: the step's evidence exists but a rule refused it.
     Fix the cause, record the step again, and push **the same commit**.
     Make a new commit only if the commit's own contents cause the failure;
     an environment or command problem is fixed by re-recording the step.
   - `retry_without_changes: false`: pushing unchanged returns the same answer.
   - The same refusal again after you followed its remedy: stop and show your
     human the full message.

   Field-by-field detail: [references/refusals.md](references/refusals.md).
5. **Draft a policy** (only when the human asks for one, or none fits):
   1. Ask the human what a push must prove, such as tests, secrets, known
      vulnerabilities, or a build. Ask which frameworks matter and whether to
      start in Warn or Block. Framework names are intent, not certification.
   2. `cilock policy guide` lists the goals. `cilock policy guide --goal <id>`
      explains what one goal needs: the command, the attestor, what the
      evidence looks like, and the traps.
   3. `cilock policy template --goal <id>` (or `--add-step <name>`) writes a
      skeleton. The trust roots and functionaries are already filled in; leave
      them. Every `FILL` slot needs your judgment about *this* repository: the
      real command, the rule that separates a pass from a failure, and the
      files that must be present. A generated draft is not the human's intent.
   4. `cilock policy prove -p <draft> --step <name> -- <command>` proves the
      draft admits real evidence and refuses a failing run, offline. Its first
      line is your verdict: `Local verify: passed` or
      `Local verify: REFUSED by <step>: <rule>`.
   5. `cilock policy validate -p <draft>`. The platform fills the trust-root
      certificates when the human signs, so an error about their empty
      certificate data is expected. Any other error is real. Fix it.
6. **Hand off.** Save the draft as `.pushgate/policy.json` and end with the
   handoff block below. The human imports it on Pushgate, validates it, signs
   it on the platform with their passkey, and assigns it to the repository
   (Warn or Block). You may open links and poll read-only status. A closed
   browser or a timeout is not success, so read the status back. No agent API
   or cilock command reports the assignment: ask the human for the release
   and mode the Pushgate page shows. Do not guess Pushgate API URLs. A refused
   push also names the assigned release that refused it in `policies[]`.
7. **Push with evidence.** Once the policy is assigned, run each step through
   cilock for the commit and push. `cilock pushgate status --wait` reports
   delivery to the real remote.
8. **Stop paying for CI twice** (when the human asks). A pushed commit carries
   a signed Pushgate verdict. One cheap PR-tier job can verify it and skip the
   checks the release already proved, while the merge queue still runs
   everything. How, and the traps (one verdict per release, SHA-1 commit
   subjects, pinning the release): [references/ci-admission.md](references/ci-admission.md).

## Handoff block

The first line is copied exactly from `cilock policy prove`:

```
Local verify: passed
Draft:   .pushgate/policy.json (unsigned, not active)
Steps:   <step>: <command> (proved against <commit>)
Checked: <what each rule refuses, one line per step>
Gaps:    <what this policy does not prove>
Next:    human imports the draft on Pushgate, validates it, signs it on the platform, and assigns it (Warn or Block)
```

On `Local verify: REFUSED by <step>: <rule>`, say whether the code or the rule
is wrong, and let the human decide. Do not change the rule until it passes.

## When you are stuck

- `cilock <command> --help` is the current source of truth for flags.
- A cilock error names the next step. Read it before trying anything else.
- `cilock doctor` preflights the platform connection.
- Who does what, and why: [references/roles.md](references/roles.md).
