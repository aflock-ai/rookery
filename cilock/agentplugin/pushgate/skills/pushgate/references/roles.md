# Who does what

Pushgate keeps each act separate. One signature or one account never proves a
different act.

| Act | Who | Your part |
| --- | --- | --- |
| Produce evidence (`cilock run`, `cilock attest`) | You, signing as your enrolled agent | All of it |
| Enroll the agent (`cilock enroll agent`) | The human approves with a passkey | Start it, wait, read `cilock agent status` |
| Draft a policy | You | All of it, including a local proof with `cilock policy prove` |
| Sign and publish a policy | The human, on the platform, with a passkey | Prepare the draft and open the review link |
| Assign the policy to a repository (Warn or Block) | The human | Explain the before/after effect and read the result back |
| Revoke an agent | The human, on the platform | `cilock agent logout` removes only the local credential |

## Why the lines are where they are

- A policy decides what your future evidence must prove. If an agent could
  sign one, it could write its own exam. The platform refuses a policy signed
  by an agent identity, so trying only wastes a round.
- Your agent identity is bounded: it expires, the human can revoke it, and it
  is scoped to repositories. That bound is why you may sign evidence without a
  human touching each signature. Borrowing the human's login would remove the
  bound. That is why cilock never falls back to it, and you must not either.
- Framework names such as SOC 2 or NIST SSDF express the human's intent.
  A policy that passes is not a certification. Say what each rule checks and
  what it does not.

## Labels

When you report results, use the label for the claim you can actually make:

- **Verified**: cryptography and bindings were checked. Example: a
  `cilock verify` pass.
- **Observed**: a component recorded something it saw. It is not an
  identity claim.
- **Declared**: someone stated it, and nothing has proved it.
- **Enforced**: Pushgate evaluated a signed policy against the exact commit.
- **Approved**: a human account accepted an exact activation or override.

A local `Local verify: passed` is Verified for your scratch proof only. It is
not Enforced until the human has signed and assigned the policy and Pushgate
has evaluated a real push.
