# Reading a Pushgate refusal

Every refused push is written to stderr twice. The prose is for your human and
may be reworded. The JSON is the contract. It arrives on a line containing
`pushgate-challenge: `, indented and prefixed by Git with `remote: `. Take
everything after `pushgate-challenge: ` on that line and parse it as JSON.

| Field | What to do with it |
| --- | --- |
| `decision` | Always `DENY` on a refusal, including when the platform was down. Never read it as "maybe". |
| `evaluated` | `false`: no policy evaluation happened. Your evidence was never judged and is still good. Push the same commit again. Do not re-run cilock, do not amend, and do not re-mint. `true`: a real judgment. Act on `missing_evidence`. |
| `commit`, `commits` | The commit(s) you must produce evidence **for**. Attesting a different commit is the most common way an honest retry still fails. |
| `missing_evidence[]` | One entry per failed check. `command` is the exact cilock line that produces what is missing. A release entry can carry `commands[]`, one per failed step. `command: null` is not a pass. Read `type`. |
| `retry_without_changes` | `true` for a stale nonce or a platform outage. `false` means pushing the identical bytes again returns the identical answer. |
| `policies[]` | The policies this push was judged against. `readable_by` says who can open each `url`: `anyone`, or `signed-in human` for a signed release. Do not spend a push credential trying to open a human-only page. |

## Types that need a human

- `release-owner-action`: no command can fix it. Stop and give your human the
  `owner_action` sentence.
- `release`: the gate could not turn the signed verdict into a command. Show
  your human the refusal.
- `signer-*` (for example expired, revoked, out of scope): your agent identity
  cannot satisfy the gate. The fix is a new enrollment ceremony or a scope
  change, and both are the human's acts. Never fall back to a human session.

## Stop conditions

- The same refusal after you ran its remedy: stop and show the human the full
  message.
- A remedy that asks for anything broader, such as a raw key, a wider token, a
  disabled policy, or a Product binding: that is not a Pushgate remedy. Stop
  and report it.
