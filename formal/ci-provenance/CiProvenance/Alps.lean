/-
ALPS 0.1 (Agentic Levels for Provenance and Signing) as a verifier function,
and the production model that says what an adversary controlling the agent
process can make that function see.

The published ladder, cumulative, each row including the rows above it:
-- see (monorepo, outside this tree): jade/factory/edge/git/docspage.js:326-331
The producer never assigns its own level; a verifier derives the highest level
the signed evidence supports, and missing evidence is Unknown:
-- see (monorepo, outside this tree): jade/factory/edge/git/docspage.js:341-341
cilock keeps that discipline in code: the run summary never assesses a level.
-- cite: cilock/internal/options/runsummary.go:221-235 sha256:61e4b8402603721f70be01869c6baeeec82fccc55fb1ce15c14f902d0caa807b
No shipped verifier derives a level today, so `deriveAlps` below is a
reference specification, not a model of existing Go code:
-- see (monorepo, outside this tree): jade/factory/edge/git/docspage.js:351-351

The adversary is whoever controls the agent process, including the agent and
its model harness (contract Appendix B). Evidence items are Booleans a
verifier checks ("the item verified"); Unknown is `false`.
-/

namespace CiProvenance

/-- The result a verifier derives. `unknown`: not even ALPS 0 evidence. -/
inductive Alps where
  | unknown | l0 | l1 | l2 | l3
  deriving DecidableEq, Repr

def Alps.rank : Alps → Nat
  | .unknown => 0
  | .l0 => 1
  | .l1 => 2
  | .l2 => 3
  | .l3 => 4

/-- `a.atLeast b`: `a` is level `b` or higher. -/
def Alps.atLeast (a b : Alps) : Bool := decide (b.rank ≤ a.rank)

def Alps.name : Alps → String
  | .unknown => "unknown"
  | .l0 => "ALPS-0"
  | .l1 => "ALPS-1"
  | .l2 => "ALPS-2"
  | .l3 => "ALPS-3"

/-- Who the agent is and which model(s) served it. Written by the model
harness about itself: the session transcript and the process facts the
`alps-evidence` attestor reads are the harness's own, rewritable by the agent.
-- see (monorepo, outside this tree): docs/design/alps-evidence-observed-model-mix.md:26-29
-- cite: plugins/attestors/alps-evidence/alps_evidence.go:31-40 sha256:d21ed12157d340d36e0603ed05a6f4e90a2ff1946eda1b999160b7c84987d944
-/
structure Attribution where
  models  : List String
  invoker : String
  deriving DecidableEq, Repr

/-- What was executed: the command-run facts plus the digest of the CI/lock
executable that recorded them. -/
structure Execution where
  command  : List String
  exitCode : Nat
  cilock   : String
  deriving DecidableEq, Repr

/-- A run's facts. Used both for what really happened and for what the
adversary claims happened. -/
structure Facts where
  attribution : Attribution
  execution   : Execution
  products    : List (String × String)
  deriving DecidableEq, Repr

/-- The deployment as it really is. Each field is a property of the host, not
of the evidence. -/
structure Deployment where
  /-- Short-lived platform-issued identity (enrolled agent or CI workflow OIDC)
  exchanged for a Fulcio leaf. -/
  keyless        : Bool
  /-- The leaf authenticates a human session the agent inherited. -/
  humanSession   : Bool
  /-- RFC 3161 token from the platform TSA. -/
  tsa            : Bool
  /-- Enforced sandbox: session, key and signer-socket paths absent from the
  agent (ALPS 2 requirement). -/
  sandbox        : Bool
  /-- A trusted observer outside the agent signs the boundary reference and
  the measured agent and CI/lock digests. -/
  observer       : Bool
  /-- cilockd executes the requested command and signs outside the agent.
  Designed, not implemented. -/
  daemon         : Bool
  /-- Requester uid differs from the executor/observer uid (cilockd §8.4
  item 4). `cilock daemon install --user` is the case where it is false. -/
  uidSeparated   : Bool
  /-- The daemon's own digest comes from fs-verity, IMA or a package signature
  (§8.4 item 3). -/
  measuredCilock : Bool
  /-- The execution-statement key is hardware-attested (§8.4 item 5). -/
  hwKey          : Bool
  /-- No process of the agent's uid can rewrite the tree during the run
  (cilockd threat T18). -/
  siblingClosed  : Bool
  deriving DecidableEq, Repr

/-- The parties a guarantee is conditional on. `true` = assumed honest. -/
structure TrustBase where
  /-- The CA issues a leaf only to the authenticated principal it names. -/
  fulcio   : Bool
  tsa      : Bool
  /-- The ALPS 2 observer, sandbox and kernel report truthfully. -/
  observer : Bool
  /-- cilockd reports what it ran. -/
  daemon   : Bool
  /-- Hardware attestation roots are honest. -/
  hwRoot   : Bool
  deriving DecidableEq, Repr

def TrustBase.honest : TrustBase := ⟨true, true, true, true, true⟩

/-- Whoever controls the agent process: the agent, and the harness it runs in.
`forge` = it attempts every forgery its position allows; `claim` = what it
writes wherever it chooses the bytes. -/
structure Adversary where
  forge : Bool
  claim : Facts
  deriving DecidableEq, Repr

/-- ALPS 1 today rests on this: the harness reports what really happened and
runs the genuine CI/lock. It is a hypothesis about the harness, never
something evidence can establish. -/
def HarnessFaithful (adv : Adversary) (t : Facts) : Prop := adv.claim = t

/-- What the verifier reads. -/
structure Evidence where
  /-- DSSE signature over the exact statement bytes, commit-bound (ALPS 0). -/
  signed             : Bool
  /-- Leaf chains to the platform root and names a non-human agent or
  workload principal scoped to tenant/repository/purpose (ALPS 1). -/
  issued             : Bool
  timestamped        : Bool
  /-- A boundary reference is present, signed by anyone. -/
  boundaryClaimed    : Bool
  /-- The boundary reference is signed by a non-agent observer (cilockd
  §0.4 condition (a)). -/
  boundaryByObserver : Bool
  /-- Node-signed execution statement: typed-request re-derivation, measured
  CI/lock, uid separation, attested key, authority unavailable (§8.4 2-6). -/
  isolated           : Bool
  attribution        : Attribution
  execution          : Execution
  products           : List (String × String)
  deriving DecidableEq, Repr

/-- The verifier: the highest level whose cumulative requirements hold. -/
def deriveAlps (e : Evidence) : Alps :=
  if !e.signed then .unknown
  else if !(e.issued && e.timestamped) then .l0
  else if !e.boundaryByObserver then .l1
  else if !e.isolated then .l2
  else .l3

/-- A verifier that accepts any boundary reference, whoever signed it: the
"`human: true` mistake in a new costume" the ALPS 2 design warns about. -/
def deriveAlpsLax (e : Evidence) : Alps :=
  if !e.signed then .unknown
  else if !(e.issued && e.timestamped) then .l0
  else if !e.boundaryClaimed then .l1
  else if !e.isolated then .l2
  else .l3

/-- The agent can exercise a signing key: nothing keeps one out of its reach.
At ALPS 1 the enrolled credential is a 0600 bearer file in the agent's uid.
-- cite: cilock/internal/auth/agentstore.go:29-31 sha256:03a8963f745220fd6c7eabb6166d85cbe30cc2723bb3dc209267dae069d49611
-- see (monorepo, outside this tree): docs/architecture/pushgate-agent-policy-contract.md:1412-1418 -/
def agentHoldsKey (d : Deployment) : Bool := !d.sandbox && !(d.daemon && d.uidSeparated)

/-- Who records the execution, and whether that recorder is outside the
adversary and trusted. In-uid CI/lock can be substituted or bypassed by the
agent, which also holds the key; an observed CI/lock under an enforced sandbox
is trusted as far as the observer is; cilockd as far as the daemon is. -/
def executionTrusted (d : Deployment) (tb : TrustBase) : Bool :=
  (d.daemon && d.uidSeparated && tb.daemon) || (d.observer && d.sandbox && tb.observer)

/-- Products are read from a tree the agent's uid can write, so even a trusted
recorder reports adversary bytes unless sibling mutation is closed (T18). -/
def productsTrusted (d : Deployment) (tb : TrustBase) : Bool :=
  executionTrusted d tb && d.siblingClosed

/-- What a deployment emits for one run, given the adversary. An item is
present when the deployment provides it or the adversary can forge it; a
forgery of a signed item needs the signer to be dishonest. Content is the
truth where a trusted recorder outside the adversary wrote it, and the
adversary's claim otherwise. Attribution is always the harness's claim. -/
def emit (d : Deployment) (tb : TrustBase) (adv : Adversary) (t : Facts) : Evidence where
  signed             := true
  issued             := (d.keyless && !d.humanSession) || (adv.forge && !tb.fulcio)
  timestamped        := d.tsa || (adv.forge && !tb.tsa)
  boundaryClaimed    := (d.observer && d.sandbox) || (adv.forge && agentHoldsKey d)
  boundaryByObserver := (d.observer && d.sandbox) || (adv.forge && (!tb.observer || !tb.fulcio))
  isolated           := (d.daemon && d.uidSeparated && d.measuredCilock && d.hwKey)
                        || (adv.forge && (!tb.daemon || !tb.hwRoot || !tb.fulcio))
  attribution        := adv.claim.attribution
  execution          := if executionTrusted d tb then t.execution else adv.claim.execution
  products           := if productsTrusted d tb then t.products else adv.claim.products

/-- The deployment the code supports today: keyless agent or workflow
identity with the platform TSA, and nothing else. The `alps-evidence`
predicate has no boundary field, and cilockd is not built.
-- see (monorepo, outside this tree): docs/design/alps-2-boundary-attestation.md:44-51
-- cite: plugins/attestors/alps-evidence/alps_evidence.go:146-178 sha256:b54167d00e7d6da11179c49cc99aee2005c47069c0d233120d5dce733a8a29f5
-- see (monorepo, outside this tree): docs/architecture/pushgate-agent-policy-contract.md:1327-1327 -/
def asBuilt : Deployment :=
  { keyless := true, humanSession := false, tsa := true, sandbox := false, observer := false,
    daemon := false, uidSeparated := false, measuredCilock := false, hwKey := false,
    siblingClosed := false }

/-- The designed cilockd deployment on Linux with a TPM, with the ALPS 2
sandbox around the agent: §8.5 row 1 under the three conditions of §0.4.
-- designed, not implemented (docs/design/cilockd/cilockd.md:4121-4123, PR #9042) -/
def cilockdLinuxTpm : Deployment :=
  { keyless := true, humanSession := false, tsa := true, sandbox := true, observer := true,
    daemon := true, uidSeparated := true, measuredCilock := true, hwKey := true,
    siblingClosed := false }

end CiProvenance
