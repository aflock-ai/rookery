/-
  CilockPolicy.Verify: Policy.VerifyWithExternals (`policy.go`) as a
  total function over an evidence list.

  Two verdicts are defined over the same pieces:
  * `verifyAsBuilt`: the engine before #9860. The attestationsFrom Rego
    context is read from each dependency's Passed set BEFORE artifact pruning.
    Issue #9813. The engine on main is `verifyShipped` (Bound9813.lean): the
    union-acyclicity validator, then the round-bounded loop #9860 shipped.
  * `verifyFixed`: the same pipeline iterated to a JOINT fixed point: every
    step is re-gated with a context read from the dependencies' SURVIVING
    collections, until nothing changes. The soundness theorems are proved for
    this one; the as-built one is refuted in Counterexamples.lean.

  Modelling conventions (see README "Not modelled"):
  * `p.steps` is listed in the engine's topological order (`policy.go`),
    and step map keys equal Step.Name (`validate.go`; with the
    EnforceStepNameCoherence flag the engine refuses otherwise, `policy.go`).
  * Rego and AI are one opaque predicate per required attestation (`Rego`).
  * The search is the whole evidence list; the source's own filtering can only
    drop candidates and is re-checked by VerifiedSource (`verified.go`).
  -- cite: attestation/policy/policy.go:667-760 sha256:1c0fa9d05d664e9dccb0ac5453619a38fb9f5776e8809caad447fbd8e67fad27
  -- cite: attestation/policy/policy.go:1009 sha256:3c4ad285bf16007f3ad8d88adef106e95609d49f88b1c8358a1d292a39b17cde
  -- cite: attestation/policy/policy.go:1151 sha256:c2e494e031a8e25b0662fe4d1a69e0567568aa36eaf18bff7f72ddc8fc8d88c0
  -- cite: attestation/policy/policy.go:606-662 sha256:d3d162656defee17a14273bb468cef2b2f65146073be5f3915fd09469454410e
  -- cite: cilock/internal/policy/validate.go:354-357 sha256:16297b0f0b687d9a6ecf5d5b872937a20dd90d2d3c4077e1a1edfeaf55b0ac90
  -- cite: attestation/policy/policy.go:499 sha256:5839f38abbb0838072bd486680ea33d28649db7abff272bc900592e4c49a76a6
  -- cite: attestation/source/verified.go:554-652 sha256:84d0dc156f758dce85275bd42c904677571fdf7d38d720764f265529b950e835
-/
import CilockPolicy.Trust

namespace CilockPolicy

/-! ## Subjects: the anchor (`verified.go`, `digestset.go`)
  -- cite: attestation/source/verified.go:211-234 sha256:cbfc9088b890f03b7785f713cec48446e5b339bc10388dfb7e07330072e1ca47
  -- cite: attestation/cryptoutil/digestset.go:216-681 sha256:abeaf498c5237a990f7ecf8fc00a18380c745e230eb2c38ef849bdcdd758a078
-/

def isHexChar (c : Char) : Bool := c.isDigit || ('a' ≤ c && c ≤ 'f') || ('A' ≤ c && c ≤ 'F')
def isHex (s : String) : Bool := !s.isEmpty && s.toList.all isHexChar

/-- git's all-zero object id (`gitNullOID`), written for "no such commit". -/
def gitNullOID : String := "0000000000000000000000000000000000000000"

/-- The exact hardened git attestation type (`hardenedGitAttestationType`). -/
def hardenedGitType : String := "https://aflock.ai/attestations/git/v0.1"

/-- isGitCommitSubject: the value is 40 hex and not the null object id, and
    the name is "commithash:<digest>" or "<hardened git type>/commithash:<digest>",
    where only the trailing 40 digest characters are compared case-folded and
    everything before them exactly as attested. -/
def gitCommitSubject (s : Subject) : Bool :=
  let n := s.name.toList
  let cut := n.length - 40
  s.digest.alg == "sha1" && s.digest.value.length == 40 && isHex s.digest.value &&
    lower s.digest.value != lower gitNullOID &&
    40 ≤ n.length &&
    (n.drop cut).map Char.toLower == lower s.digest.value &&
    (n.take cut == "commithash:".toList || n.take cut == (hardenedGitType ++ "/commithash:").toList)

/-- IsMatchableSubjectDigest under a statement's scope. The sha1 arm is the
    hardened-git commit subject (`gitCommitSubject`). -/
def matchable (hardenedGit : Bool) (s : Subject) : Bool :=
  (s.digest.alg == "sha256" && s.digest.value.length == 64 && isHex s.digest.value) ||
  ((s.digest.alg == "gitoid:sha256" || s.digest.alg == "dirHash") && s.digest.value != "") ||
  (hardenedGit && gitCommitSubject s)

/-- The algorithms a match key can name, in the order ParseSubjectDigestKey
    tries them (`subjectKeyAlgorithms`, `subject_key.go`). -/
def keyAlgorithms : List String := ["gitoid:sha256", "gitoid:sha1", "sha256", "dirHash", "sha1"]

/-- SubjectDigestKey: a subject digest is matched as `algorithm:value`, never by
    its value alone (#9816, fixed by #9863). -/
def subjectKey (s : Subject) : String := s.digest.alg ++ ":" ++ s.digest.value

/-- The algorithm a key names, if it is a key: a known algorithm, a colon, and
    a non-empty value (ParseSubjectDigestKey). -/
def keyAlg? (k : String) : Option String :=
  keyAlgorithms.find? fun a => (a ++ ":").toList.isPrefixOf k.toList && (a ++ ":").length < k.length

/-- The value half of a key, or the whole string for a bare value. -/
def keyValue (k : String) : List Char :=
  match keyAlg? k with
  | some a => k.toList.drop (a ++ ":").length
  | none => k.toList

/-- NormalizeSubjectSeed: a key is kept; a BARE value is bound to the one
    algorithm its shape proves, and nothing else. -/
def normSeed (seed : String) : String :=
  if (keyAlg? seed).isSome then seed
  else if seed.length == 64 && isHex seed then "sha256:" ++ seed
  else if seed.length == 40 && isHex seed then "sha1:" ++ seed
  else if "gitoid:blob:sha256:".toList.isPrefixOf seed.toList then "gitoid:sha256:" ++ seed
  else if "gitoid:blob:sha1:".toList.isPrefixOf seed.toList then "gitoid:sha1:" ++ seed
  else if "h1:".toList.isPrefixOf seed.toList then "dirHash:" ++ seed
  else seed

/-- The seed KEYS a collection's SIGNED subjects hit. policyverify renders each
    seed DigestSet as algorithm:value keys (`policyverify.go`), the verified
    source normalizes every seed and keys every subject the same way
    (`verified.go`), so a value recorded under one algorithm never matches a
    seed computed under another.
    -- cite: plugins/attestors/policyverify/policyverify.go:117-134 sha256:237f48662d314cab35a32b69eb277b293aa328896b84e717a3ce9548e4f5790b
    -/
def anchorHits (seeds : List String) (c : Collection) : List String :=
  (c.subjects.filter fun s => matchable c.hardenedGit s && (seeds.map normSeed).contains (subjectKey s)).map
    subjectKey

/-- payloadMatchesSubjects: at least one matchable signed subject's key is a seed. -/
def anchored (seeds : List String) (c : Collection) : Bool := !(anchorHits seeds c).isEmpty

/-! ## Commit binding (`commit_binding.go`)
  -- cite: attestation/policy/commit_binding.go:117-160 sha256:f83e54b22c5558f44222f7dcdab4db92789ce94dae8bb240a478114bb9ce1eaf
-/

def gitType : String := "https://aflock.ai/attestations/git/v0.1"

def gitHashes (c : Collection) : List String :=
  (c.attestors.filter (·.type == gitType)).map (·.commitHash.getD "")

/-- Every git attestation names the commit, and there is at least one. -/
def commitOk (o : Options) (c : Collection) : Bool :=
  match o.commit with
  | none => true
  | some k => !(gitHashes c).isEmpty && (gitHashes c).all fun h => lower h == lower k

/-! ## Rego context and the gate (`step.go`)
  -- cite: attestation/policy/step.go:645-1071 sha256:737e47aee5e7fd8f4251f588f6777d40f52912f8bd7cb1604e6b8e8363647700
-/

/-- What Rego sees besides the attestor: input.steps (dependency name ->
    that dependency's passed collections) and input.external. -/
structure Ctx where
  steps : List (String × List Collection)
  ext   : List (String × Collection)
deriving DecidableEq, Repr

/-- The opaque Rego + AI gate of one required attestation. -/
abbrev Rego := Nat → Attestor → Ctx → Bool
/-- The opaque Rego + AI gate of an external attestation (bare predicate). -/
abbrev RegoExt := Nat → Collection → Bool

/-- gateOneContext + gateBound: exact name, commit binding, a non-empty
    requirement list, every required type present, and EVERY attestor of that
    type passing its gate (no last-writer-wins, `step.go`).
    -- cite: attestation/policy/step.go:943-1035 sha256:8520bea44bb8e0453489db239dde30984bb2f15b724f86002916bbdb298b2ee1
    -/
def gate (rego : Rego) (o : Options) (s : Step) (ctx : Ctx) (c : Collection) : Bool :=
  c.name == s.name && commitOk o c && !s.atts.isEmpty &&
  s.atts.all fun r =>
    let as := c.attestors.filter (·.type == r.type)
    !as.isEmpty && as.all fun a => rego r.gate a ctx

/-- Everything a candidate must satisfy before the gate: the search's name
    filter (`policy.go`), DSSE + the signed-subject guard
    (`verified.go`) and functionary triage.
    -- cite: attestation/policy/policy.go:1320 sha256:48fc7d8f69112af5d78747179bd96e7fba9d32bda32b7bf300bb8db09e22a94f
    -- cite: attestation/source/verified.go:554-652 sha256:84d0dc156f758dce85275bd42c904677571fdf7d38d720764f265529b950e835
    -/
def authorized (h : Hardening) (p : Policy) (o : Options) (s : Step) (e : Envelope) : Bool :=
  e.payload.name == s.name && anchored o.seeds e.payload && triage h p o s e

/-! ## Subject fan-out guard (`subject_fanout.go`), opt-in
  -- cite: attestation/policy/subject_fanout.go:74-278 sha256:0f4c925e5643240fdf5b57811ef2fe52b0bc4b0922f9b5e41b5bf526bb20966b
-/

/-- Admission over the functionary-AUTHORIZED set `auth`: a seed key hit by
    more than maxFanout authorized candidates is a hub unless its value is the
    bound commit (isBoundCommitDigest compares the value half); a candidate
    needs one non-hub hit. maxFanout = 0 disables. -/
def fanoutAdmit (o : Options) (auth : List Envelope) (e : Envelope) : Bool :=
  o.maxFanout == 0 ||
  (anchorHits o.seeds e.payload).any fun d =>
    decide ((auth.countP fun e' => (anchorHits o.seeds e'.payload).contains d) ≤ o.maxFanout) ||
    o.commit.any fun k => (keyValue d).map Char.toLower == lower k

/-- A step's Passed set for a given Rego context. -/
def passedFor (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (s : Step) (ctx : Ctx) : List Envelope :=
  let auth := E.filter (authorized h p o s)
  auth.filter fun e => fanoutAdmit o auth e && gate rego o s ctx e.payload

/-! ## Step results -/

/-- Step name -> collections. -/
abbrev State := List (String × List Envelope)

def State.get (st : State) (n : String) : List Envelope := (st.lookup n).getD []

/-- buildStepRegoContext (`step.go`): if every dependency has a passed
    collection, each dependency's collections; otherwise an empty map (Rego
    still runs, `step.go`).
    -- cite: attestation/policy/step.go:749-777 sha256:736a4b92255e9b790d8c3f61dd2a1bf887f81a1d160d0ea34e24cae1868ae0ad
    -- cite: attestation/policy/step.go:757-764 sha256:fa97f4055ea2ac4963deae674ba78c917d80fe438481248c3e012bdfe9d44e53
    -/
def stepsCtx (s : Step) (st : State) : List (String × List Collection) :=
  if s.attestationsFrom.all fun d => !(st.get d).isEmpty then
    s.attestationsFrom.map fun d => (d, (st.get d).map (·.payload))
  else []

/-- One external assignment: the external collection each referenced external
    shows Rego (input.external). -/
abbrev Assign := List (String × Collection)

def extCtx (s : Step) (α : Assign) : List (String × Collection) :=
  s.externalFrom.filterMap fun n => (α.lookup n).map (n, ·)

/-- AS-BUILT (pre-#9860) step phase: topological order, each step's context
    read from the results accumulated so far, i.e. BEFORE pruning. The step
    loop cited below is the one #9860 turned into the round loop: its first
    round is this phase (`fix9813Loop` with `prev = none`).
    -- cite: attestation/policy/policy.go:994-1149 sha256:e5695bc78bae9bf145b0785a3813c440afe983f60b80a539405e38abe3588bfc
    -/
def phaseAsBuilt (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (α : Assign) : State :=
  p.steps.foldl (fun st s =>
    st ++ [(s.name, passedFor rego h p o E s ⟨stepsCtx s st, extCtx s α⟩)]) []

/-- FIXED step phase: every step's context read from `prev`. -/
def phaseFrom (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (α : Assign) (prev : State) : State :=
  p.steps.map fun s => (s.name, passedFor rego h p o E s ⟨stepsCtx s prev, extCtx s α⟩)

/-! ## Artifact chain (`policy.go`)
  -- cite: attestation/policy/policy.go:2267-2703 sha256:cb53e3f3292a17600d2bf486d315b0306880c13b44ce7de4e4681c75e47793c0
-/

/-- Digest size in bytes for recognized algorithms (hashNames, `digestset.go`).
  -- cite: attestation/cryptoutil/digestset.go:47 sha256:d72c771e151f239196606ea3911048a3249181241f99e724d3631d544381cd72
-/
def algSize : String → Option Nat
  | "sha256" => some 32 | "gitoid:sha256" => some 32 | "dirHash" => some 32
  | "sha1" => some 20 | "gitoid:sha1" => some 20 | _ => none

def maxSize (a b : DigestSet) : Option Nat :=
  (a ++ b).foldl (fun m x => match algSize x.1, m with
    | some n, some k => some (max n k) | some n, none => some n | none, m => m) none

/-- DigestSet.Equal (`digestset.go`): the strongest recognized size class
    is shared and agrees, and no shared recognized algorithm disagrees.
    -- cite: attestation/cryptoutil/digestset.go:704-765 sha256:cc052e3f7c639ae035716c0fe89a492a8ac0d24bd5776d77664483784a8000d2
    -/
def dsEq (a b : DigestSet) : Bool :=
  match maxSize a b with
  | none => false
  | some m =>
    let strong := a.filter fun x => algSize x.1 == some m && (b.lookup x.1).isSome
    !strong.isEmpty && strong.all (fun x => b.lookup x.1 == some x.2) &&
    a.all fun x => (algSize x.1).isNone || (b.lookup x.1).all (· == x.2)

/-- Collection.Artifacts (`collection.go`): products override materials.
  -- cite: attestation/collection.go:243-265 sha256:5a1a8d36eaeaaaa9b87ff7eab61197813d9feaf97f192da5449860c19a895ab1
-/
def artifacts (c : Collection) : List (String × DigestSet) := c.products ++ c.materials

/-- compareArtifacts (`policy.go`): shared paths must be Equal; a
    material path the upstream never produced is SKIPPED; a non-empty material
    set needs at least one shared path.
    -- cite: attestation/policy/policy.go:2660-2703 sha256:8158138dbef9f186b5755cd96dd3b766480dac8752e26865c207a9f3c58029d0
    -/
def compareOk (mats arts : List (String × DigestSet)) : Bool :=
  let shared := mats.filter fun m => (arts.lookup m.1).isSome
  shared.all (fun m => (arts.lookup m.1).all (dsEq m.2 ·)) && (mats.isEmpty || !shared.isEmpty)

/-- One artifactsFrom edge from downstream `c` to upstream `u`
    (verifyCollectionArtifacts, `policy.go`).
    -- cite: attestation/policy/policy.go:2548-2655 sha256:d65fbdb53f7349c6755adf6504f172b536360aead7db4b3102821201d5b6fc67
    -/
def edgeOk (o : Options) (c u : Collection) : Bool :=
  c.leavesOk && u.leavesOk && (!c.materials.isEmpty || c.inlineMaterials) &&
  compareOk c.materials (artifacts u) &&
  (!o.requireAll || (artifacts u).all fun a => (c.materials.lookup a.1).isSome)

/-! ### The allowedUntracked glob

compileAllowedUntracked: gobwas decides which patterns are valid, and matching
is globToRegexp's RE2 translation with '/' as the separator (certglob.go). The
model follows the translator element by element:

* a run of two or more `*` is any run of characters; a lone `*` is any run
  without '/';
* `?` is one character other than '/';
* `\c` is `c` literally (a trailing `\` is nothing);
* `[…]` is one character in (or, with `[!…]`, not in) the listed characters,
  with `\` escapes, or in the range `lo-hi` when the class is exactly
  `lo-hi`; the separator does not apply to classes, so `[!a]` matches '/';
  `[]` admits no character and `[!]` any one;
* `{x,y,…}` is any one alternative, and alternatives nest; outside braces
  `,` and `}` are literal, and `]` is literal outside a class.

An alternation is expanded into its flat alternatives (RE2 `(?:x|y)z` is
`xz|yz`), so a pattern is a list of token strings and the matcher needs no
backtracking state. Which patterns gobwas refuses is not modelled: the
differential only asks about patterns the engine compiles.
    -- cite: attestation/policy/allowed_untracked.go:77-88 sha256:1d56ce0e5949e90ad2c4cbd0761134cea605e16fba16b5fae08ffeb490f31cf4
-/

inductive GlobTok where
  | lit (c : Char)
  | star
  | dstar
  | one
  | cls (neg : Bool) (items : List Char) (range : Option (Char × Char))
  deriving DecidableEq, Repr

def GlobTok.admits : GlobTok → Char → Bool
  | .cls neg items range, c =>
    let inSet := match range with
      | some (lo, hi) => decide (lo ≤ c) && decide (c ≤ hi)
      | none => items.contains c
    if neg then !inSet else inSet
  | _, _ => false

/-- globClass: the body of a class after its `[`, returning the class and
    what follows its `]`; `none` when it never closes. -/
def globClassItems : Nat → List Char → Option (List Char × List Char)
  | 0, _ => none
  | _ + 1, [] => none
  | _ + 1, ']' :: rest => some ([], rest)
  | _ + 1, ['\\'] => none
  | n + 1, '\\' :: c :: rest => (globClassItems n rest).map fun (xs, r) => (c :: xs, r)
  | n + 1, c :: rest => (globClassItems n rest).map fun (xs, r) => (c :: xs, r)

def globClass (cs : List Char) : Option (GlobTok × List Char) :=
  let (neg, body) := match cs with
    | '!' :: r => (true, r)
    | r => (false, r)
  match body with
  | lo :: '-' :: hi :: ']' :: rest => some (.cls neg [] (some (lo, hi)), rest)
  | _ :: '-' :: _ :: _ :: _ => none
  | _ => (globClassItems (body.length + 1) body).map fun (xs, r) => (.cls neg xs none, r)

def globProduct (xs ys : List (List GlobTok)) : List (List GlobTok) :=
  xs.flatMap fun a => ys.map (a ++ ·)

/-- A run of `*` after the first one: how many more, and what follows. -/
def globStars : List Char → Nat × List Char
  | '*' :: r => let (k, rest) := globStars r; (k + 1, rest)
  | r => (0, r)

mutual
/-- The flat expansions of a sequence, up to the end (depth 0) or to the `,`
    or `}` that ends it inside braces (not consumed). -/
def globSeq : Nat → Bool → List Char → Option (List (List GlobTok) × List Char)
  | 0, _, _ => none
  | _ + 1, inner, [] => if inner then none else some ([[]], [])
  | _ + 1, true, ',' :: r => some ([[]], ',' :: r)
  | _ + 1, true, '}' :: r => some ([[]], '}' :: r)
  | n + 1, inner, '{' :: r => do
    let (alts, r1) ← globAlts n r
    let (tails, r2) ← globSeq n inner r1
    pure (globProduct alts tails, r2)
  | n + 1, inner, '[' :: r => do
    let (t, r1) ← globClass r
    let (tails, r2) ← globSeq n inner r1
    pure (tails.map (t :: ·), r2)
  | n + 1, inner, '*' :: r =>
    let (k, r1) := globStars r
    let t := if k = 0 then GlobTok.star else GlobTok.dstar
    (globSeq n inner r1).map fun (tails, r2) => (tails.map (t :: ·), r2)
  | n + 1, inner, '?' :: r =>
    (globSeq n inner r).map fun (tails, r2) => (tails.map (.one :: ·), r2)
  | _ + 1, inner, ['\\'] => if inner then none else some ([[]], [])
  | n + 1, inner, '\\' :: c :: r =>
    (globSeq n inner r).map fun (tails, r2) => (tails.map (.lit c :: ·), r2)
  | n + 1, inner, c :: r =>
    (globSeq n inner r).map fun (tails, r2) => (tails.map (.lit c :: ·), r2)

/-- The alternatives of a brace group after its `{`, through its `}`. -/
def globAlts : Nat → List Char → Option (List (List GlobTok) × List Char)
  | 0, _ => none
  | n + 1, cs => do
    let (first, r) ← globSeq n true cs
    match r with
    | ',' :: r1 => do
      let (more, r2) ← globAlts n r1
      pure (first ++ more, r2)
    | '}' :: r1 => pure (first, r1)
    | _ => none
end

/-- The pattern's flat alternatives, or `none` where the translator refuses. -/
def globParse (g : String) : Option (List (List GlobTok)) :=
  (globSeq (3 * g.length + 3) false g.toList).map (·.1)

/-- One flat alternative against a path, '/' the separator. Structural on a
    fuel of token count + value length + 1, which every call decreases. -/
def globTokMatch : Nat → List GlobTok → List Char → Bool
  | 0, _, _ => false
  | _ + 1, [], s => s.isEmpty
  | n + 1, .dstar :: ts, [] => globTokMatch n ts []
  | n + 1, .dstar :: ts, c :: s => globTokMatch n ts (c :: s) || globTokMatch n (.dstar :: ts) s
  | n + 1, .star :: ts, [] => globTokMatch n ts []
  | n + 1, .star :: ts, c :: s => globTokMatch n ts (c :: s) || (c != '/' && globTokMatch n (.star :: ts) s)
  | _ + 1, _ :: _, [] => false
  | n + 1, .one :: ts, c :: s => c != '/' && globTokMatch n ts s
  | n + 1, .lit p :: ts, c :: s => p == c && globTokMatch n ts s
  | n + 1, t :: ts, c :: s => t.admits c && globTokMatch n ts s

/-- One allowedUntracked pattern against one path. -/
def sepGlob (g path : String) : Bool :=
  match globParse g with
  | some alts => alts.any fun ts => globTokMatch (ts.length + path.length + 1) ts path.toList
  | none => false

/-- allowedUntrackedMatcher.matches: an empty path never matches. Paths are
    taken as already clean (path.Clean is the identity on them). -/
def untrackedAllowed (s : Step) (path : String) : Bool :=
  path != "" && s.allowedUntracked.any fun g => sepGlob g path

/-- The paths the artifact pass counts as produced upstream: every artifact
    of every upstream collection that passed its edge, across all edges
    (`covered` in verifyCollectionArtifacts). -/
def coveredPath (o : Options) (st : State) (s : Step) (c : Collection) (path : String) : Bool :=
  s.artifactsFrom.any fun d => (st.get d).any fun u =>
    edgeOk o c u.payload && ((artifacts u.payload).lookup path).isSome

/-- checkAllowedUntracked (#9815): with EnforceAllowedUntracked on, in a step
    with artifactsFrom, every material is produced upstream or matches an
    allowedUntracked glob. Off, it only logs.
    -- cite: attestation/policy/allowed_untracked.go:112-162 sha256:487f6741ce50d210ef8494fa108c13d9d2e5aaf878635ba4c8cb8cc605e3eeaa
    -/
def untrackedOk (o : Options) (st : State) (s : Step) (c : Collection) : Bool :=
  !o.enforceUntracked || s.artifactsFrom.isEmpty ||
  c.materials.all fun m => coveredPath o st s c m.1 || untrackedAllowed s m.1

/-- A collection survives when every artifactsFrom edge has SOME surviving
    upstream partner, and no material is untracked (under enforcement). -/
def keep (o : Options) (st : State) (s : Step) (e : Envelope) : Bool :=
  (s.artifactsFrom.all fun d => (st.get d).any fun u => edgeOk o e.payload u.payload) &&
  untrackedOk o st s e.payload

def stepOf (p : Policy) (n : String) : Option Step := p.steps.find? (·.name == n)

/-- One pruning pass: every step filtered against the state at the start of
    the pass. (The Go pass updates in place in name order; both iterate to
    the same greatest fixed point. See README.) -/
def prunePass (p : Policy) (o : Options) (st : State) : State :=
  st.map fun x => (x.1, match stepOf p x.1 with
    | some s => x.2.filter (keep o st s)
    | none => x.2)

def size (st : State) : Nat := (st.map (·.2.length)).sum

/-- convergeArtifactPruning (`policy.go`): fuel = total passed + 1.
  -- cite: attestation/policy/policy.go:2357-2368 sha256:8f50b83a85041e230acea69e5bb2f10c068a469528ab0c58b97588a9b2fe2d7c
-/
def pruneLoop (p : Policy) (o : Options) : Nat → State → State
  | 0, st => st
  | n + 1, st =>
    let st' := prunePass p o st
    if size st' == size st then st else pruneLoop p o n st'

def prune (p : Policy) (o : Options) (st : State) : State := pruneLoop p o (size st + 1) st

/-! ## Externals (`policy.go`)
  -- cite: attestation/policy/policy.go:1772-2024 sha256:59499b38698ad9cdf93a34b51296d20fd48a29f2e42c7472ea2242ad9bd84bcc
-/

/-- An external candidate is bound when DSSE passes... the substitution guard
    and commit binding decide "unbound" (never counted). -/
def extBound (p : Policy) (o : Options) (e : Envelope) : Bool :=
  (verifiers p e).isEmpty ||
  (anchored o.seeds e.payload &&
    (o.commit.isNone || (e.payload.isCollection && commitOk o e.payload)))

def extPassed (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (x : External) : List Envelope :=
  E.filter fun e => e.payload.predicateType == x.predicateType && !(verifiers p e).isEmpty &&
    extBound p o e && (verifiers p e).any (fun v => x.functionaries.any fun f => fValidate h p.roots f v.cred) &&
    regoExt x.gate e.payload

def extCandidates (p : Policy) (o : Options) (E : List Envelope) (x : External) : List Envelope :=
  E.filter fun e => e.payload.predicateType == x.predicateType && extBound p o e

/-- Analyze plus the two error returns (`policy.go`): a required
    external needs a passed envelope; an optional one may be absent but not
    present-and-rejected.
    -- cite: attestation/policy/policy.go:1960-2001 sha256:48e5293f2cc102e1f9594652dfb2ae9ecdea6e7fdbe38e652c6aebe2cdc85bf9
    -/
def externalOk (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (x : External) : Bool :=
  !(extPassed regoExt h p o E x).isEmpty || (!x.required && (extCandidates p o E x).isEmpty)

/-- Every assignment of one passed candidate to each external a step reads
    (verifyStepsOverExternals, `external_assignments.go`). The 64
    assignment bound is not modelled.
    -- cite: attestation/policy/external_assignments.go:206-265 sha256:a8150d374f46dfba9fab4ba8980fc1bda40bff854f7efa7ddc7456d606913523
    -/
def assignments (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope) :
    List Assign :=
  let refd := p.externals.filter fun x => p.steps.any (·.externalFrom.contains x.name)
  refd.foldr (fun x acc =>
    match extPassed regoExt h p o E x with
    | [] => acc
    | ps => ps.flatMap fun e => acc.map ((x.name, e.payload) :: ·)) [[]]

/-! ## Static checks run before any search -/

/-- Policy.Validate (`policy.go`) plus the artifactsFrom existence check
    (`policy.go`), checkStepAbout (`decode.go`) and
    TimestampConstraint.Validate. attestationsFrom must point strictly
    EARLIER in the list, which is how the model states "acyclic, known, no
    self-reference" for a list given in topological order. Validate also
    refuses an artifactsFrom cycle now (#9860); that check is `unionAcyclic`,
    applied by `verifyShipped`, so `validate` alone is the pre-#9860 one.
    -- cite: attestation/policy/policy.go:491-579 sha256:808f541fabf44796016402e509198be4ddbd61ef82d8131cc27ab9dfc638b46e
    -- cite: attestation/policy/policy.go:952-958 sha256:255ab63a4966e38d992c6598f90df38f44e6ddd5c056271ba929d06bbf21c22a
    -- cite: attestation/policy/decode.go:152-173 sha256:b1bdf78ab77e9be7b918cf7657a02c7dd0cc6775385d65b517a3b176ca69daab
    -/
def validSteps : List String → List Step → Bool
  | _, [] => true
  | seen, s :: rest =>
    !seen.contains s.name && s.attestationsFrom.all seen.contains && validSteps (seen ++ [s.name]) rest

def tscValid : Option TsConstraint → Bool
  | none => true
  | some c => (c.notBefore.isSome || c.notAfter.isSome || c.maxAge.isSome) &&
      c.maxAge.all (· > 0) &&
      (match c.notBefore, c.notAfter with | some a, some b => decide (a ≤ b) | _, _ => true)

def validate (p : Policy) : Bool :=
  validSteps [] p.steps &&
  p.steps.all (fun s => s.artifactsFrom.all fun d => p.steps.any (·.name == d)) &&
  p.steps.all (fun s => s.externalFrom.all fun n => p.externals.any (·.name == n)) &&
  p.steps.all (fun s => s.about == "" || (s.about == "source" && p.v02)) &&
  p.steps.all (fun s => tscValid s.tsc)

/-- The preconditions of VerifyWithExternals before evidence: not expired
    (`policy.go`; expired means now > expires + skew), options valid
    (seeds non-empty, `policy.go`), and validation.
    -- cite: attestation/policy/policy.go:681-683 sha256:7759d749f16c04962d08059b1d7e97ad861c39ce2af3c99b30e54e280139a8a3
    -- cite: attestation/policy/policy.go:368-373 sha256:92beb6ed459be28b5782a45c9587f7216676b6c4884e7f4e05555babd9e06e63
    -/
def admissible (p : Policy) (o : Options) : Bool :=
  decide (o.now ≤ p.expires + o.skew) && !o.seeds.isEmpty && validate p

/-- Verdict over final step results (`policy.go`): every step has a
    surviving collection, every external passes, and SOMETHING was verified.
    -- cite: attestation/policy/policy.go:740-759 sha256:693fa1ad33c7238fb5ebc6a4cd223d39c6f35f4fadab72b083a34c3a52778283
    -/
def verdictOn (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (F : State) : Bool :=
  p.steps.all (fun s => !(F.get s.name).isEmpty) &&
  p.externals.all (externalOk regoExt h p o E) &&
  (!p.steps.isEmpty || p.externals.any fun x => !(extPassed regoExt h p o E x).isEmpty)

/-- AS-BUILT verify: some assignment's step phase, pruned, passes. -/
def verifyAsBuilt (rego : Rego) (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options)
    (E : List Envelope) : Bool :=
  admissible p o &&
  (assignments regoExt h p o E).any fun α =>
    verdictOn regoExt h p o E (prune p o (phaseAsBuilt rego h p o E α))

/-- The joint fixed-point iteration: re-gate from the survivors, prune, stop
    when the survivors repeat. Out of fuel is a failure (`none`). -/
def fixLoop (rego : Rego) (h : Hardening) (p : Policy) (o : Options) (E : List Envelope)
    (α : Assign) : Nat → State → Option State
  | 0, _ => none
  | n + 1, prev =>
    let F := prune p o (phaseFrom rego h p o E α prev)
    if F == prev then some F else fixLoop rego h p o E α n F

/-- FIXED verify (the proposed testifysec/judge#9813 semantics): start from an empty Rego
    context, then re-gate and prune until the survivors repeat. The verdict is
    taken on that joint fixed point, so every Rego
    context was read from collections that themselves survived. -/
def verifyFixed (rego : Rego) (regoExt : RegoExt) (h : Hardening) (p : Policy) (o : Options)
    (E : List Envelope) : Bool :=
  admissible p o &&
  (assignments regoExt h p o E).any fun α =>
    match fixLoop rego h p o E α o.fixFuel (prune p o (phaseFrom rego h p o E α [])) with
    | some F => verdictOn regoExt h p o E F
    | none => false

end CilockPolicy
