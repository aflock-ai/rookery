/-
  `lake exe cilock-policy-eval`: the model as a program, for differential
  testing against the Go engine (attestation/policy/formal_diff_test.go).

  Reads a JSON array of cases on stdin and prints one verdict per line:
  `true` / `false` (see `main` for the semantics flags), or `error: <msg>` for a case it cannot
  decode. The Rego catalog is fixed and mirrored in the Go test:
    gate 0  no module (always passes)
    gate 1  passes iff some input.steps dependency collection carries an
            attestor of type `https://example.com/marker/v1`
    gate 2  denies an attestor whose name is `b1` (body 1)
-/
import Lean.Data.Json
import CilockPolicy.Verify
import CilockPolicy.Trust
import CilockPolicy.Bound9813
import CilockPolicy.Draft

open Lean CilockPolicy

def markerType : String := "https://example.com/marker/v1"

def diffRego : Rego := fun g a ctx =>
  match g with
  | 0 => true
  | 1 => ctx.steps.any fun d => d.2.any fun c => c.attestors.any (·.type == markerType)
  | 2 => a.body != 1
  | _ => false

def field (j : Json) (k : String) : Except String Json := j.getObjVal? k

def arr (j : Json) (k : String) : Except String (Array Json) := do (← field j k).getArr?

def strs (j : Json) (k : String) : Except String (List String) := do
  (← arr j k).toList.mapM (·.getStr?)

def natD (j : Json) (k : String) (d : Nat) : Nat := ((field j k >>= (·.getNat?)).toOption).getD d

def boolD (j : Json) (k : String) (d : Bool) : Bool := ((field j k >>= (·.getBool?)).toOption).getD d

def digestSet (j : Json) : Except String DigestSet := do
  j.getArr? >>= fun a => a.toList.mapM fun p => do
    let xs ← p.getArr?
    pure (← (xs[0]!).getStr?, ← (xs[1]!).getStr?)

def pathSets (j : Json) (k : String) : Except String (List (String × DigestSet)) := do
  (← arr j k).toList.mapM fun p => do
    let xs ← p.getArr?
    pure (← (xs[0]!).getStr?, ← digestSet xs[1]!)

def decodeStep (j : Json) : Except String Step := do
  let fs ← (← arr j "functionaries").toList.mapM fun f => do
    pure ({ type := "publickey", keyId := ← (← field f "keyId").getStr? } : Functionary)
  let atts ← (← arr j "atts").toList.mapM fun a => do
    pure (⟨← (← field a "type").getStr?, ← (← field a "gate").getNat?⟩ : AttReq)
  let tsc : Option TsConstraint :=
    match field j "maxAge" >>= (·.getNat?) with
    | .ok m => some { maxAge := some m }
    | .error _ => none
  pure { name := ← (← field j "name").getStr?, functionaries := fs, atts := atts,
         artifactsFrom := ← strs j "artifactsFrom", attestationsFrom := ← strs j "attestationsFrom", tsc := tsc,
         allowedUntracked := (strs j "allowedUntracked").toOption.getD [] }

def decodeEnvelope (j : Json) : Except String Envelope := do
  let subjects ← (← arr j "subjects").toList.mapM fun s => do
    pure (⟨← (← field s "name").getStr?, ⟨← (← field s "alg").getStr?, ← (← field s "value").getStr?⟩⟩ : Subject)
  let attestors ← (← arr j "attestors").toList.mapM fun a => do
    pure (⟨← (← field a "type").getStr?, ← (← field a "body").getNat?, none⟩ : Attestor)
  let sigs ← (← arr j "sigs").toList.mapM fun s => do
    pure (⟨.key (← (← field s "key").getStr?), ← (← field s "ok").getBool?, []⟩ : Sig)
  let c : Collection :=
    { name := ← (← field j "name").getStr?, isCollection := true,
      predicateType := "https://aflock.ai/attestation-collection/v0.1", subjects := subjects,
      hardenedGit := boolD j "hardenedGit" false, attestors := attestors, materials := ← pathSets j "materials",
      products := ← pathSets j "products", leavesOk := true, inlineMaterials := boolD j "inline" false,
      backRefs := [] }
  pure ⟨← (← field j "ref").getStr?, c, sigs⟩

def decodeCase (j : Json) : Except String (Hardening × Policy × CilockPolicy.Options × List Envelope) := do
  let pj ← field j "policy"
  let oj ← field j "options"
  let p : Policy :=
    { expires := natD pj "expires" 0, roots := [], tsas := [], keys := ← strs pj "keys",
      steps := ← (← arr pj "steps").toList.mapM decodeStep }
  let warn := (field j "hardening" >>= (·.getStr?)).toOption == some "warn"
  let o : CilockPolicy.Options :=
    { now := natD oj "now" 0, seeds := ← strs oj "seeds", maxFanout := natD oj "maxFanout" 0,
      requireAll := boolD oj "requireAll" false, enforceUntracked := !warn }
  let h := if warn then Hardening.warn
    else Hardening.enforce
  pure (h, p, o, ← (← arr j "evidence").toList.mapM decodeEnvelope)

/-- `--glob`: one matcher question per case, `{"kind", "pattern", "value"}`.
    `cert` is certGlob (Trust.lean, the cert-constraint matcher after #9867,
    no case folding); `untracked` is untrackedAllowed (Verify.lean, the
    allowedUntracked matcher of #9862). -/
def decodeGlob (j : Json) : Except String (String × String × String) := do
  let k ← (← field j "kind").getStr?
  let p ← (← field j "pattern").getStr?
  let v ← (← field j "value").getStr?
  pure (k, p, v)

def globCase (j : Json) : String :=
  match decodeGlob j with
  | .ok ("cert", p, v) => toString (certGlob p.toList v.toList)
  | .ok ("untracked", p, v) =>
    let s : Step := { name := "", functionaries := [], atts := [], allowedUntracked := [p] }
    toString (untrackedAllowed s v)
  | .ok (k, _, _) => s!"error: unknown kind {k}"
  | .error e => s!"error: {e}"

/-- A parsed JSON value as the Draft model's `JV`. Lean's parser keeps an
    object as a key-ordered map, the order the Go walk visits. A repeated key
    never reaches either walk: the Go validator refuses the document first
    (validateFillSlots), so what Lean's parser would do with one is moot. -/
partial def toJV : Json → Draft.JV
  | .null => .null
  | .bool b => .bool b
  | .num n => .num n.mantissa (n.exponent == 0)
  | .str s => .str s
  | .arr xs => .arr (xs.toList.map toJV)
  | .obj kvs => .obj (kvs.toList.map fun (k, v) => (k, toJV v))

/-- `--draft-slots`: each case is a policy document; prints the JSON array of
    the unfilled-slot paths the validator reports, in its order. -/
def draftSlotsCase (j : Json) : String :=
  (Json.arr ((Draft.slots "" (toJV j)).toArray.map Json.str)).compress

/-- `--assurance`: `{"min", "acr": [values]}`, answered by `meetsMin`
    (Trust.lean, CertConstraint.MinAssuranceLevel). -/
def assuranceCase (j : Json) : String :=
  match (do pure (← (← field j "min").getStr?, ← strs j "acr") : Except String (String × List String)) with
  | .ok (m, acr) => toString (meetsMin m acr)
  | .error e => s!"error: {e}"

/-- With no flag, the pre-#9813 as-built semantics. `--fix9813` evaluates the
    engine as #9860 shipped it (`verifyShipped`: the union-acyclicity
    validator, then the round-bounded fix); `--fixed`
    evaluates the unbounded joint fixed point (`verifyFixed`). -/
def main (args : List String) : IO Unit := do
  let fixed := args.contains "--fixed"
  let fix9813 := args.contains "--fix9813"
  let input ← (← IO.getStdin).readToEnd
  match Json.parse input >>= (·.getArr?) with
  | .error e => IO.println s!"error: {e}"
  | .ok cases =>
    if args.contains "--glob" then
      for c in cases do IO.println (globCase c)
      return
    if args.contains "--draft-slots" then
      for c in cases do IO.println (draftSlotsCase c)
      return
    if args.contains "--assurance" then
      for c in cases do IO.println (assuranceCase c)
      return
    for c in cases do
      match decodeCase c with
      | .error e => IO.println s!"error: {e}"
      | .ok (h, p, o, E) =>
        let v := if fix9813 then verifyShipped diffRego (fun _ _ => true) h p o E
          else if fixed then verifyFixed diffRego (fun _ _ => true) h p o E
          else verifyAsBuilt diffRego (fun _ _ => true) h p o E
        IO.println (toString v)
