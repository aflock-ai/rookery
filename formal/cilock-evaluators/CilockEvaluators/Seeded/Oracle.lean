/-
  CilockEvaluators.Seeded.Oracle: the `seeded` case kind of the oracle.

  Input: `{"kind":"seeded","rule":<id>,"param":<fill value>,"predicate":<json>,
  "steps":<json, optional>}`. Output: `admit` or `deny`, computed by
  `Seeded.admits`. Decoding is the only logic here; a fractional number is a
  decode error rather than a rounded integer.
-/
import Lean.Data.Json
import CilockEvaluators.Seeded.Rules

namespace CilockEvaluators.Seeded.Oracle

open Lean (Json)

partial def toJ : Json → Except String J
  | .null => pure .null
  | .bool b => pure (.bool b)
  | .num n => if n.exponent == 0 then pure (.num n.mantissa) else throw s!"non-integer number {n}"
  | .str s => pure (.str s)
  | .arr xs => do return .arr (← xs.toList.mapM toJ)
  | .obj kvs => do return .obj (← kvs.toList.mapM (fun (k, v) => do return (k, ← toJ v)))

def seededCase (j : Json) : Except String String := do
  let rule ← (← j.getObjVal? "rule").getStr?
  let param ← match j.getObjVal? "param" with
    | .ok v => toJ v
    | .error _ => pure J.null
  let pred ← toJ (← j.getObjVal? "predicate")
  let steps ← match j.getObjVal? "steps" with
    | .ok .null => pure none
    | .ok v => some <$> toJ v
    | .error _ => pure none
  match admits rule param pred steps with
  | some true => pure "admit"
  | some false => pure "deny"
  | none => throw s!"unknown rule {rule}"

end CilockEvaluators.Seeded.Oracle
