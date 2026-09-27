/-
  `lake exe attestor-evidence-eval`: print every vector row as one JSON line,
  with the model's own answer, for the Go differential tests to replay.
  Each line: {"slice": "...", "in": [...], "out": ...}. `out` is null when
  the model abstains or refuses.
-/
import AttestorEvidence

open AttestorEvidence

def q (s : String) : String :=
  "\"" ++ (s.replace "\\" "\\\\" |>.replace "\"" "\\\"" |>.replace "\n" "\\n" |>.replace "\t" "\\t") ++ "\""

def arr (xs : List String) : String := "[" ++ ", ".intercalate (xs.map q) ++ "]"

def optS : Option Text → String
  | some b => q (String.ofList b)
  | none => "null"

def optB : Option Bool → String
  | some true => "true"
  | some false => "false"
  | none => "null"

def xattrName : Program.Xattr → String
  | .present => "present" | .enodata => "enodata"
  | .eopnotsupp => "eopnotsupp" | .otherErr => "error"

def main : IO Unit := do
  for (ty, v, _) in Vectors.sbomRows do
    IO.println s!"\{\"slice\": \"sbom\", \"in\": {arr [ty, v]}, \"out\": {optS (Sbom.imageBackref none ty v.toList)}}"
  for (dir, p, _) in Vectors.programRows do
    IO.println s!"\{\"slice\": \"windows-exe-path\", \"in\": {arr [dir, p]}, \"out\": {optS (Vectors.resolvedAs (Program.joinExe Vectors.driveCwd dir.toList p.toList))}}"
  for (m, f, x, _) in Vectors.setIdRows do
    IO.println s!"\{\"slice\": \"setid\", \"in\": [{m}, {f}, {q (xattrName x)}], \"out\": {optB (Program.setIdOf m f x)}}"
  for (argv, fns, _) in Vectors.shRows do
    let out := match Script.shWords fns (argv.map String.toList) with
      | some ws => arr (ws.map String.ofList)
      | none => "null"
    IO.println s!"\{\"slice\": \"sh-c-words\", \"in\": [{arr argv}, {fns}], \"out\": {out}}"
  -- The guard rows carry their environment; the Go test replays them against
  -- the real name list and shapes, which agree with the model's on these rows.
  let env := Vectors.guardEnv.map fun e => String.ofList e.name ++ "=" ++ String.ofList e.value
  for (body, _) in Vectors.guardRows do
    let refused := Script.refuses Vectors.ghShape Vectors.sensitiveName Vectors.guardEnv body.toList
    IO.println s!"\{\"slice\": \"script-guard\", \"in\": [{arr env}, {q body}], \"out\": {refused}}"
