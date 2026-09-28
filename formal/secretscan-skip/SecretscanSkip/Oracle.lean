/-
  SecretscanSkip.Oracle: the model as an executable, for differential testing
  against the Go skip (plugins/attestors/secretscan, the
  `formal:differential secretscan-skip` test).

  Input: JSON Lines on stdin, one case per line, `{"facts": {...}}` with every
  `Facts` field as a boolean. Output: one line per case, `skip` or `scan`
  (computed by `skip`, never re-implemented here), or `decode-error: ...`.
  A case whose facts violate `WellFormed` answers `ill-formed`: the driver
  only builds real file systems, so that line is itself a mismatch.
-/
import Lean.Data.Json
import SecretscanSkip.Model

namespace SecretscanSkip.Oracle

open Lean (Json)

abbrev D := Except String

def bool (j : Json) (k : String) : D Bool := do (← j.getObjVal? k).getBool?

/-- A fact added after the first driver: absent means false. -/
def optBool (j : Json) (k : String) : D Bool :=
  match j.getObjVal? k with
  | .error _ => pure false
  | .ok v => v.getBool?

def decodeFacts (j : Json) : D Facts := do
  return {
    inside := ← bool j "inside", gitReady := ← bool j "gitReady",
    parentSymlink := ← bool j "parentSymlink", finalSymlink := ← bool j "finalSymlink",
    resolves := ← bool j "resolves", tracked := ← bool j "tracked",
    spelledTracked := ← bool j "spelledTracked", isStream := ← bool j "isStream",
    envelope := ← bool j "envelope", residualDirty := ← bool j "residualDirty",
    underGitlink := ← optBool j "underGitlink", recordedProduct := ← optBool j "recordedProduct",
    treeScope := ← optBool j "treeScope", nestedRepo := ← optBool j "nestedRepo" }

/-- `WellFormed` as a boolean, for the check above. -/
def wellFormedB (f : Facts) : Bool :=
  f.parentSymlink || f.finalSymlink || f.underGitlink || f.nestedRepo ||
    f.spelledTracked == f.tracked

def runCase (line : String) : String :=
  match Json.parse line with
  | .error e => s!"decode-error: {e}"
  | .ok j =>
    match (do decodeFacts (← j.getObjVal? "facts") : D Facts) with
    | .error e => s!"decode-error: {e}"
    | .ok f => if !wellFormedB f then "ill-formed" else if skip f then "skip" else "scan"

end SecretscanSkip.Oracle
