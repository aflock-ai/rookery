/-
  AttestorEvidence.ScriptCapture: what cilock-action records about the command
  it wraps (#10139, docs/design/cilock-action-script-capture.md), and what may
  never reach the attestation.

  1. Execution is never changed by recording. The action always runs
     `sh -c <text>` (cilock-action cmd/cilock-action/main.go), whatever the
     capture mode. Rounds 1-3 of #10139 each found a way a direct exec differed
     from `sh -c` (builtins, ENOEXEC, an empty `#!`, a PATH-resolved probe);
     the fix removed the direct exec, and `exec_is_sh_c` pins that.

  2. Reading the text (commandrun `shCommandWords`, script_operands.go). The
     text is read as words only for argv exactly `[sh, -c, text]` (argv0's
     basename is `sh`), when the text holds no byte of `shSyntax`, the
     environment defines no shell function, and the first word is not an
     assignment. Otherwise nothing is read, so nothing is recorded: abstaining
     is always the safe direction. Words are split on space and tab only.

  3. The secret guard (cilock-action internal/scriptguard/guard.go) runs over
     every body commandrun is about to embed, after capture and before the
     command runs, and refuses the step when the body matches a credential
     shape or contains the value (8 bytes or more) of an environment variable
     whose name is sensitive. Shapes and names are abstract predicates here;
     their tables are the Go code's, and its tests pin them.
-/
import AttestorEvidence.Text

namespace AttestorEvidence.Script

open AttestorEvidence

/-! ### 1. Execution -/

inductive Capture where
  | off | identity | content
  deriving DecidableEq, Repr

/-- The argv the action executes for `command:` text. -/
def execArgv (_mode : Capture) (text : Text) : List Text :=
  ["sh".toList, "-c".toList, text]

theorem exec_is_sh_c (m : Capture) (text : Text) :
    execArgv m text = ["sh".toList, "-c".toList, text] := rfl

theorem capture_mode_never_changes_exec (m₁ m₂ : Capture) (text : Text) :
    execArgv m₁ text = execArgv m₂ text := rfl

/-! ### 2. Reading `sh -c` text -/

def shSyntax : Text := "|&;<>()$`~{}*?[]'\"\\#\n".toList

def isBlank (c : Char) : Bool := c = ' ' || c = '\t'

/-- Split on runs of blanks, dropping empty words (`strings.FieldsFunc`). -/
def fields (s : Text) : List Text :=
  (s.splitOnP isBlank).filter (fun w => !w.isEmpty)

def basename (p : Text) : Text :=
  (p.splitOn '/').getLast?.getD p

/-- `shCommandWords`: `some words` when the text is read, `none` to abstain. -/
def shWords (envDefinesFunctions : Bool) : List Text → Option (List Text)
  | [a0, flag, text] =>
    if basename a0 = "sh".toList ∧ flag = "-c".toList ∧
        text.all (fun c => !shSyntax.contains c) = true ∧ envDefinesFunctions = false then
      match fields text with
      | w :: ws => if w.contains '=' then none else some (w :: ws)
      | [] => none
    else none
  | _ => none

/-- Whatever is read came from plain `sh -c` text free of shell syntax, in an
    environment with no functions, and does not start with an assignment. -/
theorem read_only_plain_sh {env : Bool} {argv : List Text} {ws : List Text}
    (h : shWords env argv = some ws) :
    ∃ a0 text, argv = [a0, "-c".toList, text] ∧ basename a0 = "sh".toList ∧
      text.all (fun c => !shSyntax.contains c) = true ∧ env = false ∧
      ws = fields text ∧ ∃ w rest, ws = w :: rest ∧ w.contains '=' = false := by
  match argv, h with
  | [a0, flag, text], h =>
    simp only [shWords] at h
    split at h
    · rename_i hc
      obtain ⟨hb, hf, hs, he⟩ := hc
      split at h
      · rename_i w rest hfw
        split at h
        · cases h
        · rename_i hw
          cases h
          subst hf
          exact ⟨a0, text, rfl, hb, hs, he, hfw.symm, w, rest, rfl, by simpa using hw⟩
      · cases h
    · cases h

/-- A function in the environment could replace any command sh looks up
    (`BASH_FUNC_bash%%` does, under macOS /bin/sh), so nothing is read. -/
theorem functions_abstain (argv : List Text) : shWords true argv = none := by
  unfold shWords
  split
  · simp
  · rfl

/-! ### 3. The guard -/

structure EnvVar where
  name : Text
  value : Text

def minSensitiveValueLen : Nat := 8

def envRefuses (sensitive : Text → Bool) (body : Text) (e : EnvVar) : Bool :=
  decide (minSensitiveValueLen ≤ utf8Len e.value) && sensitive e.name && contains e.value body

/-- `Check`: refuse on a credential shape, then on a sensitive value. -/
def refuses (shape sensitive : Text → Bool) (env : List EnvVar) (body : Text) : Bool :=
  shape body || env.any (envRefuses sensitive body)

/-- No body that carries a sensitive value of 8 bytes or more is embedded.
    Bytes, as Go's `len(value)` counts them: four `é` is eight. -/
theorem sensitive_value_refused (shape sensitive : Text → Bool) (env : List EnvVar)
    (e : EnvVar) (he : e ∈ env) (hs : sensitive e.name = true)
    (hl : minSensitiveValueLen ≤ utf8Len e.value) (pre post : Text) :
    refuses shape sensitive env (pre ++ e.value ++ post) = true := by
  simp only [refuses, Bool.or_eq_true, List.any_eq_true]
  right
  have hc := contains_append_left e.value pre post
  rw [List.append_assoc] at hc
  exact ⟨e, he, by simp [envRefuses, hs, hl, hc]⟩

theorem shape_refused (shape sensitive : Text → Bool) (env : List EnvVar) (body : Text)
    (h : shape body = true) : refuses shape sensitive env body = true := by
  simp [refuses, h]

/-- A body passes only when no shape matched and no sensitive value of 8 bytes
    or more occurs in it. -/
theorem passes_iff (shape sensitive : Text → Bool) (env : List EnvVar) (body : Text) :
    refuses shape sensitive env body = false ↔
      shape body = false ∧ ∀ e ∈ env, envRefuses sensitive body e = false := by
  simp [refuses]

end AttestorEvidence.Script
