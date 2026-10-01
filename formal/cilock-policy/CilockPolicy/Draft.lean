/-
  CilockPolicy.Draft: what `cilock policy validate` accepts in an authoring
  draft, beyond the verifier this package otherwise models.

  None of this is `cilock verify`. The validator in cilock/internal/policy is
  reached only from `cilock policy validate` and `cilock policy prove`; the
  platform's release path runs its own validator and then the verifier the
  rest of this package models. What is modelled here is the authoring
  linter's verdict, so a draft an agent is told is fine is fine by the rule
  written down, and the Go is held to that rule by a differential test
  (cilock/internal/policy/formal_draft_diff_test.go).

  A JSON value is `JV`. An object is its members in key order with each key
  once, which is what encoding/json's decode into a map followed by
  sort.Strings presents to the walk: the oracle builds a `JV` from Lean's
  own parser, whose objects are key-ordered maps. A document that names a
  key twice in one object is refused before the walk
  (canonicaljson.RejectDuplicateKeys), because encoding/json's typed decode
  merges a repeated map member while its untyped decode keeps the last, so
  the walk could miss a slot the policy still holds. Every document the walk
  sees is therefore a `JV`.
-/
namespace CilockPolicy.Draft

inductive JV where
  | null
  | bool (b : Bool)
  /-- A number, and whether its literal is a plain integer (no fraction or
      exponent). Only integers in range decode into a Go integer type. -/
  | num (n : Int) (integral : Bool)
  | str (s : String)
  | arr (xs : List JV)
  | obj (kvs : List (String × JV))
  deriving Repr, Inhabited

/-! ## Fill slots

  A template draft marks every place only the author can judge with a string
  that starts with `__FILL__`. The validator walks the whole decoded document
  and reports each such string by JSON path; any report fails the draft.
  -- cite: cilock/internal/policy/validate.go:205 sha256:7bb4cfebebf6fc6a7904ab8d0b2ca9f2b93e672e9ab8e127c4469627d672f377
  -- cite: cilock/internal/policy/validate.go:211-259 sha256:cb913295bffc34af49cc2a4f6b6074630c5e51c50b6c9f226a14d79e4b10b5be
-/

def fillMarker : String := "__FILL__"

def isSlot (s : String) : Bool := s.startsWith fillMarker

def childKey (p k : String) : String := if p == "" then k else p ++ "." ++ k

def childIdx (p : String) (i : Nat) : String := p ++ "[" ++ toString i ++ "]"

mutual
/-- The paths of every unfilled slot under `p`, in the walk's order: object
    members in key order, array elements in index order. -/
def slots : String → JV → List String
  | p, .str s => if isSlot s then [p] else []
  | p, .arr xs => slotsArr p 0 xs
  | p, .obj kvs => slotsObj p kvs
  | _, _ => []

def slotsArr : String → Nat → List JV → List String
  | _, _, [] => []
  | p, i, x :: xs => slots (childIdx p i) x ++ slotsArr p (i + 1) xs

def slotsObj : String → List (String × JV) → List String
  | _, [] => []
  | p, (k, v) :: kvs => slots (childKey p k) v ++ slotsObj p kvs
end

/-- The fill-slot half of the validator's verdict: no slot anywhere. -/
def slotFree (doc : JV) : Bool := (slots "" doc).isEmpty

/-- A slot is reported wherever it sits: one slot in any member of an
    object fails the whole draft. -/
theorem slot_member_reported (p : String) (kvs : List (String × JV)) (k : String) (v : JV)
    (hmem : (k, v) ∈ kvs) (h : slots (childKey p k) v ≠ []) : slotsObj p kvs ≠ [] := by
  induction kvs with
  | nil => cases hmem
  | cons hd tl ih =>
    obtain ⟨k', v'⟩ := hd
    simp only [slotsObj]
    cases hmem with
    | head => simp [h]
    | tail _ hin =>
      intro hnil
      exact ih hin (List.append_eq_nil_iff.mp hnil).2

/-- The same for arrays: a slot in any element fails the draft. -/
theorem slot_element_reported (p : String) (xs : List JV) (i : Nat) (x : JV)
    (hmem : x ∈ xs) (h : ∀ j, slots (childIdx p j) x ≠ []) : slotsArr p i xs ≠ [] := by
  induction xs generalizing i with
  | nil => cases hmem
  | cons hd tl ih =>
    simp only [slotsArr]
    cases hmem with
    | head => simp [h]
    | tail _ hin =>
      intro hnil
      exact ih (i + 1) hin (List.append_eq_nil_iff.mp hnil).2

/-- Only a string can be a slot, and a string is one exactly when it opens
    with the marker. -/
theorem slot_string_iff (p s : String) : slots p (.str s) ≠ [] ↔ isSlot s = true := by
  simp only [slots]
  cases isSlot s <;> simp

-- A trace, checked by the evaluator at build time: a slot nested in an array
-- in an unknown member is still named, by its full path.
#guard slots "" (.obj [("steps", .obj [("build", .obj [("functionaries",
    .arr [.obj [("publickeyid", .str "__FILL__ key")]])])]),
    ("x", .arr [.null, .str "__FILL__"])]) =
    ["steps.build.functionaries[0].publickeyid", "x[1]"]

end CilockPolicy.Draft
