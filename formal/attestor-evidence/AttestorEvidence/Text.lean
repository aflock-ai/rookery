/-
  AttestorEvidence.Text: the string helpers every module shares. Text is a
  `List Char` (Unicode scalar values) so every predicate is decidable and every
  vector is checked by `decide`.

  Go measures strings in bytes. Wherever the Go compares a LENGTH, the model
  compares `utf8Len`, the UTF-8 encoded size, never `List.length`: a value of
  four `é` is eight bytes to `len()` and four characters to `length`.
  Prefix, containment and splitting on ASCII separators agree between the two
  views for valid UTF-8, which is self-synchronising. Invalid UTF-8 (an
  environment value may hold any bytes) is outside the model; the Go tests
  cover it.
-/
namespace AttestorEvidence

abbrev Text := List Char

/-- Bytes in the UTF-8 encoding of one scalar value. -/
def utf8Width (c : Char) : Nat :=
  if c.toNat < 0x80 then 1 else if c.toNat < 0x800 then 2
  else if c.toNat < 0x10000 then 3 else 4

/-- `len(s)` in Go: the UTF-8 encoded size in bytes. -/
def utf8Len (s : Text) : Nat := (s.map utf8Width).sum

/-- `strings.CutPrefix`: the rest of `s` after `p`, when `s` starts with `p`. -/
def cutPrefix (p s : Text) : Option Text :=
  if p.isPrefixOf s then some (s.drop p.length) else none

/-- `strings.Contains(hay, needle)`. -/
def contains (needle : Text) : Text → Bool
  | [] => needle.isEmpty
  | h@(_ :: t) => needle.isPrefixOf h || contains needle t

theorem cutPrefix_some {p s r : Text} (h : cutPrefix p s = some r) : s = p ++ r := by
  unfold cutPrefix at h
  split at h
  · rename_i hp
    cases h
    obtain ⟨t, ht⟩ := List.isPrefixOf_iff_prefix.mp hp
    subst ht
    simp
  · cases h

theorem contains_append_left (needle pre post : Text) :
    contains needle (pre ++ needle ++ post) = true := by
  induction pre with
  | nil =>
    cases needle with
    | nil => cases post <;> simp [contains]
    | cons c cs =>
      simp [contains, List.isPrefixOf_iff_prefix]
  | cons c cs ih =>
    simp only [List.cons_append, contains]
    rw [List.append_assoc] at ih
    simp [ih]

end AttestorEvidence
