/-
  DsseIntoto.Pae: the DSSE Pre-Authentication Encoding.

  Spec: DSSE protocol v1.0.2 (secure-systems-lab/dsse, protocol.md, May 10 2024).
  As built: attestation/dsse/dsse.go `preauthEncode`, which both `Sign` and
  `Verify` call.

  Results:
  * `lenEnc_isLen`       the length field meets the spec's LEN() exactly
  * `pae_injective`      no two (type, body) pairs share PAE bytes
  * `preauthEncode_eq`   the Go encoder is the spec's PAE, for every input

  Bytes are naturals. Nothing here depends on the 0..255 bound, so the results
  hold for byte strings a fortiori.
-/
namespace DsseIntoto

abbrev Bytes := List Nat

-- spec: DSSE protocol §Signature Definition: SP = ASCII space [0x20]
def SP : Nat := 0x20

-- spec: DSSE protocol §Signature Definition: "DSSEv1" = ASCII [0x44, 0x53, 0x53, 0x45, 0x76, 0x31]
def dsseV1 : Bytes := [0x44, 0x53, 0x53, 0x45, 0x76, 0x31]

def isDigit (c : Nat) : Bool := 48 ≤ c && c < 58

/-- The value of an ASCII decimal numeral. -/
def decVal (l : Bytes) : Nat := l.foldl (fun a c => a * 10 + (c - 48)) 0

/-- `l` is LEN(s) for a string of `n` bytes. -/
-- spec: DSSE protocol §Signature Definition: LEN(s) = ASCII decimal encoding of the byte length of s, with no leading zeros
def IsLen (l : Bytes) (n : Nat) : Prop :=
  l ≠ [] ∧ (∀ c ∈ l, isDigit c = true) ∧ (l.head? = some 48 → l = [48]) ∧ decVal l = n

/-- The decimal numeral of `n`, most significant digit first. -/
def lenEnc (n : Nat) : Bytes :=
  if n < 10 then [48 + n] else lenEnc (n / 10) ++ [48 + n % 10]
termination_by n
decreasing_by omega

/-- PAE(type, body). -/
-- spec: DSSE protocol §Signature Definition: PAE(type, body) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(body) + SP + body
def pae (ty body : Bytes) : Bytes :=
  dsseV1 ++ SP :: (lenEnc ty.length ++ SP :: (ty ++ SP :: (lenEnc body.length ++ SP :: body)))

/-! ### LEN -/

theorem lenEnc_lt (n : Nat) (h : n < 10) : lenEnc n = [48 + n] := by
  rw [lenEnc]; simp [h]

theorem lenEnc_ge (n : Nat) (h : ¬ n < 10) : lenEnc n = lenEnc (n / 10) ++ [48 + n % 10] := by
  rw [lenEnc]; simp [h]

theorem lenEnc_ne_nil (n : Nat) : lenEnc n ≠ [] := by
  by_cases h : n < 10
  · rw [lenEnc_lt n h]; simp
  · rw [lenEnc_ge n h]; simp

theorem lenEnc_digits : ∀ n, ∀ c ∈ lenEnc n, isDigit c = true := by
  intro n
  induction n using Nat.strongRecOn with
  | _ n ih =>
    intro c hc
    by_cases h : n < 10
    · rw [lenEnc_lt n h] at hc
      simp at hc; subst hc; simp [isDigit]; omega
    · rw [lenEnc_ge n h] at hc
      simp at hc
      cases hc with
      | inl hc => exact ih (n / 10) (by omega) c hc
      | inr hc => subst hc; simp [isDigit]; omega

theorem lenEnc_head (n : Nat) (hn : 1 ≤ n) : (lenEnc n).head? ≠ some 48 := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    by_cases h : n < 10
    · rw [lenEnc_lt n h]; simp; omega
    · rw [lenEnc_ge n h]
      have hne := lenEnc_ne_nil (n / 10)
      cases hl : lenEnc (n / 10) with
      | nil => exact absurd hl hne
      | cons x xs =>
        have := ih (n / 10) (by omega) (by omega)
        rw [hl] at this
        simpa using this

theorem decVal_append_digit (l : Bytes) (c : Nat) :
    decVal (l ++ [c]) = decVal l * 10 + (c - 48) := by
  simp [decVal, List.foldl_append]

theorem decVal_lenEnc : ∀ n, decVal (lenEnc n) = n := by
  intro n
  induction n using Nat.strongRecOn with
  | _ n ih =>
    by_cases h : n < 10
    · rw [lenEnc_lt n h]; simp [decVal]
    · rw [lenEnc_ge n h, decVal_append_digit, ih (n / 10) (by omega)]
      omega

theorem lenEnc_isLen (n : Nat) : IsLen (lenEnc n) n := by
  refine ⟨lenEnc_ne_nil n, lenEnc_digits n, ?_, decVal_lenEnc n⟩
  intro hh
  by_cases hn : n = 0
  · subst hn; rw [lenEnc_lt 0 (by omega)]
  · exact absurd hh (lenEnc_head n (by omega))

theorem decVal_pos_of_head (y : Nat) (ys : Bytes) (hy : 49 ≤ y) : 1 ≤ decVal (y :: ys) := by
  have key : ∀ (zs : Bytes) (a : Nat), 1 ≤ a → 1 ≤ zs.foldl (fun a c => a * 10 + (c - 48)) a := by
    intro zs
    induction zs with
    | nil => intro a ha; simpa using ha
    | cons z zs ihz => intro a ha; simp; apply ihz; omega
  unfold decVal; simp; apply key; omega

theorem isLen_unique_aux : ∀ k (l : Bytes), l.length = k → l ≠ [] → (∀ c ∈ l, isDigit c = true) →
    (l.head? = some 48 → l = [48]) → l = lenEnc (decVal l) := by
  intro k
  induction k using Nat.strongRecOn with
  | _ k ih =>
    intro l hk hne hd hz
    rcases List.eq_nil_or_concat l with h | ⟨xs, c, h⟩
    · exact absurd h hne
    · rw [List.concat_eq_append] at h
      subst h
      have hc : isDigit c = true := hd c (by simp)
      simp [isDigit] at hc
      rw [decVal_append_digit]
      cases xs with
      | nil =>
        simp [decVal]
        rw [lenEnc_lt _ (by omega)]
        simp; omega
      | cons y ys =>
        have hy : isDigit y = true := hd y (by simp)
        simp [isDigit] at hy
        have hy0 : y ≠ 48 := by
          intro hy48
          have := hz (by simp [hy48])
          simp at this
        have ihp := ih (y :: ys).length (by simp at hk ⊢; omega) (y :: ys) rfl (by simp)
          (fun d hd' => hd d (List.mem_append_left _ hd')) (by simp; intro h; exact absurd h hy0)
        have hpos := decVal_pos_of_head y ys (by omega)
        have hge : ¬ (decVal (y :: ys) * 10 + (c - 48) < 10) := by omega
        rw [lenEnc_ge _ hge]
        have hdiv : (decVal (y :: ys) * 10 + (c - 48)) / 10 = decVal (y :: ys) := by omega
        have hmod : (decVal (y :: ys) * 10 + (c - 48)) % 10 = c - 48 := by omega
        rw [hdiv, hmod, ← ihp]
        simp; omega

/-- Every LEN() numeral for `n` IS `lenEnc n`: the spec's encoding is unique,
    so "the" PAE is a function and `pae` is it. -/
theorem isLen_unique (l : Bytes) (n : Nat) (h : IsLen l n) : l = lenEnc n := by
  obtain ⟨hne, hd, hz, hv⟩ := h
  subst hv
  exact isLen_unique_aux l.length l rfl hne hd hz

theorem lenEnc_inj {m n : Nat} (h : lenEnc m = lenEnc n) : m = n := by
  have hm := decVal_lenEnc m
  rw [h, decVal_lenEnc n] at hm
  exact hm.symm

theorem lenEnc_noSP (n : Nat) : ∀ c ∈ lenEnc n, c ≠ SP := by
  intro c hc
  have := lenEnc_digits n c hc
  simp [isDigit] at this
  simp [SP]; omega

/-! ### Injectivity -/

/-- Splitting at the first separator: a separator-free prefix is determined. -/
theorem sep_split {a a' r r' : Bytes} (ha : ∀ c ∈ a, c ≠ SP) (ha' : ∀ c ∈ a', c ≠ SP)
    (h : a ++ SP :: r = a' ++ SP :: r') : a = a' ∧ r = r' := by
  induction a generalizing a' with
  | nil =>
    cases a' with
    | nil => simpa using h
    | cons y ys =>
      simp at h
      exact absurd h.1.symm (ha' y (by simp))
  | cons x xs ih =>
    cases a' with
    | nil =>
      simp at h
      exact absurd h.1 (ha x (by simp))
    | cons y ys =>
      simp at h
      obtain ⟨hxy, h2⟩ := h
      subst hxy
      have := ih (fun c hc => ha c (by simp [hc])) (fun c hc => ha' c (by simp [hc])) h2
      exact ⟨by rw [this.1], this.2⟩

/-- PAE is injective: equal encodings have equal type AND equal body. So a
    signature over PAE(t, b) is a signature over exactly one (t, b). -/
theorem pae_injective {t b t' b' : Bytes} (h : pae t b = pae t' b') : t = t' ∧ b = b' := by
  unfold pae at h
  have h1 := List.append_cancel_left h
  simp only [List.cons.injEq, true_and] at h1
  obtain ⟨hl, h2⟩ := sep_split (lenEnc_noSP _) (lenEnc_noSP _) h1
  have hlen : t.length = t'.length := lenEnc_inj hl
  obtain ⟨ht, h3⟩ := List.append_inj h2 hlen
  simp only [List.cons.injEq, true_and] at h3
  obtain ⟨_, h4⟩ := sep_split (lenEnc_noSP _) (lenEnc_noSP _) h3
  exact ⟨ht, h4⟩

/-! ### As built -/

/-- Go's `%d` of a non-negative int: `strconv`'s decimal digits. Modeled by
    Lean core's `Nat.toDigits 10`, an independent definition of the numeral. -/
def goD (n : Nat) : Bytes := (Nat.toDigits 10 n).map Char.toNat

/-- `preauthEncode(bodyType, body)` as built: one `fmt.Sprintf` head, then the
    body appended. `len(bodyType)` is Go's byte length of the string. -/
-- cite: attestation/dsse/dsse.go:240-247 sha256:1552241a2cd0fde3
def preauthEncode (ty body : Bytes) : Bytes :=
  ("DSSEv1".toList.map Char.toNat ++ [SP] ++ goD ty.length ++ [SP] ++ ty ++ [SP] ++
    goD body.length ++ [SP]) ++ body

theorem digitChar_toNat (d : Nat) (h : d < 10) : (Nat.digitChar d).toNat = 48 + d := by
  match d, h with
  | 0, _ => rfl
  | 1, _ => rfl
  | 2, _ => rfl
  | 3, _ => rfl
  | 4, _ => rfl
  | 5, _ => rfl
  | 6, _ => rfl
  | 7, _ => rfl
  | 8, _ => rfl
  | 9, _ => rfl

theorem goD_eq_lenEnc : ∀ n, goD n = lenEnc n := by
  intro n
  induction n using Nat.strongRecOn with
  | _ n ih =>
    unfold goD
    rw [Nat.toDigits_eq_ite (by decide)]
    by_cases h : n < 10
    · simp only [h, ↓reduceIte]; rw [lenEnc_lt n h]; simp [digitChar_toNat n h]
    · simp only [h, ↓reduceIte]; rw [lenEnc_ge n h, List.map_append]
      have := ih (n / 10) (by omega)
      unfold goD at this
      rw [this]; simp [digitChar_toNat (n % 10) (by omega)]

/-- The shipped encoder is the spec's PAE on every input. -/
theorem preauthEncode_eq (ty body : Bytes) : preauthEncode ty body = pae ty body := by
  unfold preauthEncode pae
  rw [goD_eq_lenEnc, goD_eq_lenEnc]
  have : "DSSEv1".toList.map Char.toNat = dsseV1 := by decide
  rw [this]
  simp

/-- Hence the shipped encoder is injective too. -/
theorem preauthEncode_injective {t b t' b' : Bytes}
    (h : preauthEncode t b = preauthEncode t' b') : t = t' ∧ b = b' := by
  rw [preauthEncode_eq, preauthEncode_eq] at h
  exact pae_injective h

end DsseIntoto
