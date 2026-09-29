/-!
# Subject binding: provenance subjects are the product digests, per algorithm

The SLSA attestor copies the attestation context's products when it meets the
product attestor, then builds `file:<name>` subjects from them and overlays
the subjects other attestors emitted:
-- cite: plugins/attestors/slsa/slsa.go:312-326 sha256:04a9e314a6c3bd3287c1dd52da90a998d9649552b1958db671a3a5fbdbd0b3b2
-- cite: plugins/attestors/slsa/slsa.go:362-376 sha256:de0f3a2557f7e23c3482906f1eabfc29c61dbfb2cf87b8c0c4f5eed83ed7e698
An attestor that errored contributes nothing:
-- cite: plugins/attestors/slsa/slsa.go:176-179 sha256:2ca61b975d8a4b47849541266f2763e01d3a3cebe74fa9681cdede640e820fae
The context's products are every producer's, last writer wins:
-- cite: attestation/context.go:567-572 sha256:ce8e30325badd203b43fd277114f5411f10379a8960418bf60f1d99be0a008f8
The product attestor's own subject is the Merkle root, under sha256 only:
-- cite: plugins/attestors/product/product.go:960-964 sha256:fa0624a77d4f15a88d4d8aa059ce8d65052ef91a1dd1523020bbc234e65cb394

A digest set is a map from algorithm name ("sha256", "gitoid:sha256",
"dirHash", ...) to value; maps are association lists whose first binding wins,
which is the Go map read for a key.
-/

namespace CiProvenance

abbrev DigestSet := List (String × String)
abbrev Named (α : Type) := List (String × α)

def lookup {α : Type} (m : Named α) (k : String) : Option α :=
  (m.find? (fun p => p.1 == k)).map (·.2)

/-- Go's `m[k] = v`. -/
def insert {α : Type} (m : Named α) (k : String) (v : α) : Named α :=
  (k, v) :: m.filter (fun p => p.1 != k)

/-- `Provenance.Subjects()`: `file:<name>` for every product, then every
other subject, overwriting. -/
def slsaSubjects (products : Named DigestSet) (extra : Named DigestSet) : Named DigestSet :=
  let base := products.foldr (fun p m => insert m ("file:" ++ p.1) p.2) []
  extra.foldr (fun p m => insert m p.1 p.2) base

/-- `AttestationContext.Products()` after each producer ran in order. -/
def ctxProducts (producers : List (Named DigestSet)) : Named DigestSet :=
  producers.foldl (fun m ps => ps.foldr (fun p acc => insert acc p.1 p.2) m) []

theorem lookup_nil {α : Type} (k : String) : lookup ([] : Named α) k = none := rfl

theorem lookup_cons {α : Type} (k k' : String) (v : α) (m : Named α) :
    lookup ((k, v) :: m) k' = if k = k' then some v else lookup m k' := by
  by_cases h : k = k' <;> simp [lookup, h]

theorem lookup_filter_ne {α : Type} (m : Named α) (k k' : String) (h : k ≠ k') :
    lookup (m.filter (fun p => p.1 != k)) k' = lookup m k' := by
  induction m with
  | nil => rfl
  | cons p rest ih =>
    obtain ⟨a, v⟩ := p
    by_cases ha : a = k
    · subst ha
      simp [lookup_cons, h, ih]
    · simp [ha, lookup_cons, ih]

theorem lookup_insert {α : Type} (m : Named α) (k k' : String) (v : α) :
    lookup (insert m k v) k' = if k = k' then some v else lookup m k' := by
  unfold insert
  rw [lookup_cons]
  by_cases h : k = k'
  · simp [h]
  · simp [h, lookup_filter_ne m k k' h]

/-- Folding inserts under an injective key map: a key the fold wrote reads
back the first binding in the list; any other key reads through. -/
theorem lookup_foldr_insert {α : Type} (f : String → String) (hf : ∀ a b, f a = f b → a = b)
    (ps : Named α) (m0 : Named α) (n : String) :
    lookup (ps.foldr (fun p m => insert m (f p.1) p.2) m0) (f n) =
      match lookup ps n with
      | some d => some d
      | none => lookup m0 (f n) := by
  induction ps with
  | nil => rfl
  | cons p rest ih =>
    obtain ⟨a, v⟩ := p
    simp only [List.foldr_cons]
    rw [lookup_insert, lookup_cons]
    by_cases han : a = n
    · subst han; simp
    · have : f a ≠ f n := fun h => han (hf a n h)
      simp [this, han, ih]

theorem file_prefix_inj : ∀ a b : String, "file:" ++ a = "file:" ++ b → a = b :=
  fun _ _ h => (String.append_right_inj "file:").mp h

/-- Subject binding. When no other attestor emits a `file:<name>` key, the
provenance subject for product `name` is exactly the digest set the product
producer recorded: same algorithms, same values. -/
theorem subject_binding (products extra : Named DigestSet) (n : String)
    (hno : lookup extra ("file:" ++ n) = none) :
    lookup (slsaSubjects products extra) ("file:" ++ n) = lookup products n := by
  unfold slsaSubjects
  have hid : ∀ a b : String, id a = id b → a = b := fun _ _ h => h
  have hx := lookup_foldr_insert id hid extra
    (products.foldr (fun p m => insert m ("file:" ++ p.1) p.2) []) ("file:" ++ n)
  simp only [id] at hx
  rw [hx, hno]
  simp only
  rw [lookup_foldr_insert (fun s => "file:" ++ s) file_prefix_inj products [] n]
  cases lookup products n <;> rfl

/-- With the product attestor the only producer, the context's products are
its products. In-tree, only the product attestor implements `Producer`. -/
theorem ctxProducts_single (pa : Named DigestSet) (n : String) :
    lookup (ctxProducts [pa]) n = lookup pa n := by
  unfold ctxProducts
  simp only [List.foldl_cons, List.foldl_nil]
  have hid : ∀ a b : String, id a = id b → a = b := fun _ _ h => h
  have := lookup_foldr_insert id hid pa [] n
  simp only [id] at this
  rw [this]
  cases lookup pa n <;> rfl

/-- The end-to-end binding under the two assumptions: the product attestor is
the only producer and nothing else emits a `file:` key. -/
theorem provenance_subject_is_product_digest (pa extra : Named DigestSet) (n : String)
    (hno : lookup extra ("file:" ++ n) = none) :
    lookup (slsaSubjects (ctxProducts [pa]) extra) ("file:" ++ n) = lookup pa n := by
  rw [subject_binding _ _ _ hno, ctxProducts_single]

/-- Counterexample: another attestor emitting `file:<name>` overwrites the
product digest. No in-tree subjecter does (OCI uses `manifestdigest:`,
`tardigest:`, `imageid:`), but nothing in the code forbids it. -/
theorem file_key_collision_overwrites :
    lookup (slsaSubjects [("app", [("sha256", "good")])] [("file:app", [("sha256", "evil")])]) "file:app" ≠
      lookup [("app", [("sha256", "good")])] "app" := by
  decide

/-- Counterexample: a second producer writing the same name wins. -/
theorem second_producer_overwrites :
    lookup (ctxProducts [[("app", [("sha256", "good")])], [("app", [("sha256", "evil")])]]) "app" ≠
      lookup [("app", [("sha256", "good")])] "app" := by
  decide

/-! ## Matching a seed against a subject: algorithm-aware or not (issue #9816)

Since #9863 the code matches on (algorithm, value): policyverify turns each
seed into an algorithm:value key and the memory index is keyed the same way.
`matchByValue` is the pre-#9863 behaviour, kept as the counterexample; the
refined model with the matchability filter and the legacy table is
formal/security-backlog SecBacklog/Subject.lean.

-- cite: plugins/attestors/policyverify/policyverify.go:128-138 sha256:b8d9bbe775e3698b
-- cite: attestation/source/memory.go:111-113 sha256:7605160503b2bca1
-/

/-- Match on (algorithm, value). -/
def matchAlgAware (subject : DigestSet) (seed : String × String) : Bool :=
  subject.any (fun p => p == seed)

/-- Match on the bare value, as the seed flattening does. -/
def matchByValue (subject : DigestSet) (value : String) : Bool :=
  subject.any (fun p => p.2 == value)

theorem matchAlgAware_sound (subject : DigestSet) (alg v : String)
    (h : matchAlgAware subject (alg, v) = true) : (alg, v) ∈ subject := by
  simp [matchAlgAware] at h
  exact h

/-- Algorithm-aware binding end to end: a seed that matches the `file:<name>`
subject names a digest the product producer recorded under that algorithm. -/
theorem seed_match_binds_product (pa extra : Named DigestSet) (n alg v : String) (d : DigestSet)
    (hno : lookup extra ("file:" ++ n) = none)
    (hs : lookup (slsaSubjects (ctxProducts [pa]) extra) ("file:" ++ n) = some d)
    (hm : matchAlgAware d (alg, v) = true) :
    ∃ recorded, lookup pa n = some recorded ∧ (alg, v) ∈ recorded := by
  rw [provenance_subject_is_product_digest pa extra n hno] at hs
  exact ⟨d, hs, matchAlgAware_sound d alg v hm⟩

/-- Counterexample: value-only matching lets a `dirHash` value stand in for a
`sha1` seed with the same string; the algorithm-aware match refuses it. -/
theorem value_match_crosses_algorithms :
    matchByValue [("dirHash", "ab12")] "ab12" = true ∧ matchAlgAware [("dirHash", "ab12")] ("sha1", "ab12") = false := by
  decide

end CiProvenance
