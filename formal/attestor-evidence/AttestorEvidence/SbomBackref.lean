/-
  AttestorEvidence.SbomBackref: when an SBOM predicate may claim, through an
  `imagedigest:` backref, that it describes a particular image.

  As built (#10192, subtrees/rookery/plugins/attestors/sbom/sbom.go):
  `backRefsFromExtraction` takes the digest from `metadata.component.purl`
  (`imageDigestFromPURL`, already on main) and otherwise from
  `containerDigestFromVersion(type, version)`, which accepts exactly
  `sha256:<64 lowercase hex>` on a component of type `container`. Anything else
  falls back to the `name:` anchor, which claims no image.

  The purl parser is modelled only by its output (`purlDigest`); its grammar is
  main's and out of scope here.
-/
import AttestorEvidence.Text

namespace AttestorEvidence.Sbom

open AttestorEvidence

def isLowerHex (c : Char) : Bool :=
  ('0' ≤ c && c ≤ '9') || ('a' ≤ c && c ≤ 'f')

def sha256Prefix : Text := "sha256:".toList

/-- `containerDigestFromVersion` (sbom.go). -/
def containerDigest (ty : String) (version : Text) : Option Text :=
  if ty = "container" then
    match cutPrefix sha256Prefix version with
    | some h => if utf8Len h = 64 ∧ h.all isLowerHex = true then some h else none
    | none => none
  else none

/-- The digest an `imagedigest:` backref carries, if any: the purl's wins. -/
def imageBackref (purlDigest : Option Text) (ty : String) (version : Text) : Option Text :=
  match purlDigest with
  | some d => some d
  | none => containerDigest ty version

/-- A backref taken from the version needs a `container` component. A library
    whose version happens to look like a digest never names an image. -/
theorem version_backref_needs_container {ty : String} {v d : Text}
    (h : imageBackref none ty v = some d) : ty = "container" := by
  simp only [imageBackref, containerDigest] at h
  split at h
  · assumption
  · cases h

/-- A backref taken from the version is exactly the observed version bytes
    after `sha256:`, 64 bytes of lowercase hex (Go checks `len` = 64, then every rune): nothing is normalised, so the
    claim is bound to the bytes the SBOM carried. -/
theorem version_backref_is_exact {ty : String} {v d : Text}
    (h : imageBackref none ty v = some d) :
    v = sha256Prefix ++ d ∧ utf8Len d = 64 ∧ d.all isLowerHex = true := by
  simp only [imageBackref, containerDigest] at h
  split at h
  · split at h
    · rename_i r hr
      split at h
      · rename_i hc
        cases h
        exact ⟨cutPrefix_some hr, hc.1, hc.2⟩
      · cases h
    · cases h
  · cases h

/-- The purl's digest always wins over the version. -/
theorem purl_wins (d : Text) (ty : String) (v : Text) :
    imageBackref (some d) ty v = some d := rfl

end AttestorEvidence.Sbom
