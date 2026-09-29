/-
  CilockPolicy.Fixtures: small concrete values the traces are built from.
  One raw-key signer `k`, one seed digest, one attestation type.
-/
import CilockPolicy.Verify

namespace CilockPolicy.Fixtures
open CilockPolicy

/-- A well-formed sha256 hex value, used as the seed. -/
def seedD : String := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
/-- The digest of the artifact the build really produced. -/
def builtD : String := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
/-- The digest of some other artifact. -/
def otherD : String := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

def seedSubject : Subject := ⟨"artifact", ⟨"sha256", seedD⟩⟩
def attT : String := "https://example.com/att/v1"

/-- A good signature by the policy key `k`. -/
def sigK : Sig := ⟨.key "k", true, []⟩

/-- A collection named `n`, anchored on the seed, carrying one `attT`. -/
def coll (n : String) (extra : List Attestor := []) (mats prods : List (String × DigestSet) := []) :
    Collection :=
  { name := n, isCollection := true, predicateType := "https://aflock.ai/attestation-collection/v0.1",
    subjects := [seedSubject], hardenedGit := false, attestors := ⟨attT, 0, none⟩ :: extra,
    materials := mats, products := prods, leavesOk := true, inlineMaterials := true, backRefs := [] }

def env (ref : String) (c : Collection) (sigs : List Sig := [sigK]) : Envelope := ⟨ref, c, sigs⟩

/-- The functionary for key `k`. -/
def fK : Functionary := { type := "publickey", keyId := "k" }

def step (n : String) (gateId : Nat := 0) : Step :=
  { name := n, functionaries := [fK], atts := [⟨attT, gateId⟩] }

def basePolicy (steps : List Step) : Policy :=
  { expires := 1000, roots := [], tsas := [], keys := ["k"], steps := steps }

def opts : Options := { now := 10, seeds := [seedD] }

/-- Gate 0 always passes; gate 1 passes only when input.steps.scan holds a
    collection with a `clean` attestor. Opaque Rego, concrete for the trace. -/
def rego : Rego := fun g _ ctx =>
  g == 0 || ctx.steps.any fun d => d.1 == "scan" && d.2.any fun c => c.attestors.any (·.type == "clean")

def regoExt : RegoExt := fun _ _ => true

end CilockPolicy.Fixtures
