/-
  SigningTrust.Vectors: the differential vectors, generated from the model.

  vectors/signing-trust.json holds, per case, the input and the AS-BUILT and
  REQUIRED answers. Replayed against the real code by

    attestation/cryptoutil/formal_x509_differential_test.go
    attestation/timestamp/formal_tsp_differential_test.go

  Staleness gate: `lake build` fails when the committed file is not exactly
  what this module generates. Regenerate after a model change:

    SIGNING_TRUST_VECTORS_REGEN=1 lake env lean --run SigningTrust/Vectors.lean > vectors/signing-trust.json
-/
import SigningTrust.Tsp

namespace SigningTrust.Vectors
open SigningTrust

deriving instance Inhabited for SigningTrust.EKU
deriving instance Inhabited for SigningTrust.Alg
deriving instance Inhabited for SigningTrust.Ess

def jstr (s : String) : String := "\"" ++ s ++ "\""
def jarr (xs : List String) : String := "[" ++ ",".intercalate xs ++ "]"
def jbool (b : Bool) : String := if b then "true" else "false"
def jnat (n : Nat) : String := toString n
def jopt (o : Option Nat) : String := match o with | none => "null" | some n => jnat n

def lcg (s : Nat) : Nat := (s * 1103515245 + 12345) % 2147483648

def draws (s k n : Nat) : List Nat × Nat :=
  (List.range n).foldl (fun (acc, s) _ => let s' := lcg s; (acc ++ [s' / 65536 % k], s')) ([], s)

def ekuStr : EKU → String
  | .none => "none" | .codeSigning => "codeSigning" | .timeStamping => "timeStamping"
  | .serverAuth => "serverAuth" | .any => "any" | .codeAndServer => "codeAndServer" | .tsAndServer => "tsAndServer"

def kuJson : Option KU → String
  | none => "null"
  | some k => "{\"ds\":" ++ jbool k.digitalSignature ++ ",\"cc\":" ++ jbool k.contentCommitment ++ ",\"cs\":" ++ jbool k.keyCertSign ++ "}"

def certJson (c : Cert) : String :=
  "{\"id\":" ++ jnat c.id ++ ",\"bc\":" ++ jbool c.bc ++ ",\"ca\":" ++ jbool c.ca ++ ",\"pathLen\":" ++ jopt c.pathLen ++
  ",\"ku\":" ++ kuJson c.ku ++ ",\"eku\":" ++ jstr (ekuStr c.eku) ++ ",\"nb\":" ++ jnat c.nb ++ ",\"na\":" ++ jnat c.na ++
  ",\"crit\":" ++ jbool c.crit ++ "}"

def pick {α} [Inhabited α] (xs : List α) (n : Nat) : α := xs[n % xs.length]!

def times : List Nat := [100, 400, 500, 600, 900]

def mkLeaf (d : List Nat) : Cert :=
  let bc := d[0]! % 3 = 0
  let ca := bc && d[1]! % 3 = 0
  let ku := pick [none, some ⟨true, false, false⟩, some ⟨true, false, true⟩, some ⟨false, false, false⟩,
                  some ⟨false, true, false⟩, none] d[2]!
  let eku := pick [EKU.codeSigning, .codeSigning, .codeSigning, .none, .serverAuth, .any, .codeAndServer, .timeStamping] d[3]!
  let a := pick [100, 100, 400, 450, 600] d[4]!
  let b := pick [900, 900, 600, 550, 400] d[5]!
  ⟨10, bc, ca, none, ku, eku, min a b, max a b, d[6]! % 20 = 0⟩

def mkCA (id : Nat) (d : List Nat) : Cert :=
  let bc := d[0]! % 16 != 0
  let ca := bc && d[1]! % 16 != 0
  let pl := if ca then pick [none, none, some 0, some 1] d[2]! else none
  let ku := pick [some ⟨false, false, true⟩, some ⟨false, false, true⟩, some ⟨false, false, true⟩, none, none, some ⟨true, false, false⟩,
                  some ⟨true, false, true⟩] d[3]!
  let eku := pick [EKU.none, .none, .none, .none, .none, .none, .none, .codeSigning, .serverAuth, .any] d[4]!
  let a := pick [0, 0, 0, 0, 100, 500] d[5]!
  let b := pick [2000, 2000, 2000, 2000, 900, 400] d[6]!
  ⟨id, bc, ca, pl, ku, eku, min a b, max a b, d[7]! % 20 = 0⟩

def x509Case (chain : List Cert) (anchors : List Nat) (t : Time) : String :=
  let res := match chain with
    | [] => (false, false)
    | leaf :: rest => match choosePath anchors leaf rest with
      | none => (false, false)
      | some p => (x509Verify p t, x509VerifyReq p t)
  "{\"chain\":" ++ jarr (chain.map certJson) ++ ",\"anchors\":" ++ jarr (anchors.map jnat) ++ ",\"t\":" ++ jnat t ++
  ",\"asbuilt\":" ++ jbool res.1 ++ ",\"required\":" ++ jbool res.2 ++ "}"

def genX509 (s : Nat) : String × Nat :=
  let (d, s) := draws s 1024 30
  let leaf := mkLeaf (d.drop 0)
  let nca := d[7]! % 3
  let cas := (List.range nca).map (fun i => mkCA (20 + i) (d.drop (8 + 7 * i)))
  let root := mkCA 1 (d.drop 22)
  let chain := leaf :: cas ++ [root]
  let anchors := match d[29]! % 10 with
    | 0 => []
    | 1 => [leaf.id]
    | 2 => (cas.head?.map (·.id)).toList
    | 3 => root.id :: (cas.head?.map (·.id)).toList
    | _ => [root.id]
  let t := pick [500, 500, 500, 450, 550, 100, 400, 900, 1500] d[28]!
  (x509Case chain anchors t, s)

def x509Cases : List String :=
  ((List.range 1200).foldl (fun (acc, s) _ => let (v, s) := genX509 s; (acc ++ [v], s)) ([], 9917)).1

/-! ### RFC 3161 tokens -/

def algStr : Alg → String | .sha1 => "sha1" | .sha256 => "sha256" | .sha384 => "sha384" | .sha512 => "sha512"
def essStr : Ess → String
  | .none => "none" | .v2 => "v2" | .v2BadHash => "v2BadHash" | .v2BadSerial => "v2BadSerial"
  | .v1 => "v1" | .v1BadHash => "v1BadHash"

def tsaRoot : Cert := ⟨1, true, true, none, some ⟨false, false, true⟩, .none, 0, 2000, false⟩

def tspCase (anchors : List Nat) (tok : Token) : String :=
  "{\"alg\":" ++ jstr (algStr tok.alg) ++ ",\"imprintOk\":" ++ jbool tok.imprintOk ++ ",\"sigOk\":" ++ jbool tok.sigOk ++
  ",\"genTime\":" ++ jnat tok.genTime ++ ",\"signingTime\":" ++ jopt tok.signingTime ++
  ",\"leaf\":" ++ certJson tok.leaf ++ ",\"root\":" ++ certJson tok.root ++ ",\"ess\":" ++ jstr (essStr tok.ess) ++
  ",\"anchors\":" ++ jarr (anchors.map jnat) ++
  ",\"asbuilt\":" ++ jopt (tspVerify anchors tok 1000) ++ ",\"kuonly\":" ++ jopt (tspVerifyKU anchors tok 1000) ++ ",\"required\":" ++ jopt (tspVerifyReq anchors tok 1000) ++ "}"

def genTsp (s : Nat) : String × Nat :=
  let (d, s) := draws s 1024 12
  let alg := pick [Alg.sha256, .sha256, .sha384, .sha512, .sha1] d[0]!
  let ess := pick [Ess.v2, .v2, .v2, .none, .v2BadHash, .v2BadSerial, .v1, .v1BadHash] d[1]!
  let eku := pick [EKU.timeStamping, .timeStamping, .timeStamping, .timeStamping, .timeStamping, .tsAndServer, .none, .codeSigning] d[2]!
  let ku := pick [some ⟨true, false, false⟩, some ⟨true, false, false⟩, none, some ⟨false, true, false⟩,
                  some ⟨false, false, false⟩, some ⟨true, false, true⟩] d[3]!
  let a := pick [100, 100, 400, 600] d[4]!
  let b := pick [900, 900, 500, 1500] d[5]!
  let leaf : Cert := ⟨2, true, false, none, ku, eku, min a b, max a b, false⟩
  let g := pick [500, 500, 500, 500, 500, 200, 950, 0] d[6]!
  let st := pick [some 500, none, some 500, some 1200] d[7]!
  let anchors := pick [[1], [1], [1], [], [2], [1, 2]] d[8]!
  (tspCase anchors ⟨alg, d[9]! % 8 != 0, d[10]! % 10 != 0, g, st, leaf, tsaRoot, ess⟩, s)

def tspCases : List String :=
  ((List.range 400).foldl (fun (acc, s) _ => let (v, s) := genTsp s; (acc ++ [v], s)) ([], 3161)).1

def vectorsJson : String :=
  "{\"x509\":[\n" ++ ",\n".intercalate x509Cases ++ "\n],\n\"tsp\":[\n" ++ ",\n".intercalate tspCases ++ "\n]}\n"

/- Staleness gate: the committed vectors must be exactly this model's.
   Skipped only while regenerating (SIGNING_TRUST_VECTORS_REGEN=1). -/
#eval show IO Unit from do
  if (← IO.getEnv "SIGNING_TRUST_VECTORS_REGEN").isSome then return
  let path : System.FilePath := "vectors" / "signing-trust.json"
  let committed ← IO.FS.readFile path
  unless committed == vectorsJson do
    throw <| IO.userError s!"{path} is stale; regenerate: SIGNING_TRUST_VECTORS_REGEN=1 lake env lean --run SigningTrust/Vectors.lean > {path}"

end SigningTrust.Vectors

def main : IO Unit := IO.print SigningTrust.Vectors.vectorsJson
