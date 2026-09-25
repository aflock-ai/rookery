/-
  DsseIntoto.Vectors: the differential vectors, generated from the model.

  vectors/dsse-intoto.json holds, for every case, the input and the answer
  the AS-BUILT model gives (and, where a fix is specified, the REQUIRED
  model's answer too). The Go tests replay each case against the real code:

    attestation/dsse/formal_dsse_differential_test.go
    attestation/intoto/formal_statement_differential_test.go
    attestation/source/formal_consume_differential_test.go

  Staleness gate: `lake build` fails when the committed file is not exactly
  what this module generates. Regenerate after a model change:

    DSSE_INTOTO_VECTORS_REGEN=1 lake env lean --run DsseIntoto/Vectors.lean > vectors/dsse-intoto.json
-/
import DsseIntoto.Pae
import DsseIntoto.Verify
import DsseIntoto.Statement

namespace DsseIntoto.Vectors
open DsseIntoto

def jstr (s : String) : String := "\"" ++ s ++ "\""
def jarr (xs : List String) : String := "[" ++ ",".intercalate xs ++ "]"
def jbool (b : Bool) : String := if b then "true" else "false"
def jnat (n : Nat) : String := toString n
def jint (n : Int) : String := toString n

def hexDigit (n : Nat) : Char := "0123456789abcdef".toList.getD n '0'
def hex (bs : Bytes) : String := String.ofList (bs.flatMap (fun b => [hexDigit (b / 16 % 16), hexDigit (b % 16)]))
def bytesOf (s : String) : Bytes := s.toUTF8.toList.map UInt8.toNat

/-- A deterministic pseudo-random stream (the C LCG). -/
def lcg (s : Nat) : Nat := (s * 1103515245 + 12345) % 2147483648

/-- Draw `n` values below `k` from seed `s`, and the next seed. -/
def draws (s k n : Nat) : List Nat × Nat :=
  (List.range n).foldl (fun (acc, s) _ => let s' := lcg s; (acc ++ [s' / 65536 % k], s')) ([], s)

/-! ### PAE -/

def paeTypes : List String :=
  ["", "a", "0", "x y", "application/vnd.in-toto+json", "héllo wörld",
   String.ofList (List.replicate 10 'T'), String.ofList (List.replicate 100 't')]

def paeLens : List Nat := [0, 1, 9, 10, 11, 99, 100, 101, 999, 1000, 1001, 65536]

def paeCase (ty : String) (n : Nat) (fill : Nat) : String :=
  let t := bytesOf ty
  let enc := preauthEncode t (List.replicate n fill)
  let head := enc.take (enc.length - n)
  "{\"type_hex\":" ++ jstr (hex t) ++ ",\"body_len\":" ++ jnat n ++ ",\"body_byte\":" ++ jnat fill ++
    ",\"head_hex\":" ++ jstr (hex head) ++ "}"

def paeCases : List String :=
  (paeTypes.zipIdx).flatMap (fun (ty, i) => paeLens.map (fun n => paeCase ty n ((i * 37 + n) % 256)))

/-! ### Verify -/

def vPayloadType : String := "application/vnd.test+json"
def vPayload : String := "hello"
def vPae : Bytes := preauthEncode (bytesOf vPayloadType) (bytesOf vPayload)

def certTimes : List Nat := [0, 50, 150, 250, 950, 1050, 2000]
def tsTimes : List Nat := [100, 200, 300]

def verdictStr : Verdict → String
  | .invalidThreshold => "invalidThreshold"
  | .noSignatures => "noSignatures"
  | .noMatching => "noMatching"
  | .thresholdNotMet n => "thresholdNotMet:" ++ toString n
  | .ok n => "ok:" ++ toString n

def certJson : Option Cert → String
  | none => "null"
  | some c => "{\"key\":" ++ jnat c.key ++ ",\"chains\":" ++ jbool c.chains ++ ",\"nb\":" ++ jnat c.nb ++
      ",\"na\":" ++ jnat c.na ++ "}"

def sigJson (s : EnvSig) : String :=
  "{\"keyid\":" ++ jnat s.keyid ++ ",\"signer\":" ++ jnat s.sig.signer ++ ",\"good\":" ++ jbool (s.sig.msg == vPae) ++
    ",\"cert\":" ++ certJson s.cert ++ ",\"ts\":" ++ jarr (s.timestamps.map jnat) ++ "}"

def verifyCase (o : Opts) (e : Envelope) : String :=
  "{\"threshold\":" ++ jint o.threshold ++ ",\"verifiers\":" ++ jarr (o.verifiers.map jnat) ++
    ",\"tsas\":" ++ jarr (o.tsas.map jnat) ++ ",\"fallback\":" ++ jbool o.fallback ++
    ",\"sigs\":" ++ jarr (e.sigs.map sigJson) ++ ",\"asbuilt\":" ++ jstr (verdictStr (verify o e)) ++ "}"

def mkEnv (sigs : List EnvSig) : Envelope := ⟨bytesOf vPayloadType, bytesOf vPayload, sigs⟩

/-- A sub-list of `xs` chosen by the bits of `m`. -/
def subsetOf (xs : List Nat) (m : Nat) : List Nat :=
  (xs.zipIdx).filterMap (fun (x, i) => if m / (2 ^ i) % 2 = 1 then some x else none)

def genSig (s : Nat) : EnvSig × Nat :=
  let (d, s) := draws s 64 9
  let signer := d[0]! % 4 + 1
  let good := d[1]! % 4 != 0
  let certSel := d[2]! % 3
  let cert : Option Cert :=
    if certSel = 0 then none
    else
      let key := if d[3]! % 4 = 0 then d[3]! % 3 + 1 else signer
      let nb := certTimes[d[4]! % certTimes.length]!
      let na := certTimes[d[5]! % certTimes.length]!
      some ⟨key, certSel = 1, min nb na, max nb na⟩
  let ts := subsetOf tsTimes (d[6]! % 8)
  (⟨d[7]!, ⟨signer, if good then vPae else [0]⟩, cert, ts⟩, s)

def genVerify (s : Nat) : String × Nat :=
  let (d, s) := draws s 64 6
  let threshold : Int := match d[0]! % 10 with | 0 => -1 | 1 => 0 | 7 | 8 => 2 | 9 => 3 | _ => 1
  let verifiers := match d[1]! % 5 with
    | 0 => [] | 1 => [1] | 2 => [1, 2] | 3 => [2, 1, 1] | _ => [3]
  let tsas := subsetOf [100, 200] (d[2]! % 4)
  let fallback := d[3]! % 2 = 1
  let nsig := if d[4]! % 10 = 0 then 0 else d[4]! % 3 + 1
  let (sigs, s) := (List.range nsig).foldl (fun (acc, s) _ => let (g, s) := genSig s; (acc ++ [g], s)) ([], s)
  -- duplicate a signature now and then: one key must not count twice
  let sigs := if d[5]! % 5 = 0 then sigs ++ sigs.take 1 else sigs
  (verifyCase ⟨verifiers, threshold, tsas, fallback, 1000⟩ (mkEnv sigs), s)

def c (key : Nat) (chains : Bool) (nb na : Nat) : Option Cert := some ⟨key, chains, nb, na⟩

/-- Targeted cases first: each pins one clause. -/
def targeted : List String :=
  let good (k : Nat) : Sig := ⟨k, vPae⟩
  let o (vs : List Key) (t : Int) (tsas : List Time) (fb : Bool) : Opts := ⟨vs, t, tsas, fb, 1000⟩
  [ verifyCase (o [1] 1 [] false) (mkEnv []),
    verifyCase (o [1] 0 [] false) (mkEnv [⟨0, good 1, none, []⟩]),
    verifyCase (o [1] 2 [] false) (mkEnv [⟨0, good 1, none, []⟩, ⟨0, good 1, none, []⟩]),
    verifyCase (o [1, 2] 2 [] false) (mkEnv [⟨0, good 1, none, []⟩, ⟨0, good 2, none, []⟩]),
    verifyCase (o [1, 1] 2 [] false) (mkEnv [⟨0, good 1, none, []⟩]),
    verifyCase (o [1] 2 [100] false) (mkEnv [⟨0, good 1, c 1 true 50 150, [100]⟩]),
    verifyCase (o [] 1 [100] false) (mkEnv [⟨0, good 1, c 1 true 50 150, [100]⟩]),
    verifyCase (o [] 1 [100] false) (mkEnv [⟨0, good 1, c 1 true 150 250, [100]⟩]),
    verifyCase (o [] 1 [100] false) (mkEnv [⟨0, good 1, c 1 true 100 100, [100]⟩]),
    verifyCase (o [] 1 [100] false) (mkEnv [⟨0, good 1, c 1 false 50 150, [100]⟩]),
    verifyCase (o [] 1 [200] false) (mkEnv [⟨0, good 1, c 1 true 50 150, [100]⟩]),
    verifyCase (o [] 1 [] false) (mkEnv [⟨0, good 1, c 1 true 950 1050, []⟩]),
    verifyCase (o [] 1 [] true) (mkEnv [⟨0, good 1, c 1 true 950 1050, []⟩]),
    verifyCase (o [] 1 [] true) (mkEnv [⟨0, good 1, c 1 true 50 150, []⟩]),
    verifyCase (o [] 1 [100] true) (mkEnv [⟨0, good 1, c 1 true 950 1050, [100]⟩]),
    verifyCase (o [] 2 [100, 200] false) (mkEnv [⟨0, good 1, c 1 true 50 250, [100, 200]⟩, ⟨0, good 2, c 2 true 50 250, [200]⟩]),
    verifyCase (o [] 1 [100] false) (mkEnv [⟨0, good 1, c 2 true 50 150, [100]⟩]),
    verifyCase (o [1] 1 [] false) (mkEnv [⟨999, ⟨1, [0]⟩, none, []⟩]),
    verifyCase (o [2] 1 [] false) (mkEnv [⟨2, good 1, none, []⟩]) ]

def verifyCases : List String :=
  targeted ++ ((List.range 800).foldl (fun (acc, s) _ => let (v, s) := genVerify s; (acc ++ [v], s)) ([], 20260925)).1

/-! ### Statement construction -/

def kindStr : Option JKind → String
  | none => "invalid"
  | some .object => "object" | some .array => "array" | some .string => "string"
  | some .number => "number" | some .bool => "bool" | some .null => "null"

def errStr : MkErr → String
  | .invalidJson => "invalidJson" | .emptyPredicateType => "emptyPredicateType"
  | .predicateNotObject => "predicateNotObject" | .subjectWithoutDigest => "subjectWithoutDigest"

def digJson (d : List (String × String)) : String :=
  "{" ++ ",".intercalate (d.map (fun (k, v) => jstr k ++ ":" ++ jstr v)) ++ "}"

def subsJson (subs : List (String × List (String × String))) : String :=
  jarr (subs.map (fun (n, d) => "{\"name\":" ++ jstr n ++ ",\"digest\":" ++ digJson d ++ "}"))

def outJson : Except MkErr Statement → String
  | .error e => "{\"error\":" ++ jstr (errStr e) ++ "}"
  | .ok s => "{\"type\":" ++ jstr s.ty ++ ",\"subject\":" ++ subsJson (s.subject.map (fun x => (x.name, x.digest))) ++
      ",\"predicateType\":" ++ jstr s.predicateType ++ ",\"predicate\":" ++ jstr (kindStr (some s.predicate)) ++ "}"

def stmtSubjects : List (List (String × List (String × String))) :=
  [ [],
    [("a", [("sha256", "ab01")])],
    [("b", [("sha256", "cd02")]), ("a", [("sha1", "ef03"), ("gitoid:sha1", "gitoid:blob:sha1:0a")])],
    [("a", [])],
    [("z", [("dirHash", "0f")]), ("a", [])] ]

def stmtCases : List String :=
  ["", "https://example.com/p/v1"].flatMap (fun pt =>
    [none, some .object, some .array, some .string, some .number, some .bool, some .null].flatMap (fun k =>
      stmtSubjects.map (fun subs =>
        "{\"predicateType\":" ++ jstr pt ++ ",\"predicate\":" ++ jstr (kindStr k) ++ ",\"subjects\":" ++ subsJson subs ++
        ",\"asbuilt\":" ++ outJson (newStatement pt k subs) ++
        ",\"required\":" ++ outJson (newStatementReq statementV01 pt k subs) ++ "}")))

/-! ### Reading a verified envelope -/

def payloadTypes : List String :=
  [ intotoPayloadType, "application/vnd.in-toto.provenance+json", "application/vnd.in-toto.+json",
    "application/json", "application/vnd.aflock.policy+json", "", "APPLICATION/VND.IN-TOTO+JSON" ]

def decodedJson : Option Decoded → String
  | none => "null"
  | some d => "{\"type\":" ++ jstr d.ty ++ ",\"predicateType\":" ++ jstr d.predicateType ++ ",\"collection\":" ++ jbool d.collection ++ "}"

def decodeds : List (Option Decoded) :=
  none :: ([statementV1, statementV01, "https://example.com/Other"].flatMap (fun ty =>
    ["", "https://aflock.ai/attestation-collection/v0.1"].flatMap (fun pt =>
      [true, false].map (fun col => some ⟨ty, pt, col⟩))))

def consumeCases : List String :=
  payloadTypes.flatMap (fun pt => decodeds.map (fun d =>
    let e : RawEnv := ⟨pt, d⟩
    "{\"payloadType\":" ++ jstr pt ++ ",\"payload\":" ++ decodedJson d ++
    ",\"asbuilt\":" ++ jbool (toCollection e).isSome ++ ",\"required\":" ++ jbool (toCollectionReq e).isSome ++ "}"))

def externalCases : List String :=
  let prov := "https://slsa.dev/provenance/v1"
  let srcs : List Decoded := [⟨statementV1, prov, false⟩,
                              ⟨statementV1, "https://slsa.dev/verification_summary/v1", false⟩]
  let pays : List (Option Decoded) := [none, some ⟨statementV1, prov, false⟩,
    some ⟨"https://example.com/Other", prov, false⟩]
  [intotoPayloadType, "application/vnd.in-toto.provenance+json", "application/json"].flatMap (fun pt =>
    pays.flatMap (fun p => srcs.flatMap (fun src =>
      -- the search names the source's claimed type, or the signed one
      [[src.predicateType], [prov]].eraseDups.map (fun req =>
        let x : External := ⟨⟨pt, p⟩, src, req⟩
        "{\"payloadType\":" ++ jstr pt ++ ",\"payload\":" ++ decodedJson p ++ ",\"source\":" ++ decodedJson (some src) ++
        ",\"requested\":" ++ jarr (req.map jstr) ++
        ",\"asbuilt\":" ++ decodedJson (externalRead x) ++ ",\"required\":" ++ decodedJson (externalReadReq x) ++ "}"))))

/-! ### Envelope JSON decoding -/

def b64Str : B64 → String
  | .both => "both" | .stdOnly => "std" | .urlOnly => "url" | .invalid => "invalid"

def b64s : List B64 := [.both, .stdOnly, .urlOnly, .invalid]

def sigChoices : List (List (Bool × B64)) :=
  let one := [true, false].flatMap (fun p => b64s.map (fun b => (p, b)))
  [[]] ++ one.map (fun x => [x]) ++ one.map (fun x => [(true, .both), x])

def decodeCases : List String :=
  [true, false].flatMap (fun hp => [true, false].flatMap (fun ht => [true, false].flatMap (fun hs =>
    b64s.flatMap (fun pb => (if hs then sigChoices else [[]]).map (fun sigs =>
      let j : EnvJson := ⟨hp, ht, hs, pb, sigs⟩
      "{\"hasPayload\":" ++ jbool hp ++ ",\"hasPayloadType\":" ++ jbool ht ++ ",\"hasSignatures\":" ++ jbool hs ++
      ",\"payload\":" ++ jstr (b64Str pb) ++
      ",\"sigs\":" ++ jarr (sigs.map (fun (p, b) => "{\"has\":" ++ jbool p ++ ",\"enc\":" ++ jstr (b64Str b) ++ "}")) ++
      ",\"asbuilt\":" ++ jbool (decodes j) ++ ",\"required\":" ++ jbool (decodesReq j) ++ "}")))))

def sec (name : String) (xs : List String) : String :=
  jstr name ++ ":[\n" ++ ",\n".intercalate xs ++ "\n]"

def vectorsJson : String :=
  "{" ++ ",\n".intercalate
    [ sec "pae" paeCases, sec "verify" verifyCases, sec "statement" stmtCases,
      sec "consume" consumeCases, sec "external" externalCases, sec "decode" decodeCases ] ++ "}\n"

/- Staleness gate: the committed vectors must be exactly this model's.
   Skipped only while regenerating (DSSE_INTOTO_VECTORS_REGEN=1). -/
#eval show IO Unit from do
  if (← IO.getEnv "DSSE_INTOTO_VECTORS_REGEN").isSome then return
  let path : System.FilePath := "vectors" / "dsse-intoto.json"
  let committed ← IO.FS.readFile path
  unless committed == vectorsJson do
    throw <| IO.userError s!"{path} is stale; regenerate: DSSE_INTOTO_VECTORS_REGEN=1 lake env lean --run DsseIntoto/Vectors.lean > {path}"

end DsseIntoto.Vectors

def main : IO Unit := IO.print DsseIntoto.Vectors.vectorsJson
