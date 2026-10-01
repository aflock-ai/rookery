/-
  CilockEvaluators.Seeded.Json: the JSON values a seeded rule reads, and the
  handful of Rego operations the rules use on them.

  Numbers are integers. The Go driver and the attestors only emit integer
  counts, indices and exit codes, and the oracle refuses a fractional number
  rather than rounding it (a modelling boundary, stated in the README).

  Objects are lists of (key, value) pairs in key order with unique keys, which
  is what the oracle's decoder produces from a parsed JSON object; structural
  equality on that representation is Rego's equality on objects.
-/

namespace CilockEvaluators.Seeded

inductive J where
  | null
  | bool (b : Bool)
  | num (n : Int)
  | str (s : String)
  | arr (xs : List J)
  | obj (kvs : List (String × J))
  deriving Repr, Inhabited

mutual
/-- Rego equality (`==`), for values of any shape. -/
def J.eqv : J → J → Bool
  | .null, .null => true
  | .bool a, .bool b => a == b
  | .num a, .num b => a == b
  | .str a, .str b => a == b
  | .arr xs, .arr ys => J.eqvList xs ys
  | .obj xs, .obj ys => J.eqvObj xs ys
  | _, _ => false

def J.eqvList : List J → List J → Bool
  | [], [] => true
  | x :: xs, y :: ys => J.eqv x y && J.eqvList xs ys
  | _, _ => false

def J.eqvObj : List (String × J) → List (String × J) → Bool
  | [], [] => true
  | (k, x) :: xs, (l, y) :: ys => k == l && J.eqv x y && J.eqvObj xs ys
  | _, _ => false
end

def J.isNull : J → Bool | .null => true | _ => false
def J.isBool : J → Bool | .bool _ => true | _ => false
def J.isNum : J → Bool | .num _ => true | _ => false
def J.isStr : J → Bool | .str _ => true | _ => false
def J.isArr : J → Bool | .arr _ => true | _ => false
def J.isObj : J → Bool | .obj _ => true | _ => false

/-- `x.k` / `x[k]` for a string key: defined only on an object that has it. -/
def J.get : J → String → Option J
  | .obj kvs, k => kvs.lookup k
  | _, _ => none

/-- The rules' shared total accessor:
    `field(x, k, d) = v { is_object(x); v := object.get(x, k, d) } else = d`. -/
def field (x : J) (k : String) (d : J) : J :=
  match x with
  | .obj kvs => (kvs.lookup k).getD d
  | _ => d

/-- `object.get(x, k, d)` without the `field` guard: on a non-object it is a
    builtin type error, which StrictBuiltinErrors turns into a refusal
    (`none`). The tracing rules read process records this way. -/
def oget (x : J) (k : String) (d : J) : Option J :=
  match x with
  | .obj kvs => some ((kvs.lookup k).getD d)
  | _ => none

/-- `x[_]`: the elements of an array, the values of an object, nothing else. -/
def J.elems : J → List J
  | .arr xs => xs
  | .obj kvs => kvs.map Prod.snd
  | _ => []

/-- `x[i]` for a number `i`: an array element in range; undefined otherwise. -/
def J.at : J → J → Option J
  | .arr xs, .num i => if 0 ≤ i then xs[i.toNat]? else none
  | _, _ => none

/-- `count(x)` on an array. -/
def J.len : J → Nat
  | .arr xs => xs.length
  | _ => 0

/-- `x >= 0` under Rego's total order (null < boolean < number < string <
    array < object): true for a non-negative number and for every string,
    array and object; false for null, booleans and negative numbers. -/
def J.geZero : J → Bool
  | .null => false
  | .bool _ => false
  | .num n => 0 ≤ n
  | _ => true

/-- `x == "s"`. -/
def J.isStrEq (x : J) (s : String) : Bool :=
  match x with
  | .str t => t == s
  | _ => false

/-- `n > 0` / `n < 1` style checks on a value already known to be a number. -/
def J.numVal : J → Int
  | .num n => n
  | _ => 0

/-- Membership in a set of values, by Rego equality. -/
def memJ (x : J) (xs : List J) : Bool := xs.any (fun y => J.eqv x y)

/-- Membership of a value in a set of strings (`allowed[x]`). -/
def memStr (x : J) (ss : List String) : Bool :=
  match x with
  | .str s => ss.contains s
  | _ => false

/-- Rego `contains(s, sub)` on strings (by characters; equal to Go's byte
    test on valid UTF-8). -/
def strContains (s sub : String) : Bool := go s.toList
where
  go : List Char → Bool
    | [] => sub.toList.isEmpty
    | c :: cs => sub.toList.isPrefixOf (c :: cs) || go cs

def isHexChar (c : Char) : Bool := ('0' ≤ c && c ≤ '9') || ('a' ≤ c && c ≤ 'f')

/-- `regex.match("^[0-9a-f]{n,}$", s)`: at least `n` lowercase hex digits. -/
def hexAtLeast (n : Nat) (s : String) : Bool := decide (n ≤ s.length) && s.toList.all isHexChar

/-- `regex.match("^[0-9a-f]{n}$", s)`: exactly `n` lowercase hex digits. -/
def hexExactly (n : Nat) (s : String) : Bool := decide (s.length = n) && s.toList.all isHexChar

/-- Rego `startswith(s, pre)`. -/
def strStarts (s pre : String) : Bool := pre.toList.isPrefixOf s.toList

/-- Rego `endswith(s, suf)`. -/
def strEnds (s suf : String) : Bool := suf.toList.reverse.isPrefixOf s.toList.reverse

end CilockEvaluators.Seeded
