/-
  CilockPolicy.Assumptions: every cryptographic or third-party fact the
  theorems rely on, as named hypotheses. Nothing here is baked into the model:
  `Sig.ok`, `TsToken.ok` and `Cert.chainsTo` are the verifier's observations,
  and these hypotheses say what those observations imply about the world.

  Each hypothesis ranges over the evidence `E` being verified, never over
  every constructible signature: "a policy TSA never issues a time after the
  clock" over ALL tokens is refuted by a token someone could build, which
  would make the bundle uninhabitable. `assumptions_inhabited`
  (NonVacuity.lean) exhibits a certificate policy with a TSA, evidence that
  passes it, and the bundle holding.

  cilock-generic: no tenant, platform or product concept appears.
-/
import CilockPolicy.Verify

namespace CilockPolicy

/-- The world facts the verdict is about, and the hypotheses that connect the
    verifier's observations on evidence `E` to them, for one policy and one
    verify clock. -/
structure Assumptions (p : Policy) (o : Options) (E : List Envelope) where
  /-- The holder of key `k` signed this collection. -/
  signed : KeyId → Collection → Prop
  /-- The signature existed at this time. -/
  existedAt : Sig → Time → Prop
  /-- The CA at this root verified the identity fields it put in this cert
      (for Fulcio: the OIDC subject and the extension claims). -/
  vouches : RootId → Cert → Prop
  /-- SigUnforgeable: a signature in the evidence that checks was made by the
      key's holder. -/
  sigUnforgeable : ∀ e ∈ E, ∀ s ∈ e.sigs, s.ok = true → signed s.cred.keyId e.payload
  /-- TsaHonest: a token in the evidence that verifies against a policy TSA
      proves the signature existed at the token's time. -/
  tsaHonest : ∀ e ∈ E, ∀ s ∈ e.sigs, ∀ t ∈ s.tokens, t.ok = true →
    p.tsas.contains t.tsa = true → existedAt s t.time
  /-- TsaNotFuture: a policy TSA issued no token in the evidence with a time
      after the verify clock. -/
  tsaNotFuture : ∀ e ∈ E, ∀ s ∈ e.sigs, ∀ t ∈ s.tokens, t.ok = true →
    p.tsas.contains t.tsa = true → t.time ≤ o.now
  /-- CaIssuesOnlyVerifiedIdentity (FulcioIssuesOnlyToOidcSubject): a cert in
      the evidence that chains to a policy root carries identity that root
      verified. -/
  caHonest : ∀ e ∈ E, ∀ s ∈ e.sigs, ∀ c, s.cred = .cert c → ∀ r, c.chainsTo.contains r = true →
    p.roots.contains r = true → vouches r c

end CilockPolicy
