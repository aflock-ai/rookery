# product attestor

The `product` attestor records the files that exist in the working directory
after a `cilock run` step completes — that is, the *outputs* of whatever
command the step wrapped (`go build`, `pip install`, `npm install`, `cargo
build`, etc.). It is the canonical "what did this step produce" attestor and
sits at the bottom of the dependency stack for SBOM, SARIF, SLSA, and
behavioral analysis attestors which all walk the product set.

## Predicate types

| URI                                                | Status     | Subject shape           |
|----------------------------------------------------|------------|-------------------------|
| `https://aflock.ai/attestations/product/v0.2`      | **Current**| One `tree:products` subject (merkle root) |
| `https://aflock.ai/attestations/product/v0.1`      | Legacy     | One `file:<path>` / `dir:<path>` subject per product |
| `https://witness.dev/attestations/product/v0.1`    | Legacy alias | Aliased to v0.1 via `legacyAliases` |

Both `v0.1` and `v0.2` are registered. New attestations always use `v0.2`. The
`v0.1` registration exists solely so that historical attestations stored in
Archivista (or anywhere else) continue to deserialize and verify against the
subject set the original cilock run wrote into the DSSE statement.

## Why v0.2 — the per-file subject explosion

Through the v0.1 era, the product attestor emitted **one in-toto subject per
file** in the working directory after the step completed. For source-only
projects this is fine: a `go build` produces a binary or two, a `cargo build`
produces a target dir, etc. For *package installations* it is catastrophic:

| Step                          | Files    | v0.1 subjects |
|-------------------------------|---------:|--------------:|
| `pip install requests`        |    ~150  |          ~150 |
| `pip install litellm`         |  ~3,200  |        ~3,200 |
| `npm install lodash`          |    ~25   |           ~25 |
| `npm install next`            | ~29,000  |       ~29,000 |
| `cargo build` (mid-size crate)|  ~5,000  |        ~5,000 |

That last row is what broke us. Archivista's MySQL backend uses prepared
statements for bulk subject inserts, and MySQL caps prepared-statement
parameters at **65,535 per query**. ent's `BatchCreate` for the `Subject`
table emits 4 placeholders per row (`id`, `created_at`, `name`,
`statement_id`), so anything north of ~16,000 subjects in a single
statement gets rejected with:

```
Error 1390 (HY000): Prepared statement contains too many placeholders
```

Even when the count stays under the limit, the per-file model has other
problems:

- DSSE envelopes balloon to 10+ MB. The `next` attestation we hit was 10.6 MB
  on disk. That's slow to upload, slow to download, and chokes the frontend
  attestation viewer.
- Each scan stores `N` Subject + `N` SubjectDigest rows. At 30k files per
  scan and ~10k scans per day that is **600M rows/day** of metadata for the
  privilege of saying "this file existed."
- Anyone querying Archivista by subject gets back a wall of `file:` entries
  that are useless without the original predicate to give them context.
- The "subjects" concept in in-toto is meant for *cross-attestation linking*
  ("this thing here matches that thing there"). Per-file subjects abuse the
  field for what is really a content listing.

## v0.2 design — one merkle-root subject

In v0.2 the attestor emits exactly **one** subject:

```json
{
  "subject": [
    {
      "name": "tree:products",
      "digest": {
        "sha256": "9c6f...d3a1"
      }
    }
  ]
}
```

The digest is a deterministic merkle root over the set of products that
survive the `--include-glob` / `--exclude-glob` filters. The full per-file
list is *unchanged* — it still lives in the predicate JSON, where it is
gzip-compressed in transit and stored as a single rich JSON column rather
than being multiplied across SQL placeholders.

### Merkle algorithm

For each hash algorithm `algo` present in the product set:

```
h := hash.New(algo)
for _, name := range sortedProductNames {
    h.Write([]byte(name))
    h.Write([]byte{0})
    h.Write([]byte(productDigests[name][algo]))
    h.Write([]byte{0})
}
root[algo] = h.Sum(nil)
```

Properties:

- **Deterministic**: product names are sorted lexically before hashing, so
  Go map iteration order does not affect the result.
- **Portable**: file paths are normalized with
  `strings.ReplaceAll(name, "\\", "/")` before hashing — *not*
  `filepath.ToSlash`, which is OS-aware and would leave Windows backslashes
  alone on a Linux verifier. The merkle root is therefore the same
  regardless of which OS produced the attestation.
- **Sensitive to renames, adds, removes, and content changes**: NUL framing
  between `name` and `digest` prevents `("ab", "cd")` from colliding with
  `("a", "bcd")`. Tests cover all four mutation classes.
- **Verifiable from the predicate alone**: anyone with the predicate JSON
  can recompute the root and compare it against the subject digest. No
  external state is required.
- **Multi-algorithm**: if products were hashed with both sha256 and sha1,
  the tree subject's `DigestSet` contains a root for each, computed
  independently from the same product list.

### Subject name

The single subject is named `tree:products` rather than something like
`tree:<workdir>` because the workdir basename is not a stable identifier
across CI environments. Cross-attestation linking that needs to refer to a
specific tree should match on the digest, not the name.

### Empty product set

If the include/exclude globs select zero products (or the workdir is
empty), `Subjects()` returns an empty map — *not* a tree subject with the
empty hash. This matches v0.1 semantics: empty workdir → no subjects.

## Backwards compatibility

The v0.2 change is breaking on the wire (a verifier expecting `file:` subjects
will not find them in a v0.2 statement) but historical attestations remain
verifiable through the legacy registration:

1. The `v0.1` predicate type stays registered in `attestationsByType`.
2. Its factory constructs an `Attestor` with `legacyMode=true`.
3. `Subjects()` checks `legacyMode` and dispatches to `legacySubjects()`,
   which emits one `file:<path>` / `dir:<path>` subject per product —
   byte-for-byte identical to what v0.1 originally wrote.
4. The predicate JSON shape is unchanged between v0.1 and v0.2 (it has
   always been `map[path]Product`), so `UnmarshalJSON` works for either
   version without modification.

`FactoryByName("product")` continues to return the **modern** attestor —
the legacy factory is reachable only by explicit `FactoryByType(v0.1)`
lookups. Users invoking the attestor by name from CLI flags, presets, or
go-witness libraries will always get the v0.2 behavior. They cannot
accidentally produce a v0.1 attestation.

`WithLegacyMode()` is exported but documented as "do not use for new
attestations" — it exists for the registry plumbing and for tests.

## Verification semantics

A verifier loading a v0.2 attestation should:

1. Decode the DSSE envelope and statement.
2. Recompute the merkle root from the predicate's product map (using the
   algorithm above).
3. Compare against `statement.subject[0].digest`.
4. If they match, the predicate has not been tampered with — all listed
   files exist with the listed digests at the time the attestor ran.

For per-file granular verification (e.g. "did `node_modules/foo/bar.js`
have digest X"), the verifier reads the predicate's product map directly.
The merkle root acts as a cryptographic seal over the entire list, so any
tampering — even removing or renaming a single file — fails verification.

## Configuration

| Flag                | Default | Effect                                                  |
|---------------------|---------|---------------------------------------------------------|
| `--include-glob`    | `*`     | Only files matching this glob are recorded as products |
| `--exclude-glob`    | (empty) | Files matching this glob are dropped from products     |

Both glob filters apply at `RecordArtifacts` time, so they affect the
products map *and* the merkle root. The glob is matched against the
forward-slash-normalized relative path inside the working directory.

## Related work

- The [SBOM attestor](../sbom/) and [SARIF attestor](../sarif/) walk the
  product map directly — they are unaffected by the v0.2 subject change.
- The [SLSA provenance attestor](../slsa/) reads products to populate its
  `subject` field; it gets the new tree subject automatically.
- The [omnitrail attestor](../omnitrail/) records dirhash trees at finer
  granularity for cases where per-file integrity is needed without paying
  the per-file subject cost.

## Tests

See `product_test.go` and `product_v02_test.go`. The v0.2 suite covers:

- Single tree subject in default mode (V02_001)
- Merkle root matches a hand-computed sha256 reference (V02_002)
- Determinism across 20 fresh runs of the same input (V02_003)
- Renames, content edits, and additions all change the root (V02_004 – V02_006)
- Empty workdir / exclude-everything produce zero subjects (V02_007 – V02_008)
- Nil-glob safety (V02_009)
- JSON predicate roundtrip preserves products and reproduces the root (V02_010 – V02_011)
- Legacy mode emits per-file `file:` subjects with matching digests (V02_012 – V02_013)
- Both v0.1 and v0.2 predicate types are registered, with the modern one
  reachable by name and the legacy one only by type lookup (V02_014 – V02_015)
- Version-bump constants did not regress (V02_016)
- 5,000-file regression test for the original Archivista bug (V02_017)
- Path normalization is identical across `/` and `\` separators (V02_018)
- Legacy mode still respects include/exclude globs (V02_019)
