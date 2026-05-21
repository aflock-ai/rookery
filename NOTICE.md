# Third-Party Notices

This file lists upstream projects from which rookery has inlined code, types,
schemas, or fixtures. Maintenance of this file is enforced by CI — see
`.provenance/README.md` and `scripts/check-provenance.sh`.

Each entry below corresponds to one or more files in `.provenance/`, which
record the exact commit SHA + upstream URL + license used at the time of
inlining. CI re-fetches the upstream content on every PR and verifies the
SHA256 still matches.

## Why this file exists

rookery is a security-tooling library; users need to be able to audit every
byte. Inlining upstream code without provenance creates legal and operational
debt that compounds invisibly. The policy here is intentionally strict so
that audit-time discovery is impossible.

Tracking issue: [#72](https://github.com/aflock-ai/rookery/issues/72).

## Current upstreams

_Nothing inlined yet._ Entries are added as part of the PR that performs the
inlining. See `.provenance/README.md` for the format.

When entries land here, group them by upstream:

```
### <upstream-org/repo> — <license>

- `<local/path/to/file.go>` derives from `<upstream/path>` at
  commit `<sha>`. See `.provenance/<entry>.json`.
```

## License compatibility

rookery is Apache-2.0. We only inline from upstreams whose licenses permit
redistribution under Apache-2.0:

| Upstream license | Compatible? | Attribution required |
|---|---|---|
| Apache-2.0 | yes | yes — preserve `LICENSE` header + `NOTICE` |
| MIT | yes | yes — preserve copyright notice |
| BSD-2-Clause / BSD-3-Clause | yes | yes — preserve copyright + license |
| ISC | yes | yes — preserve copyright + license |
| MPL-2.0 | no — file-level copyleft; do not inline | — |
| GPL / LGPL | no | — |
| Unknown / no license | no | — |

Any PR that inlines from an incompatible-license upstream will fail
`provenance-check` because the entry's `license_spdx` value will not match
the allowlist.
