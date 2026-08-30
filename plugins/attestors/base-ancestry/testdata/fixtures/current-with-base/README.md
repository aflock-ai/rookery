# current-with-base fixture

A real repository, not a hand-authored sample. Produced with the system `git`
and pinned dates so the hashes never drift:

```
git init -q -b feature .
git config user.name "Rookery Catalog Test"
git config user.email "catalog-test@aflock.ai"
git config commit.gpgsign false
printf 'rookery base-ancestry attestor fixture\n' > README.md
git add README.md
GIT_AUTHOR_DATE="2026-08-27T00:00:00 +0000" GIT_COMMITTER_DATE="2026-08-27T00:00:00 +0000" \
  git commit -q -m "seed: base commit"                       # 2d10d913…
git update-ref refs/remotes/origin/main "$(git rev-parse HEAD)"
git symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/main
printf 'a change built on the base\n' > CHANGE.md
git add CHANGE.md
GIT_AUTHOR_DATE="2026-08-27T00:01:00 +0000" GIT_COMMITTER_DATE="2026-08-27T00:01:00 +0000" \
  git commit -q -m "feature: one commit on top of the base"  # fbe0ea22…
```

The objects were then PACKED before capture:

```
git repack -a -d -q && git prune-packed
rm -f .git/objects/pack/*.rev && rm -rf .git/objects/info   # git-version-specific
```

and `.git/{objects,refs,HEAD,index}` were copied to `dot-git/` with a minimal
`config` (no remote URL, so the predicate carries no `remotes`), and the two
working-tree files beside it. Topology is synthetic and public-safe.

Pack, not loose, and that is load-bearing. Git decides text-vs-binary by looking
for a NUL byte in the first 8000; a small loose object is a zlib stream that may
contain none, in which case git calls it TEXT and inlines its raw deflate bytes
into any diff. Those bytes are not valid UTF-8, and `codex exec` — which the AI
review pipeline feeds the PR diff on stdin — rejects the ENTIRE prompt on the
first one:

    Failed to read prompt from stdin: input is not valid UTF-8

The reviewer then reports "produced no output", the PR is marked INCOMPLETE, and
because INCOMPLETE buckets as a *passing* check the PR looks healthy while being
unable to earn the approval it needs to merge. Measured on #8407: object
`fb/e0ea22…` was the only NUL-free one, and contributed all 75 invalid bytes in
the diff. A packfile always carries NULs, so it is unambiguously binary.

Note `.gitattributes` cannot fix this: GitHub renders the PR diff server-side and
the review job classifies against the DEFAULT BRANCH, so a `binary` attribute on
the PR's own branch does not change the bytes the reviewer receives (measured —
the same error recurred at a shifted offset). Only the committed bytes matter.

What it proves: with no `--base-ref`, the attestor reads the base from the
remote's recorded HEAD, resolves it through `refs/remotes/origin/main`, finds
the merge-base equal to that base, and records `relationship: current`.
