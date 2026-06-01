#!/usr/bin/env bash
# Records the single-commit git fixture from a REAL `git init` + one commit.
#
# The git attestor is PreMaterial: it opens a .git directory with go-git
# (DetectDotGit) and reads the HEAD commit, refs, and worktree status. To prove
# its contract hermetically we capture an actual tiny repo as the workdir input.
#
# Storage trick: a real `.git/` cannot be committed inside THIS repo (git ignores
# nested .git directories), so the captured repo's metadata is stored under
# dot-git/ and the testkit workdir materializer renames dot-git/ -> .git/ when it
# stages the tree for the attestor.
#
# Determinism: the commit SHA is pinned by fixing the author/committer dates and
# the synthetic identity below, so re-running this reproduces the SAME commit
# hash (041a7e649121fe0f6e99da05c573bb9512b4980c) and the fixture's asserted
# commithash subject does not drift.
#
# Topology is synthetic and PUBLIC-OK: no remote, no real author, no secrets.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$work"
git init -q -b main .
git config user.name "Rookery Catalog Test"
git config user.email "catalog-test@aflock.ai"
git config commit.gpgsign false
printf 'rookery git attestor fixture\n' > README.md
git add README.md
GIT_AUTHOR_DATE="2026-05-23T00:00:00 +0000" \
GIT_COMMITTER_DATE="2026-05-23T00:00:00 +0000" \
  git commit -q -m "seed: rookery git attestor catalog fixture"

echo "recorded commit: $(git rev-parse HEAD)"

# Stage only what the attestor reads (objects/refs/HEAD/config/index) — drop
# hooks/, logs/, COMMIT_EDITMSG, description, info/ to keep the fixture minimal.
rm -rf "$here/dot-git" "$here/README.md"
mkdir -p "$here/dot-git"
cp -R .git/objects .git/refs .git/HEAD .git/index "$here/dot-git/"
printf '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n' > "$here/dot-git/config"
cp README.md "$here/README.md"

echo "wrote fixture under: $here"
