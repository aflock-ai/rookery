# alps-evidence — live reproduction

`alps-evidence` observes the live process ancestry around a cilock run. There
is no stable artifact that the catalog fixture harness can replay: PIDs,
ancestry, executable paths, versions, agent configuration, and visibility all
belong to the current machine and invocation.

Run `./reproduce.sh` from a supported coding agent. It builds the canonical
cilock binary from this tree, signs one offline test collection with an
ephemeral key, and validates the decoded `alps-evidence` predicate. The key and
output live in a temporary directory and are removed when the script exits.

A supported agent normally yields `status: detected`. A terminal can truthfully
yield `not-detected`, and an unsupported platform yields `unavailable`. All are
valid observations. The invariant the script enforces is that the predicate is
present, uses the closed status vocabulary, and says `enforcement: false`.

This example is proof that the live producer is wired and runnable. It is not
proof of agent identity: the observed process can forge every descriptive
field. The signing principal, human presence, and policy decision are separate
contracts.
