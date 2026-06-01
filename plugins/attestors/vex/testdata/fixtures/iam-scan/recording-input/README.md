# recording-input (vex / iam-scan)

vexctl `create` synthesizes the OpenVEX document from command-line flags and
needs NO input files and NO credentials, so this directory is intentionally
empty apart from this note. The live re-run gate copies this tree into the
record workdir and re-runs the recorded argv (see ../record.sh); the argv is
fully self-contained, which is why this fixture is live-rerunnable.
