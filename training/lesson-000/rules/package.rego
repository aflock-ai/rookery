package lesson.package

# Rule 3 (part): packaging finished cleanly. The other half of rule 3, that the
# package holds the exact binary the build produced, is "artifactsFrom" in the policy.
# Input: the command-run attestation from the "package" receipt.

deny[msg] {
    not has_exit_code
    msg := "no exit code recorded for packaging"
}

deny[msg] {
    has_exit_code
    input.exitcode != 0
    msg := sprintf("packaging failed (exit code %v)", [input.exitcode])
}

# Helper rule: `not has_exit_code` fires when the field is missing.
# Writing `not is_number(input.exitcode)` inside deny would never fire.
has_exit_code {
    is_number(input.exitcode)
}
