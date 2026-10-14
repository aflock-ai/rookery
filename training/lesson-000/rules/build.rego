package lesson.build

# Rule 1: the build step ran and finished cleanly.
# Input: the command-run attestation from the "build" receipt.

deny[msg] {
    not has_exit_code
    msg := "no exit code recorded for the build"
}

deny[msg] {
    has_exit_code
    input.exitcode != 0
    msg := sprintf("the build failed (exit code %v)", [input.exitcode])
}

# Helper rule: `not has_exit_code` fires when the field is missing.
# Writing `not is_number(input.exitcode)` inside deny would never fire.
has_exit_code {
    is_number(input.exitcode)
}
