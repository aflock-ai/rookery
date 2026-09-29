package lesson.test

# Rule 2: the tests ran and passed.
# Input: the command-run attestation from the "test" receipt.

deny[msg] {
    not has_exit_code
    msg := "no exit code recorded for the tests"
}

deny[msg] {
    has_exit_code
    input.exitcode != 0
    msg := sprintf("the tests failed (exit code %v)", [input.exitcode])
}

# Helper rule: `not has_exit_code` fires when the field is missing.
# Writing `not is_number(input.exitcode)` inside deny would never fire.
has_exit_code {
    is_number(input.exitcode)
}
