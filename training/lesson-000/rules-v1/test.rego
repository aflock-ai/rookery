package lesson.test

deny[msg] {
    not is_number(input.exitcode)
    msg := "no exit code recorded for the tests"
}

deny[msg] {
    input.exitcode != 0
    msg := sprintf("the tests failed (exit code %v)", [input.exitcode])
}
