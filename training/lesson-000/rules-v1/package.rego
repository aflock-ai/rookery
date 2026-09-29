package lesson.package

deny[msg] {
    not is_number(input.exitcode)
    msg := "no exit code recorded for packaging"
}

deny[msg] {
    input.exitcode != 0
    msg := sprintf("packaging failed (exit code %v)", [input.exitcode])
}
