package lesson.build

# First draft, deliberately weak. Two problems, both found by the loop in
# part2-policy-loop.sh: `not is_number(input.exitcode)` inside deny never fires when the
# field is missing, and the policy built from these rules has no artifactsFrom.

deny[msg] {
    not is_number(input.exitcode)
    msg := "no exit code recorded for the build"
}

deny[msg] {
    input.exitcode != 0
    msg := sprintf("the build failed (exit code %v)", [input.exitcode])
}
