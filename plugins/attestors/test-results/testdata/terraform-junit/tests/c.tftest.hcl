// jade:ring local

run "bad_reference" {
  command = plan
  variables {
    name = "d"
  }
  assert {
    condition     = terraform_data.nope.input == "d"
    error_message = "unreachable"
  }
}
