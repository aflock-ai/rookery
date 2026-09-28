// jade:ring local

run "passes" {
  command = plan
  variables {
    name = "a"
  }
  assert {
    condition     = terraform_data.x.input == "a"
    error_message = "input"
  }
}

run "fails" {
  command = plan
  variables {
    name = "b"
  }
  assert {
    condition     = terraform_data.x.input == "not-b"
    error_message = "deliberate assertion failure"
  }
}
