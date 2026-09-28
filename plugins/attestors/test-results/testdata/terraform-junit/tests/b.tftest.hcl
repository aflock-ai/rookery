// jade:ring local

run "errors" {
  command = plan
  variables {
    name = file("does-not-exist.txt")
  }
}

run "after_error" {
  command = plan
  variables {
    name = "c"
  }
}
