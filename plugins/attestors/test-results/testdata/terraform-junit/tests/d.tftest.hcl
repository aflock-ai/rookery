// jade:ring local

provider "unknownthing" {}

run "uses_unknown_provider" {
  command = plan
  variables {
    name = "e"
  }
}
