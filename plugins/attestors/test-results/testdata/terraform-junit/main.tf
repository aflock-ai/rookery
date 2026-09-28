variable "name" {
  type = string
}

resource "terraform_data" "x" {
  input = var.name
}

output "name" {
  value = terraform_data.x.input
}
