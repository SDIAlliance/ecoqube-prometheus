variable "workspace_iam_roles" {
  default = {
    dev = "arn:aws:iam::281741148394:role/ecoqube-github-integration-role"
  }
}

provider "aws" {
  region = "eu-central-1"
  # assume_role {
  #   role_arn     = var.workspace_iam_roles[var.env]
  #   session_name = "terraform_session"
  # }
}
