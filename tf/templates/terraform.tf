terraform {
  backend "s3" {
    encrypt        = true
    bucket         = "ecoqube-tf-state-bucket"
    dynamodb_table = "ecoqube-tf-state-lock-table"
    region         = "eu-central-1"
    key            = "terraform.state"
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.59.0"
    }
  }
}
