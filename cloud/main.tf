terraform {
  required_version = ">= 0.9.3"
  backend "s3" {}
}

provider "aws" {}

data "aws_region" "current" {
  current = true
}

module "ecr" {
  source = "github.com/agilestacks/terraform-modules//ecr"
  name   = "agilestacks/${var.name}.${var.base_domain}/secrets-service"
}

