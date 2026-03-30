terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # Uncomment and configure for remote state storage:
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "pii-redaction-gateway/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "pii-redaction-gateway"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Data source for current AWS account and region
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
