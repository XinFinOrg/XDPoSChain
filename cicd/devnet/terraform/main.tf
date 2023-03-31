terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

# Default
provider "aws" {
  region  = "us-east-1"
}

provider "aws" {
  alias = "us-east-2"
  region  = "us-east-2"
}

module "us-east-2" {
  source = "./module/region"
  availability_zone = "us-east-2a"
  region = "us-east-2"
  devnetNodeKeys = local.devnetNodeKeys["us-east-2"]
  logLevel = local.logLevel
  devnet_xdc_ecs_tasks_execution_role_arn = aws_iam_role.devnet_xdc_ecs_tasks_execution_role.arn

  providers = {
    aws = aws.us-east-2
  }
}

provider "aws" {
  alias = "eu-west-1"
  region  = "eu-west-1"
}

module "eu-west-1" {
  source = "./module/region"
  availability_zone = "eu-west-1a"
  region = "eu-west-1"
  devnetNodeKeys = local.devnetNodeKeys["eu-west-1"]
  logLevel = local.logLevel
  devnet_xdc_ecs_tasks_execution_role_arn = aws_iam_role.devnet_xdc_ecs_tasks_execution_role.arn

  providers = {
    aws = aws.eu-west-1
  }
}

provider "aws" {
  alias = "sa-east-1"
  region  = "sa-east-1"
}

module "sa-east-1" {
  source = "./module/region"
  availability_zone = "sa-east-1a"
  region = "sa-east-1"
  devnetNodeKeys = local.devnetNodeKeys["sa-east-1"]
  logLevel = local.logLevel
  devnet_xdc_ecs_tasks_execution_role_arn = aws_iam_role.devnet_xdc_ecs_tasks_execution_role.arn

  providers = {
    aws = aws.sa-east-1
  }
}

provider "aws" {
  alias = "ap-northeast-1"
  region  = "ap-northeast-1"
}

module "ap-northeast-1" {
  source = "./module/region"
  availability_zone = "ap-northeast-1a"
  region = "ap-northeast-1"
  devnetNodeKeys = local.devnetNodeKeys["ap-northeast-1"]
  logLevel = local.logLevel
  devnet_xdc_ecs_tasks_execution_role_arn = aws_iam_role.devnet_xdc_ecs_tasks_execution_role.arn

  providers = {
    aws = aws.ap-northeast-1
  }
}

provider "aws" {
  alias = "ap-southeast-2"
  region  = "ap-southeast-2"
}

module "ap-southeast-2" {
  source = "./module/region"
  availability_zone = "ap-southeast-2a"
  region = "ap-southeast-2"
  devnetNodeKeys = local.devnetNodeKeys["ap-southeast-2"]
  logLevel = local.logLevel
  devnet_xdc_ecs_tasks_execution_role_arn = aws_iam_role.devnet_xdc_ecs_tasks_execution_role.arn

  providers = {
    aws = aws.ap-southeast-2
  }
}
