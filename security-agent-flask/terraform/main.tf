data "aws_caller_identity" "current" {}

data "aws_s3_bucket" "artifacts" {
  bucket = var.artifacts_bucket
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  ec2_arn    = "arn:aws:ec2:${var.region}:${local.account_id}"

  tags = [for k, v in var.tags : { key = k, value = v }]

  # aws_resources.vpcs e pentest.vpc_config pedem ARN, nao ID.
  vpcs = var.vpc_config == null ? [] : [{
    vpc_arn             = "${local.ec2_arn}:vpc/${var.vpc_config.vpc_id}"
    subnet_arns         = [for s in var.vpc_config.subnet_ids : "${local.ec2_arn}:subnet/${s}"]
    security_group_arns = [for g in var.vpc_config.security_group_ids : "${local.ec2_arn}:security-group/${g}"]
  }]

  artifacts = { for a in var.artifacts : coalesce(a.file_name != "" ? a.file_name : null, basename(a.path)) => a }

  actors = { for a in var.actors : a.identifier => a }
}
