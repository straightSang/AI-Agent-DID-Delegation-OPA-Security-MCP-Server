terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "project_name" {
  type    = string
  default = "agent-security"
}

variable "anchor_retention_days" {
  type    = number
  default = 365
}

# All servers share Challenge, requestId, approval-token, and revocation state.
resource "aws_dynamodb_table" "security_state" {
  name         = "${var.project_name}-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "namespace"
  range_key    = "stateKey"

  attribute { name = "namespace" type = "S" }
  attribute { name = "stateKey" type = "S" }

  ttl {
    attribute_name = "expiresAt"
    enabled        = true
  }

  point_in_time_recovery { enabled = true }
  server_side_encryption { enabled = true }
}

# Table reserved for central ledger indexes and search metadata.
resource "aws_dynamodb_table" "audit" {
  name         = "${var.project_name}-audit"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "instanceId"
  range_key    = "sequence"

  attribute { name = "instanceId" type = "S" }
  attribute { name = "sequence" type = "N" }

  point_in_time_recovery { enabled = true }
  server_side_encryption { enabled = true }
}

# Asymmetric signing key whose private material never enters application memory.
resource "aws_kms_key" "signing" {
  description              = "Agent Security approval and ledger signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30
  enable_key_rotation      = false
}

# Object Lock must be enabled at bucket creation and requires versioning.
resource "aws_s3_bucket" "anchors" {
  bucket_prefix       = "${var.project_name}-anchors-"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "anchors" {
  bucket = aws_s3_bucket.anchors.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "anchors" {
  bucket = aws_s3_bucket.anchors.id
  depends_on = [aws_s3_bucket_versioning.anchors]

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.anchor_retention_days
    }
  }
}

resource "aws_s3_bucket_public_access_block" "anchors" {
  bucket                  = aws_s3_bucket.anchors.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

output "security_state_table" { value = aws_dynamodb_table.security_state.name }
output "audit_table"          { value = aws_dynamodb_table.audit.name }
output "anchor_bucket"        { value = aws_s3_bucket.anchors.bucket }
output "kms_key_id"           { value = aws_kms_key.signing.key_id }
