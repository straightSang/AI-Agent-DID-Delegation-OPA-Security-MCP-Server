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

# Challenge, requestId, 승인 토큰, 폐기 토큰을 모든 서버가 공유한다.
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

# 향후 중앙 원장 인덱스와 검색 메타데이터를 저장할 테이블이다.
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

# 서버 개인키가 애플리케이션 메모리로 나오지 않는 비대칭 서명 키다.
resource "aws_kms_key" "signing" {
  description              = "Agent Security approval and ledger signing"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30
  enable_key_rotation      = false
}

# Object Lock은 생성 시점에 활성화해야 하며 Versioning이 필수다.
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
