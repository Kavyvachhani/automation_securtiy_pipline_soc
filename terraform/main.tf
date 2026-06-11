terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS Region"
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  default     = "production"
}

# ─── S3 VAULT ─────────────────────────────────────────────────
resource "aws_s3_bucket" "devsecops_vault" {
  bucket = "devsecops-results-vault-kavy-soc-2026"
  tags = {
    Name        = "DevSecOps Security Vault"
    Environment = var.environment
    Purpose     = "SOC2 Evidence Storage"
  }
}

resource "aws_s3_bucket_public_access_block" "vault_block" {
  bucket                  = aws_s3_bucket.devsecops_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "vault_versioning" {
  bucket = aws_s3_bucket.devsecops_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault_sse" {
  bucket = aws_s3_bucket.devsecops_vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "vault_lifecycle" {
  bucket = aws_s3_bucket.devsecops_vault.id
  rule {
    id     = "expire-old-scans"
    status = "Enabled"
    filter {
      prefix = "scans/"
    }
    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
  rule {
    id     = "expire-reports"
    status = "Enabled"
    filter {
      prefix = "reports/"
    }
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
    expiration {
      days = 730
    }
  }
}

# ─── DYNAMODB — Findings & Trend History ──────────────────────
resource "aws_dynamodb_table" "scan_findings" {
  name           = "DevSecOps-ScanFindings"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "commit_sha"
  range_key      = "scan_timestamp"

  attribute {
    name = "commit_sha"
    type = "S"
  }
  attribute {
    name = "scan_timestamp"
    type = "S"
  }
  attribute {
    name = "branch"
    type = "S"
  }

  global_secondary_index {
    name            = "branch-timestamp-index"
    hash_key        = "branch"
    range_key       = "scan_timestamp"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl_expiry"
    enabled        = true
  }

  tags = {
    Name        = "DevSecOps Scan Findings"
    Environment = var.environment
    Purpose     = "SOC2 Audit Trail"
  }
}

# ─── IAM ROLE & POLICY ────────────────────────────────────────
resource "aws_iam_role" "lambda_exec_role" {
  name = "devsecops_lambda_role_kavy_soc_v2"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = {
    Name = "DevSecOps Lambda Execution Role"
  }
}

resource "aws_iam_policy" "lambda_policy" {
  name = "devsecops_lambda_policy_kavy_soc_v2"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:HeadObject"]
        Resource = [
          aws_s3_bucket.devsecops_vault.arn,
          "${aws_s3_bucket.devsecops_vault.arn}/*"
        ]
      },
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.scan_findings.arn,
          "${aws_dynamodb_table.scan_findings.arn}/index/*"
        ]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# ─── LAMBDA ───────────────────────────────────────────────────
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/lambda_function.zip"
}

resource "aws_lambda_function" "generate_report_lambda" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "DevSecOpsReportGenerator"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "generate_report.handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 600
  memory_size      = 1024

  environment {
    variables = {
      S3_BUCKET       = aws_s3_bucket.devsecops_vault.bucket
      DYNAMODB_TABLE  = aws_dynamodb_table.scan_findings.name
      ENVIRONMENT     = var.environment
    }
  }

  tags = {
    Name        = "DevSecOps Report Generator"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${aws_lambda_function.generate_report_lambda.function_name}"
  retention_in_days = 90
  tags = {
    Name = "DevSecOps Lambda Logs"
  }
}

# ─── OUTPUTS ──────────────────────────────────────────────────
output "s3_bucket_name" {
  value       = aws_s3_bucket.devsecops_vault.bucket
  description = "S3 bucket for scan results and reports (use as S3_VAULT_BUCKET secret)"
}

output "lambda_function_name" {
  value       = aws_lambda_function.generate_report_lambda.function_name
  description = "Lambda function name (use as LAMBDA_FUNCTION_NAME secret)"
}

output "dynamodb_table_name" {
  value       = aws_dynamodb_table.scan_findings.name
  description = "DynamoDB table for scan history and trend data"
}

output "s3_folder_structure" {
  value = {
    raw_scans   = "s3://${aws_s3_bucket.devsecops_vault.bucket}/scans/<commit-sha>/"
    pdf_reports = "s3://${aws_s3_bucket.devsecops_vault.bucket}/reports/<commit-sha>/"
  }
  description = "S3 folder structure for scan artifacts"
}
