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

resource "aws_s3_bucket" "devsecops_vault" {
  bucket = "devsecops-results-vault-kavy-soc-2026"
}

resource "aws_s3_bucket_public_access_block" "devsecops_vault_block" {
  bucket = aws_s3_bucket.devsecops_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "lambda_exec_role" {
  name = "devsecops_lambda_role_kavy_soc"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "lambda_s3_policy" {
  name = "devsecops_lambda_s3_policy_kavy_soc"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          aws_s3_bucket.devsecops_vault.arn,
          "${aws_s3_bucket.devsecops_vault.arn}/*"
        ]
      },
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_s3_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_s3_policy.arn
}

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
  runtime          = "python3.10"
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      S3_BUCKET = aws_s3_bucket.devsecops_vault.bucket
    }
  }
}

output "s3_bucket_name" {
  value = aws_s3_bucket.devsecops_vault.bucket
}

output "lambda_function_name" {
  value = aws_lambda_function.generate_report_lambda.function_name
}
