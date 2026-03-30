# =============================================================================
# Lambda Functions + IAM
# =============================================================================

# IAM Role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "${var.project_name}-lambda-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# CloudWatch Logs policy
resource "aws_iam_role_policy" "lambda_logging" {
  name = "${var.project_name}-logging"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}

# S3 audit bucket policy
resource "aws_iam_role_policy" "lambda_s3" {
  name = "${var.project_name}-s3-audit"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.audit.arn}/*"
      },
      {
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.audit.arn
      }
    ]
  })
}

# Secrets Manager policy
resource "aws_iam_role_policy" "lambda_secrets" {
  name = "${var.project_name}-secrets"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = aws_secretsmanager_secret.api_keys.arn
      }
    ]
  })
}

# Package Lambda code
data "archive_file" "lambda_package" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/../lambda_package.zip"
}

# Webhook Handler Lambda
resource "aws_lambda_function" "webhook" {
  function_name    = "${var.project_name}-webhook-${var.environment}"
  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256
  handler          = "handlers.webhook_handler.lambda_handler"
  runtime          = "python3.12"
  role             = aws_iam_role.lambda_role.arn
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout

  layers = [aws_lambda_layer_version.dependencies.arn]

  environment {
    variables = {
      LOG_LEVEL          = var.log_level
      LLM_PROVIDER       = var.llm_provider
      LLM_ENABLED        = tostring(var.llm_enabled)
      REDACTION_STYLE    = var.redaction_style
      ENABLED_PII_TYPES  = var.enabled_pii_types
      AUDIT_S3_BUCKET    = aws_s3_bucket.audit.id
      SECRETS_ARN        = aws_secretsmanager_secret.api_keys.arn
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.webhook,
  ]
}

# Health Check Lambda
resource "aws_lambda_function" "health" {
  function_name    = "${var.project_name}-health-${var.environment}"
  filename         = data.archive_file.lambda_package.output_path
  source_code_hash = data.archive_file.lambda_package.output_base64sha256
  handler          = "handlers.health_handler.lambda_handler"
  runtime          = "python3.12"
  role             = aws_iam_role.lambda_role.arn
  memory_size      = 128
  timeout          = 5

  environment {
    variables = {
      LOG_LEVEL = var.log_level
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.health,
  ]
}

# Lambda Layer for Python dependencies
resource "aws_lambda_layer_version" "dependencies" {
  layer_name          = "${var.project_name}-deps-${var.environment}"
  filename            = "${path.module}/../lambda_layer.zip"
  compatible_runtimes = ["python3.12"]
  description         = "Python dependencies for PII Redaction Gateway"

  lifecycle {
    create_before_destroy = true
  }
}

# Lambda permissions for API Gateway
resource "aws_lambda_permission" "webhook_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.webhook.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}

resource "aws_lambda_permission" "health_apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.health.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.main.execution_arn}/*/*"
}
