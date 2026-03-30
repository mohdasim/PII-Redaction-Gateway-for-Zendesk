output "webhook_url" {
  description = "URL for Zendesk webhook configuration"
  value       = "${aws_api_gateway_stage.prod.invoke_url}/webhook"
}

output "health_url" {
  description = "Health check endpoint URL"
  value       = "${aws_api_gateway_stage.prod.invoke_url}/health"
}

output "audit_s3_bucket" {
  description = "S3 bucket name for audit logs"
  value       = aws_s3_bucket.audit.id
}

output "webhook_lambda_arn" {
  description = "ARN of the webhook Lambda function"
  value       = aws_lambda_function.webhook.arn
}

output "health_lambda_arn" {
  description = "ARN of the health check Lambda function"
  value       = aws_lambda_function.health.arn
}

output "api_gateway_id" {
  description = "API Gateway REST API ID"
  value       = aws_api_gateway_rest_api.main.id
}

output "secrets_arn" {
  description = "ARN of the Secrets Manager secret (populate after deployment)"
  value       = aws_secretsmanager_secret.api_keys.arn
}
