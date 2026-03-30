# =============================================================================
# AWS Secrets Manager — API Keys
# =============================================================================

resource "aws_secretsmanager_secret" "api_keys" {
  name        = "${var.project_name}/${var.environment}/api-keys"
  description = "API keys for LLM providers, Zendesk, and webhook authentication"

  tags = {
    Name = "${var.project_name}-api-keys"
  }
}

# NOTE: The actual secret value must be set manually after deployment:
#
#   aws secretsmanager put-secret-value \
#     --secret-id pii-redaction-gateway/dev/api-keys \
#     --secret-string '{
#       "ANTHROPIC_API_KEY": "sk-ant-...",
#       "OPENAI_API_KEY": "sk-...",
#       "GEMINI_API_KEY": "AIza...",
#       "ZENDESK_SUBDOMAIN": "yourcompany",
#       "ZENDESK_EMAIL": "bot@yourcompany.com",
#       "ZENDESK_API_TOKEN": "...",
#       "WEBHOOK_SECRET": "your-secret-here"
#     }'
#
# This is intentional — secrets should never be stored in Terraform state files.
