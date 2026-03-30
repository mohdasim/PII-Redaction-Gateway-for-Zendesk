variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "pii-redaction-gateway"
}

variable "log_level" {
  description = "Application log level"
  type        = string
  default     = "INFO"

  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], var.log_level)
    error_message = "Log level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL."
  }
}

variable "llm_provider" {
  description = "Primary LLM provider for PII detection"
  type        = string
  default     = "claude"

  validation {
    condition     = contains(["claude", "openai", "gemini"], var.llm_provider)
    error_message = "LLM provider must be one of: claude, openai, gemini."
  }
}

variable "llm_enabled" {
  description = "Enable LLM-based PII detection (Layer 2). Set to false for regex-only mode."
  type        = bool
  default     = true
}

variable "audit_retention_days" {
  description = "Number of days to retain audit logs in S3 before expiration"
  type        = number
  default     = 90
}

variable "audit_glacier_transition_days" {
  description = "Number of days before transitioning audit logs to Glacier storage"
  type        = number
  default     = 30
}

variable "lambda_memory_size" {
  description = "Lambda function memory in MB"
  type        = number
  default     = 512
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

variable "redaction_style" {
  description = "Redaction style: bracket ([REDACTED-SSN]) or mask (****)"
  type        = string
  default     = "bracket"

  validation {
    condition     = contains(["bracket", "mask"], var.redaction_style)
    error_message = "Redaction style must be 'bracket' or 'mask'."
  }
}

variable "enabled_pii_types" {
  description = "Comma-separated list of PII types to detect"
  type        = string
  default     = "SSN,CREDIT_CARD,EMAIL,PHONE,PASSWORD,PHI,ADDRESS,NAME,DATE_OF_BIRTH"
}

variable "alarm_email" {
  description = "Email address for CloudWatch alarm notifications (optional)"
  type        = string
  default     = ""
}
