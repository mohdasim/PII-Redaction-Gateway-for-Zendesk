# =============================================================================
# CloudWatch Logging, Dashboard, and Alarms
# =============================================================================

# Log groups
resource "aws_cloudwatch_log_group" "webhook" {
  name              = "/aws/lambda/${var.project_name}-webhook-${var.environment}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "health" {
  name              = "/aws/lambda/${var.project_name}-health-${var.environment}"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "api_gateway" {
  name              = "/aws/apigateway/${var.project_name}-${var.environment}"
  retention_in_days = 30
}

# Dashboard
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", "${var.project_name}-webhook-${var.environment}"],
            ["AWS/Lambda", "Errors", "FunctionName", "${var.project_name}-webhook-${var.environment}"],
            ["AWS/Lambda", "Throttles", "FunctionName", "${var.project_name}-webhook-${var.environment}"],
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "Webhook Lambda — Invocations / Errors / Throttles"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", "${var.project_name}-webhook-${var.environment}", { stat = "Average" }],
            ["AWS/Lambda", "Duration", "FunctionName", "${var.project_name}-webhook-${var.environment}", { stat = "p99" }],
          ]
          period = 300
          region = var.aws_region
          title  = "Webhook Lambda — Duration (avg / p99)"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApiGateway", "Count", "ApiName", "${var.project_name}-${var.environment}"],
            ["AWS/ApiGateway", "4XXError", "ApiName", "${var.project_name}-${var.environment}"],
            ["AWS/ApiGateway", "5XXError", "ApiName", "${var.project_name}-${var.environment}"],
          ]
          period = 300
          stat   = "Sum"
          region = var.aws_region
          title  = "API Gateway — Requests / 4xx / 5xx"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApiGateway", "Latency", "ApiName", "${var.project_name}-${var.environment}", { stat = "Average" }],
            ["AWS/ApiGateway", "Latency", "ApiName", "${var.project_name}-${var.environment}", { stat = "p99" }],
          ]
          period = 300
          region = var.aws_region
          title  = "API Gateway — Latency (avg / p99)"
        }
      },
    ]
  })
}

# Error Alarm
resource "aws_cloudwatch_metric_alarm" "webhook_errors" {
  alarm_name          = "${var.project_name}-webhook-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Triggers when the webhook Lambda has more than 5 errors in 5 minutes"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.webhook.function_name
  }

  alarm_actions = var.alarm_email != "" ? [aws_sns_topic.alarms[0].arn] : []
}

# Duration Alarm (approaching timeout)
resource "aws_cloudwatch_metric_alarm" "webhook_duration" {
  alarm_name          = "${var.project_name}-webhook-duration-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Duration"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "p99"
  threshold           = var.lambda_timeout * 1000 * 0.8 # 80% of timeout
  alarm_description   = "Triggers when p99 duration exceeds 80% of Lambda timeout"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.webhook.function_name
  }

  alarm_actions = var.alarm_email != "" ? [aws_sns_topic.alarms[0].arn] : []
}

# SNS Topic for alarms (only created if alarm_email is set)
resource "aws_sns_topic" "alarms" {
  count = var.alarm_email != "" ? 1 : 0
  name  = "${var.project_name}-alarms-${var.environment}"
}

resource "aws_sns_topic_subscription" "alarm_email" {
  count     = var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alarms[0].arn
  protocol  = "email"
  endpoint  = var.alarm_email
}
