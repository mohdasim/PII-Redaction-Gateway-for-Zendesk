# Setup Guide — PII Redaction Gateway for Zendesk

Step-by-step instructions to deploy and configure the PII Redaction Gateway.

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| AWS CLI | >= 2.x | [Install Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) |
| Terraform | >= 1.5.0 | [Install Guide](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) |
| Python | >= 3.11 | [python.org](https://www.python.org/downloads/) |
| pip | latest | Included with Python |

You also need:
- An **AWS account** with permissions to create Lambda, API Gateway, S3, Secrets Manager, CloudWatch, and IAM resources
- A **Zendesk account** with Admin access (to configure webhooks and triggers)
- At least one **LLM API key** (Anthropic Claude recommended; OpenAI or Gemini as alternatives)

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/mohdasim/PII-Redaction-Gateway-for-Zendesk.git
cd PII-Redaction-Gateway-for-Zendesk
```

## Step 2: Configure AWS Credentials

```bash
aws configure
# Enter your AWS Access Key ID, Secret Access Key, region (e.g., us-east-1)

# Verify
aws sts get-caller-identity
```

## Step 3: Configure Terraform Variables

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
```

Edit `terraform/terraform.tfvars`:
```hcl
aws_region   = "us-east-1"
environment  = "prod"
llm_provider = "claude"
llm_enabled  = true

# Optional: email for CloudWatch alarm notifications
alarm_email = "your-team@company.com"
```

## Step 4: Deploy Infrastructure

```bash
# Option A: Use the deploy script
./scripts/deploy.sh apply

# Option B: Manual steps
cd terraform

# Initialize Terraform (downloads providers)
terraform init

# Preview changes
terraform plan

# Deploy
terraform apply
```

Note the outputs:
```
webhook_url   = "https://xxxxx.execute-api.us-east-1.amazonaws.com/prod/webhook"
health_url    = "https://xxxxx.execute-api.us-east-1.amazonaws.com/prod/health"
audit_s3_bucket = "pii-redaction-gateway-audit-prod-123456789012"
```

## Step 5: Store API Secrets

After deployment, store your API keys in Secrets Manager:

```bash
aws secretsmanager put-secret-value \
  --secret-id pii-redaction-gateway/prod/api-keys \
  --secret-string '{
    "ANTHROPIC_API_KEY": "sk-ant-your-key-here",
    "OPENAI_API_KEY": "sk-your-openai-key",
    "GEMINI_API_KEY": "AIza-your-gemini-key",
    "ZENDESK_SUBDOMAIN": "yourcompany",
    "ZENDESK_EMAIL": "bot@yourcompany.com",
    "ZENDESK_API_TOKEN": "your-zendesk-api-token",
    "WEBHOOK_SECRET": "generate-a-strong-random-secret"
  }'
```

Generate a strong webhook secret:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Step 6: Verify Deployment

```bash
# Health check
curl https://xxxxx.execute-api.us-east-1.amazonaws.com/prod/health

# Expected response:
# {"status": "healthy", "service": "pii-redaction-gateway", "version": "1.0.0"}
```

## Step 7: Configure Zendesk Webhook

1. Log in to **Zendesk Admin Center**
2. Go to **Apps and integrations** > **Webhooks** > **Create webhook**
3. Configure:
   - **Name**: PII Redaction Gateway
   - **Endpoint URL**: `https://xxxxx.execute-api.us-east-1.amazonaws.com/prod/webhook`
   - **Request method**: POST
   - **Request format**: JSON
   - **Authentication**: API key
     - **Header name**: `X-API-Key`
     - **Value**: The webhook secret you generated in Step 5
4. Click **Create webhook**

## Step 8: Find Your Bot User ID

The gateway uses the bot's Zendesk user ID to prevent infinite webhook loops (when the bot updates a ticket, the webhook fires again — the bot ID check skips its own updates).

1. In Zendesk Admin Center, go to **People** > search for the API bot user
2. Open the user profile — the **user ID** is in the URL: `https://yourcompany.zendesk.com/agent/users/{USER_ID}`
3. Add this to your Secrets Manager or Lambda environment variables as `ZENDESK_BOT_USER_ID`

> **If you skip this step**, the gateway falls back to detecting its own internal notes via pattern matching, which is less reliable.

## Step 9: Create Zendesk Triggers

You need **two triggers** — one for ticket creation, one for ticket updates.

### Trigger 1: Ticket Created

1. In Zendesk Admin Center, go to **Objects and rules** > **Business rules** > **Triggers**
2. Click **Create trigger**
3. Configure:
   - **Name**: PII Redaction on Ticket Create
   - **Conditions** (Meet ALL):
     - Ticket: Is Created
     - Tags: Does not contain `pii-redaction-in-progress`
   - **Actions**:
     - Notify webhook: PII Redaction Gateway
     - JSON body:
       ```json
       {
         "event_type": "ticket.created",
         "ticket": {
           "id": "{{ticket.id}}",
           "subject": "{{ticket.title}}",
           "description": "{{ticket.description}}",
           "status": "{{ticket.status}}",
           "tags": "{{ticket.tags}}",
           "updater_id": "{{current_user.id}}"
         }
       }
       ```
4. Click **Create trigger**

### Trigger 2: Ticket Updated

1. Click **Create trigger** again
2. Configure:
   - **Name**: PII Redaction on Ticket Update
   - **Conditions** (Meet ALL):
     - Ticket: Is Updated
     - Tags: Does not contain `pii-redaction-in-progress`
   - **Actions**:
     - Notify webhook: PII Redaction Gateway
     - JSON body:
       ```json
       {
         "event_type": "ticket.updated",
         "ticket": {
           "id": "{{ticket.id}}",
           "subject": "{{ticket.title}}",
           "description": "{{ticket.description}}",
           "status": "{{ticket.status}}",
           "tags": "{{ticket.tags}}",
           "updater_id": "{{current_user.id}}",
           "latest_comment": {
             "id": "{{ticket.latest_comment.id}}",
             "body": "{{ticket.latest_comment.value}}",
             "author_id": "{{ticket.latest_comment.author.id}}",
             "public": "{{ticket.latest_comment.is_public}}"
           }
         }
       }
       ```
3. Click **Create trigger**

> **How it works**: New tickets get a full scan (all fields + comments). Updates on already-redacted tickets get an incremental scan (only the latest comment). The bot's own updates are automatically skipped via the `updater_id` check.

## Step 10: Test with a Sample Ticket

1. Create a new Zendesk ticket with test PII:
   ```
   Subject: Test PII Detection
   Description: My SSN is 123-45-6789 and my email is test@example.com.
   Card number: 4532-0150-0000-1234.
   ```

2. Wait 5-10 seconds for processing

3. Check the ticket — you should see:
   - An internal note from the bot with redacted content
   - The tag `pii-redacted` added to the ticket

4. Check the audit trail:
   ```bash
   aws s3 ls s3://your-audit-bucket/audit/ --recursive
   ```

## Step 11: Monitor

### CloudWatch Dashboard

Go to **CloudWatch > Dashboards > pii-redaction-gateway-prod** to see:
- Lambda invocations, errors, and throttles
- Average and p99 latency
- API Gateway request counts and error rates

### CloudWatch Logs

```bash
# View webhook Lambda logs
aws logs tail /aws/lambda/pii-redaction-gateway-webhook-prod --follow
```

### Alarms

If you configured `alarm_email`, you'll receive email alerts when:
- More than 5 Lambda errors in 5 minutes
- p99 latency exceeds 80% of the Lambda timeout

---

## Troubleshooting

### Webhook not triggering
- Verify the webhook URL is correct in Zendesk
- Check that the trigger conditions match (tag filter, ticket events)
- Check CloudWatch Logs for the webhook Lambda

### 401 Unauthorized
- Verify the `X-API-Key` header in Zendesk webhook matches the `WEBHOOK_SECRET` in Secrets Manager

### PII not being detected
- Check that `LLM_ENABLED` is set to `true` for contextual PII (names, addresses)
- Verify the LLM API key is valid in Secrets Manager
- Check `ENABLED_PII_TYPES` includes the expected types

### Lambda timeout
- Increase `lambda_timeout` in `terraform.tfvars` (default: 30s)
- If LLM calls are slow, consider setting `LLM_ENABLED=false` for regex-only mode

### Recursive webhook loop
- The gateway adds the `pii-redacted` tag and checks for it automatically
- Ensure your Zendesk trigger has the condition: "Tags does not contain pii-redacted"

---

## Updating

```bash
# Pull latest code
git pull

# Redeploy
./scripts/deploy.sh apply
```

## Cleanup

```bash
# Destroy all AWS resources
./scripts/deploy.sh destroy
```
