#!/usr/bin/env bash
# =============================================================================
# PII Redaction Gateway — Deployment Script
# =============================================================================
# Usage: ./scripts/deploy.sh [plan|apply|destroy]
#
# Prerequisites:
#   - AWS CLI configured with appropriate credentials
#   - Terraform >= 1.5.0 installed
#   - Python 3.12 installed
#   - pip installed
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$PROJECT_DIR/terraform"
ACTION="${1:-plan}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ---------------------------------------------------------------------------
# 1. Check prerequisites
# ---------------------------------------------------------------------------
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed. Install it from https://aws.amazon.com/cli/"
        exit 1
    fi

    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed. Install it from https://www.terraform.io/downloads"
        exit 1
    fi

    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed."
        exit 1
    fi

    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        log_error "pip is not installed."
        exit 1
    fi

    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured. Run 'aws configure' first."
        exit 1
    fi

    log_info "All prerequisites met."
}

# ---------------------------------------------------------------------------
# 2. Package Lambda dependencies as a layer
# ---------------------------------------------------------------------------
package_lambda_layer() {
    log_info "Packaging Lambda dependencies layer..."

    local LAYER_DIR="$PROJECT_DIR/.build/layer/python"
    rm -rf "$PROJECT_DIR/.build/layer"
    mkdir -p "$LAYER_DIR"

    pip3 install -r "$PROJECT_DIR/requirements.txt" -t "$LAYER_DIR" --quiet --upgrade

    cd "$PROJECT_DIR/.build/layer"
    zip -r "$PROJECT_DIR/lambda_layer.zip" . -q
    cd "$PROJECT_DIR"

    log_info "Lambda layer packaged: lambda_layer.zip ($(du -h "$PROJECT_DIR/lambda_layer.zip" | cut -f1))"
}

# ---------------------------------------------------------------------------
# 3. Run Terraform
# ---------------------------------------------------------------------------
run_terraform() {
    log_info "Running Terraform $ACTION..."

    cd "$TERRAFORM_DIR"

    # Initialize if needed
    if [ ! -d ".terraform" ]; then
        log_info "Initializing Terraform..."
        terraform init
    fi

    # Validate
    terraform validate

    case "$ACTION" in
        plan)
            terraform plan
            ;;
        apply)
            terraform apply -auto-approve
            echo ""
            log_info "Deployment complete! Outputs:"
            terraform output
            echo ""
            log_info "Next steps:"
            log_info "  1. Store your API keys in Secrets Manager (see terraform/secrets.tf for command)"
            log_info "  2. Configure the Zendesk webhook with the webhook_url above"
            log_info "  3. Create a Zendesk trigger for ticket.created/updated events"
            ;;
        destroy)
            log_warn "This will destroy all resources!"
            terraform destroy
            ;;
        *)
            log_error "Unknown action: $ACTION. Use: plan, apply, or destroy"
            exit 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
check_prerequisites
package_lambda_layer
run_terraform
