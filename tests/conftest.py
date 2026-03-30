"""Shared test fixtures for the PII Redaction Gateway test suite."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Set test environment variables before importing app modules
os.environ.setdefault("LLM_PROVIDER", "claude")
os.environ.setdefault("LLM_ENABLED", "false")
os.environ.setdefault("ZENDESK_SUBDOMAIN", "testcompany")
os.environ.setdefault("ZENDESK_EMAIL", "bot@test.com")
os.environ.setdefault("ZENDESK_API_TOKEN", "test-token")
os.environ.setdefault("WEBHOOK_SECRET", "test-secret-key")
os.environ.setdefault("AUDIT_S3_BUCKET", "test-audit-bucket")
os.environ.setdefault("LOG_LEVEL", "DEBUG")
os.environ.setdefault("REDACTION_STYLE", "bracket")
os.environ.setdefault("ENABLED_PII_TYPES", "SSN,CREDIT_CARD,EMAIL,PHONE,PASSWORD,PHI,ADDRESS,NAME,DATE_OF_BIRTH")

from src.utils.config import Config


@pytest.fixture
def test_config():
    """Return a test Config with LLM disabled."""
    return Config(
        llm_provider="claude",
        llm_enabled=False,
        zendesk_subdomain="testcompany",
        zendesk_email="bot@test.com",
        zendesk_api_token="test-token",
        webhook_secret="test-secret-key",
        audit_s3_bucket="test-audit-bucket",
        log_level="DEBUG",
    )


@pytest.fixture
def sample_payloads():
    """Load sample payloads from fixtures."""
    fixture_path = Path(__file__).parent / "fixtures" / "sample_payloads.json"
    with open(fixture_path) as f:
        return json.load(f)


@pytest.fixture
def mock_s3(mocker):
    """Mock boto3 S3 client."""
    mock_client = MagicMock()
    mocker.patch("boto3.client", return_value=mock_client)
    return mock_client


@pytest.fixture
def mock_lambda_context():
    """Mock AWS Lambda context object."""
    context = MagicMock()
    context.aws_request_id = "test-request-123"
    context.function_name = "pii-redaction-gateway-webhook"
    context.memory_limit_in_mb = 512
    return context


@pytest.fixture
def api_gateway_event():
    """Base API Gateway Lambda proxy event factory."""
    def _make_event(body: dict | str, headers: dict | None = None) -> dict:
        if isinstance(body, dict):
            body = json.dumps(body)
        return {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": headers or {"X-API-Key": "test-secret-key"},
            "body": body,
            "requestContext": {
                "requestId": "test-apigw-request",
            },
        }
    return _make_event
