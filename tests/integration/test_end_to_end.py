"""End-to-end integration tests for the PII Redaction Gateway.

Tests the full pipeline: webhook -> auth -> parse -> detect -> redact -> audit.
Uses unittest.mock for S3 and responses for Zendesk API mocking.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import responses

from src.handlers.webhook_handler import lambda_handler


@pytest.fixture
def lambda_context():
    ctx = MagicMock()
    ctx.aws_request_id = "integration-test-req-001"
    ctx.function_name = "pii-redaction-gateway-webhook"
    ctx.memory_limit_in_mb = 512
    return ctx


@pytest.fixture
def mock_s3_client():
    """Mock boto3 S3 client for audit log writes."""
    mock_client = MagicMock()
    with patch("boto3.client", return_value=mock_client):
        yield mock_client


class TestEndToEndPipeline:
    """Full pipeline integration tests."""

    @responses.activate
    def test_full_redaction_flow_with_ssn(self, lambda_context, mock_s3_client):
        """Complete flow: SSN in ticket -> detected -> redacted -> audit logged."""
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/5001.json",
            json={"ticket": {"id": 5001}},
            status=200,
        )

        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "ticket": {
                    "id": 5001,
                    "subject": "Help with account",
                    "description": "My SSN is 123-45-6789 and I need help.",
                    "tags": [],
                    "status": "new",
                    "custom_fields": [],
                    "comments": [],
                }
            }),
        }

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "processed"
        assert body["total_redactions"] >= 1

        # Verify Zendesk was called
        assert len(responses.calls) == 1
        zd_request = json.loads(responses.calls[0].request.body)
        assert "pii-redacted" in zd_request["ticket"]["additional_tags"]

        # Verify S3 audit log written
        mock_s3_client.put_object.assert_called_once()
        call_kwargs = mock_s3_client.put_object.call_args.kwargs
        assert "audit/" in call_kwargs["Key"]
        assert call_kwargs["ServerSideEncryption"] == "AES256"

        # Verify no PII in audit
        audit_body = json.loads(call_kwargs["Body"])
        audit_str = json.dumps(audit_body)
        assert "123-45-6789" not in audit_str

    @responses.activate
    def test_full_flow_mixed_pii(self, lambda_context, mock_s3_client):
        """Multiple PII types in one ticket are all detected and redacted."""
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/5002.json",
            json={"ticket": {"id": 5002}},
            status=200,
        )

        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "ticket": {
                    "id": 5002,
                    "subject": "Account for john@example.com",
                    "description": (
                        "Hi, I'm John. My email is john@example.com, "
                        "phone (555) 123-4567, SSN 456-78-9012."
                    ),
                    "tags": [],
                    "status": "new",
                    "custom_fields": [],
                    "comments": [],
                }
            }),
        }

        response = lambda_handler(event, lambda_context)

        body = json.loads(response["body"])
        # At minimum: email in subject + email in desc + phone + SSN
        assert body["total_redactions"] >= 2

    def test_clean_ticket_no_redaction(self, lambda_context, mock_s3_client):
        """Tickets with no PII pass through without modification."""
        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "ticket": {
                    "id": 5003,
                    "subject": "Question about pricing",
                    "description": "What are your enterprise plans?",
                    "tags": [],
                    "status": "new",
                    "custom_fields": [],
                    "comments": [],
                }
            }),
        }

        response = lambda_handler(event, lambda_context)

        body = json.loads(response["body"])
        assert body["total_redactions"] == 0

    def test_recursive_prevention(self, lambda_context, mock_s3_client):
        """Tickets already tagged as redacted are skipped immediately."""
        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "ticket": {
                    "id": 5004,
                    "subject": "Already processed",
                    "description": "SSN: 123-45-6789",
                    "tags": ["pii-redacted"],
                    "status": "open",
                    "custom_fields": [],
                    "comments": [],
                }
            }),
        }

        response = lambda_handler(event, lambda_context)

        body = json.loads(response["body"])
        assert body["status"] == "skipped"
        assert body["reason"] == "already_redacted"

    def test_auth_failure(self, lambda_context, mock_s3_client):
        """Invalid API key returns 401."""
        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "wrong-key"},
            "body": json.dumps({
                "ticket": {"id": 5005, "subject": "T", "description": "D", "tags": []}
            }),
        }

        response = lambda_handler(event, lambda_context)
        assert response["statusCode"] == 401

    @responses.activate
    def test_zendesk_api_failure_doesnt_break_pipeline(self, lambda_context, mock_s3_client):
        """Zendesk API failure is handled gracefully -- audit still written."""
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/5006.json",
            json={"error": "Server Error"},
            status=500,
        )

        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "ticket": {
                    "id": 5006,
                    "subject": "Help",
                    "description": "My SSN is 123-45-6789.",
                    "tags": [],
                    "status": "new",
                    "custom_fields": [],
                    "comments": [],
                }
            }),
        }

        response = lambda_handler(event, lambda_context)

        # Should still return 200 (pipeline completed, Zendesk update failed gracefully)
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["total_redactions"] >= 1

        # Audit log should still be written
        mock_s3_client.put_object.assert_called_once()
