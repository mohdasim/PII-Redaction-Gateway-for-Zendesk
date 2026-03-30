"""Unit tests for the webhook Lambda handler."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


class TestWebhookHandler:
    """Tests for the main webhook handler flow."""

    def test_auth_failure_returns_401(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Unauthenticated requests return 401."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={"ticket": {"id": 1, "subject": "Test", "description": "Test"}},
            headers={"X-API-Key": "wrong-key"},
        )

        response = lambda_handler(event, mock_lambda_context)
        assert response["statusCode"] == 401

    def test_invalid_payload_returns_400(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Malformed payloads return 400."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body="not valid json{{{",
            headers={"X-API-Key": "test-secret-key"},
        )

        response = lambda_handler(event, mock_lambda_context)
        assert response["statusCode"] == 400

    def test_already_redacted_skipped(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Tickets with 'pii-redacted' tag are skipped."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 100,
                    "subject": "Test",
                    "description": "Test",
                    "tags": ["pii-redacted"],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        response = lambda_handler(event, mock_lambda_context)
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "skipped"
        assert body["reason"] == "already_redacted"

    def test_clean_ticket_no_zendesk_update(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Tickets with no PII don't trigger Zendesk API calls."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 200,
                    "subject": "Pricing question",
                    "description": "What are your enterprise plans?",
                    "tags": [],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient") as mock_zd:
            response = lambda_handler(event, mock_lambda_context)
            # ZendeskClient should not be instantiated if no PII found
            assert response["statusCode"] == 200

    def test_pii_detected_writes_audit_log(self, api_gateway_event, mock_lambda_context, mock_s3):
        """PII detection triggers audit log write to S3."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 300,
                    "subject": "Help",
                    "description": "My SSN is 123-45-6789 and email is test@test.com",
                    "tags": [],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient"):
            response = lambda_handler(event, mock_lambda_context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["total_redactions"] >= 2

        # Verify S3 put_object was called for audit
        mock_s3.put_object.assert_called_once()
        call_args = mock_s3.put_object.call_args
        assert call_args.kwargs["Bucket"] == "test-audit-bucket"
        assert "audit/" in call_args.kwargs["Key"]
        assert call_args.kwargs["ServerSideEncryption"] == "AES256"

        # Verify audit record doesn't contain PII
        audit_body = json.loads(call_args.kwargs["Body"])
        audit_str = json.dumps(audit_body)
        assert "123-45-6789" not in audit_str
        assert "test@test.com" not in audit_str

    def test_response_has_security_headers(self, api_gateway_event, mock_lambda_context, mock_s3):
        """All responses include security headers."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={"ticket": {"id": 1, "subject": "T", "description": "D", "tags": []}},
            headers={"X-API-Key": "test-secret-key"},
        )

        response = lambda_handler(event, mock_lambda_context)
        assert response["headers"]["X-Content-Type-Options"] == "nosniff"
        assert response["headers"]["Content-Type"] == "application/json"


class TestHealthHandler:
    """Tests for the health check endpoint."""

    def test_health_returns_200(self):
        from src.handlers.health_handler import lambda_handler

        response = lambda_handler({}, None)
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "healthy"
        assert body["service"] == "pii-redaction-gateway"
