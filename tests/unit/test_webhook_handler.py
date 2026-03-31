"""Unit tests for the webhook Lambda handler."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


class TestWebhookHandler:
    """Tests for the main webhook handler flow."""

    def _mock_zendesk(self, mock_zd_cls, comments=None):
        """Helper to set up ZendeskClient mock with standard defaults."""
        mock_instance = mock_zd_cls.return_value
        mock_instance.fetch_ticket_comments.return_value = comments or []
        mock_instance.apply_redactions.return_value = {"ticket": {"id": 1}}
        return mock_instance

    def test_auth_failure_returns_401(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Unauthenticated requests return 401."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={"ticket": {"id": 1, "subject": "Test", "description": "Test", "status": "solved"}},
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

    def test_not_solved_ticket_skipped(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Tickets not in 'solved' status are skipped."""
        from src.handlers.webhook_handler import lambda_handler

        for status in ("new", "open", "pending", "hold", "closed"):
            event = api_gateway_event(
                body={
                    "ticket": {
                        "id": 100,
                        "subject": "SSN 123-45-6789",
                        "description": "Has PII but not solved",
                        "status": status,
                        "tags": [],
                    }
                },
                headers={"X-API-Key": "test-secret-key"},
            )

            response = lambda_handler(event, mock_lambda_context)
            assert response["statusCode"] == 200
            body = json.loads(response["body"])
            assert body["status"] == "skipped"
            assert body["reason"] == "not_solved"

    def test_already_redacted_skipped(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Solved tickets with 'pii-redacted' tag are skipped."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 200,
                    "subject": "Test",
                    "description": "SSN 123-45-6789",
                    "status": "solved",
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

    def test_solved_ticket_with_pii_processed(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Solved tickets with PII are detected and redacted."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 300,
                    "subject": "Help",
                    "description": "My SSN is 123-45-6789 and email is test@test.com",
                    "status": "solved",
                    "tags": [],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient") as mock_zd_cls:
            self._mock_zendesk(mock_zd_cls)
            response = lambda_handler(event, mock_lambda_context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "processed"
        assert body["total_redactions"] >= 2

    def test_solved_clean_ticket_no_zendesk_update(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Solved tickets with no PII don't trigger apply_redactions."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 400,
                    "subject": "Pricing question",
                    "description": "What are your enterprise plans?",
                    "status": "solved",
                    "tags": [],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient") as mock_zd_cls:
            mock_instance = self._mock_zendesk(mock_zd_cls)
            response = lambda_handler(event, mock_lambda_context)

        assert response["statusCode"] == 200
        mock_instance.apply_redactions.assert_not_called()

    def test_pii_detected_writes_audit_log(self, api_gateway_event, mock_lambda_context, mock_s3):
        """PII detection triggers audit log write to S3."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 500,
                    "subject": "Help",
                    "description": "My SSN is 123-45-6789",
                    "status": "solved",
                    "tags": [],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient") as mock_zd_cls:
            self._mock_zendesk(mock_zd_cls)
            response = lambda_handler(event, mock_lambda_context)

        mock_s3.put_object.assert_called_once()
        call_args = mock_s3.put_object.call_args
        assert call_args.kwargs["Bucket"] == "test-audit-bucket"
        assert "audit/" in call_args.kwargs["Key"]
        assert call_args.kwargs["ServerSideEncryption"] == "AES256"

        audit_body = json.loads(call_args.kwargs["Body"])
        assert audit_body["trigger"] == "ticket_solved"
        audit_str = json.dumps(audit_body)
        assert "123-45-6789" not in audit_str

    def test_comments_fetched_and_scanned(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Comments fetched from Zendesk API are scanned for PII."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 600,
                    "subject": "Help me",
                    "description": "I need assistance",
                    "status": "solved",
                    "tags": [],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient") as mock_zd_cls:
            mock_instance = self._mock_zendesk(mock_zd_cls, comments=[
                {"id": 901, "body": "My SSN is 111-22-3333", "author_id": 10},
                {"id": 902, "body": "No PII here", "author_id": 20},
            ])
            response = lambda_handler(event, mock_lambda_context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["total_redactions"] >= 1

        mock_instance.apply_redactions.assert_called_once()
        call_kwargs = mock_instance.apply_redactions.call_args.kwargs
        comment_redactions = call_kwargs.get("comment_redactions", [])
        redacted_comment_ids = [cr["comment_id"] for cr in comment_redactions]
        assert 901 in redacted_comment_ids

    def test_fetch_comments_failure_falls_back_gracefully(self, api_gateway_event, mock_lambda_context, mock_s3):
        """If fetching comments fails, handler still processes ticket fields."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 700,
                    "subject": "Help",
                    "description": "My SSN is 123-45-6789",
                    "status": "solved",
                    "tags": [],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient") as mock_zd_cls:
            mock_instance = self._mock_zendesk(mock_zd_cls)
            mock_instance.fetch_ticket_comments.side_effect = Exception("API timeout")
            response = lambda_handler(event, mock_lambda_context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["total_redactions"] >= 1

    def test_response_has_security_headers(self, api_gateway_event, mock_lambda_context, mock_s3):
        """All responses include security headers."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={"ticket": {"id": 1, "subject": "T", "description": "D", "status": "solved", "tags": []}},
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient") as mock_zd_cls:
            self._mock_zendesk(mock_zd_cls)
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
