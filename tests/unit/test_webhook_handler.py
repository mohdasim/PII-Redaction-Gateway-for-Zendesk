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
        mock_instance.add_tags.return_value = {}
        mock_instance.remove_tags.return_value = {}
        mock_instance.apply_redactions.return_value = {"ticket": {"id": 1}}
        return mock_instance

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

    def test_bot_self_update_skipped(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Updates made by the bot itself are skipped (loop prevention)."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 100,
                    "subject": "Test",
                    "description": "Test",
                    "tags": ["pii-redacted"],
                    "updater_id": 99999,  # matches ZENDESK_BOT_USER_ID
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        response = lambda_handler(event, mock_lambda_context)
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "skipped"
        assert body["reason"] == "bot_self_update"

    def test_in_progress_tag_skipped(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Tickets with 'pii-redaction-in-progress' tag are skipped."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 101,
                    "subject": "Test",
                    "description": "Test",
                    "tags": ["pii-redaction-in-progress"],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        response = lambda_handler(event, mock_lambda_context)
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "skipped"
        assert body["reason"] == "redaction_in_progress"

    def test_new_ticket_full_scan(self, api_gateway_event, mock_lambda_context, mock_s3):
        """New tickets (no pii-redacted tag) use full scan mode."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 200,
                    "subject": "Help",
                    "description": "My SSN is 123-45-6789",
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
        assert body["scan_mode"] == "full"
        assert body["total_redactions"] >= 1

    def test_updated_ticket_incremental_scan(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Already-redacted tickets with new content use incremental scan mode."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 300,
                    "subject": "Help",
                    "description": "Previously clean description",
                    "tags": ["pii-redacted"],
                    "updater_id": 12345,  # NOT the bot
                    "latest_comment": {
                        "id": 8001,
                        "body": "My new SSN is 234-56-7890",
                        "author_id": 12345,
                        "public": True,
                    },
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient") as mock_zd_cls:
            mock_instance = self._mock_zendesk(mock_zd_cls)
            response = lambda_handler(event, mock_lambda_context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["scan_mode"] == "incremental"
        assert body["total_redactions"] >= 1

        # Verify apply_redactions was called
        mock_instance.apply_redactions.assert_called_once()

    def test_clean_ticket_no_zendesk_update(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Tickets with no PII don't trigger Zendesk apply_redactions."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 400,
                    "subject": "Pricing question",
                    "description": "What are your enterprise plans?",
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
                    "description": "My SSN is 123-45-6789 and email is test@test.com",
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
        assert body["total_redactions"] >= 2

        # Verify S3 put_object was called for audit
        mock_s3.put_object.assert_called_once()
        call_args = mock_s3.put_object.call_args
        assert call_args.kwargs["Bucket"] == "test-audit-bucket"
        assert "audit/" in call_args.kwargs["Key"]
        assert call_args.kwargs["ServerSideEncryption"] == "AES256"

        # Verify audit record includes scan_mode and no PII
        audit_body = json.loads(call_args.kwargs["Body"])
        assert audit_body["scan_mode"] == "full"
        audit_str = json.dumps(audit_body)
        assert "123-45-6789" not in audit_str
        assert "test@test.com" not in audit_str

    def test_comments_fetched_and_scanned(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Comments fetched from Zendesk API are scanned for PII in full mode."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 600,
                    "subject": "Help me",
                    "description": "I need assistance",
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

        # Verify apply_redactions was called with comment_redactions
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

    def test_in_progress_tag_added_and_removed(self, api_gateway_event, mock_lambda_context, mock_s3):
        """In-progress tag is added at start and removed after processing."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 800,
                    "subject": "Test",
                    "description": "Clean text",
                    "tags": [],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient") as mock_zd_cls:
            mock_instance = self._mock_zendesk(mock_zd_cls)
            lambda_handler(event, mock_lambda_context)

        mock_instance.add_tags.assert_called_once_with(800, ["pii-redaction-in-progress"])
        mock_instance.remove_tags.assert_called_once_with(800, ["pii-redaction-in-progress"])

    def test_in_progress_tag_removed_on_error(self, api_gateway_event, mock_lambda_context, mock_s3):
        """In-progress tag is removed even if processing raises an error."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 900,
                    "subject": "Test",
                    "description": "SSN 123-45-6789",
                    "tags": [],
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        with patch("src.handlers.webhook_handler.ZendeskClient") as mock_zd_cls:
            mock_instance = self._mock_zendesk(mock_zd_cls)
            # Make fetch_ticket_comments raise
            mock_instance.fetch_ticket_comments.side_effect = Exception("Network error")
            lambda_handler(event, mock_lambda_context)

        # remove_tags should still be called in the finally block
        mock_instance.remove_tags.assert_called_once_with(900, ["pii-redaction-in-progress"])

    def test_bot_fallback_detection_via_internal_note(self, api_gateway_event, mock_lambda_context, mock_s3):
        """Bot update detected via internal note pattern when bot_user_id doesn't match."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={
                "ticket": {
                    "id": 1000,
                    "subject": "Test",
                    "description": "Test",
                    "tags": ["pii-redacted"],
                    "updater_id": 77777,  # Not the configured bot ID
                    "latest_comment": {
                        "id": 5001,
                        "body": "[PII Redaction Gateway] 2 PII item(s) redacted.",
                        "author_id": 77777,
                        "public": False,
                    },
                }
            },
            headers={"X-API-Key": "test-secret-key"},
        )

        response = lambda_handler(event, mock_lambda_context)
        body = json.loads(response["body"])
        assert body["status"] == "skipped"
        assert body["reason"] == "bot_self_update"

    def test_response_has_security_headers(self, api_gateway_event, mock_lambda_context, mock_s3):
        """All responses include security headers."""
        from src.handlers.webhook_handler import lambda_handler

        event = api_gateway_event(
            body={"ticket": {"id": 1, "subject": "T", "description": "D", "tags": []}},
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
