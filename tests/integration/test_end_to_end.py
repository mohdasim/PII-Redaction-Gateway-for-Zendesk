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


def _mock_tag_endpoints(ticket_id):
    """Register responses mocks for tag add/remove endpoints on a ticket."""
    responses.add(
        responses.PUT,
        f"https://testcompany.zendesk.com/api/v2/tickets/{ticket_id}/tags.json",
        json={"tags": ["pii-redaction-in-progress"]},
        status=200,
    )
    responses.add(
        responses.DELETE,
        f"https://testcompany.zendesk.com/api/v2/tickets/{ticket_id}/tags.json",
        json={"tags": []},
        status=200,
    )


class TestEndToEndPipeline:
    """Full pipeline integration tests."""

    @responses.activate
    def test_full_redaction_flow_with_ssn(self, lambda_context, mock_s3_client):
        """Complete flow: SSN in ticket -> detected -> redacted -> audit logged."""
        _mock_tag_endpoints(5001)
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/5001/comments.json",
            json={"comments": [], "next_page": None},
            status=200,
        )
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
        assert body["scan_mode"] == "full"
        assert body["total_redactions"] >= 1

        # Verify Zendesk ticket update was called
        ticket_put_calls = [
            c for c in responses.calls
            if c.request.method == "PUT" and "tickets/5001.json" in c.request.url
        ]
        assert len(ticket_put_calls) >= 1
        zd_request = json.loads(ticket_put_calls[-1].request.body)
        assert "pii-redacted" in zd_request["ticket"]["additional_tags"]

        # Verify S3 audit log written
        mock_s3_client.put_object.assert_called_once()
        call_kwargs = mock_s3_client.put_object.call_args.kwargs
        assert "audit/" in call_kwargs["Key"]
        assert call_kwargs["ServerSideEncryption"] == "AES256"

        # Verify no PII in audit and scan_mode is recorded
        audit_body = json.loads(call_kwargs["Body"])
        assert audit_body["scan_mode"] == "full"
        audit_str = json.dumps(audit_body)
        assert "123-45-6789" not in audit_str

    @responses.activate
    def test_full_flow_mixed_pii(self, lambda_context, mock_s3_client):
        """Multiple PII types in one ticket are all detected and redacted."""
        _mock_tag_endpoints(5002)
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/5002/comments.json",
            json={"comments": [], "next_page": None},
            status=200,
        )
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
        assert body["total_redactions"] >= 2

    @responses.activate
    def test_clean_ticket_no_redaction(self, lambda_context, mock_s3_client):
        """Tickets with no PII pass through without modification."""
        _mock_tag_endpoints(5003)
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/5003/comments.json",
            json={"comments": [], "next_page": None},
            status=200,
        )

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

    @responses.activate
    def test_full_flow_comment_pii_redacted(self, lambda_context, mock_s3_client):
        """PII in comments fetched from API is detected and redacted via Redaction API."""
        _mock_tag_endpoints(5007)
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/5007/comments.json",
            json={
                "comments": [
                    {"id": 9001, "body": "My SSN is 321-54-9876, please help.", "author_id": 42},
                ],
                "next_page": None,
            },
            status=200,
        )
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/5007/comments/9001/redact.json",
            json={"comment": {"id": 9001}},
            status=200,
        )
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/5007.json",
            json={"ticket": {"id": 5007}},
            status=200,
        )

        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "ticket": {
                    "id": 5007,
                    "subject": "Account inquiry",
                    "description": "Please review my account.",
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
        assert body["total_redactions"] >= 1

        redact_calls = [c for c in responses.calls if "redact.json" in c.request.url]
        assert len(redact_calls) >= 1
        redact_body = json.loads(redact_calls[0].request.body)
        assert redact_body["text"] == "321-54-9876"

    def test_bot_self_update_prevention(self, lambda_context, mock_s3_client):
        """Tickets updated by the bot itself are skipped (loop prevention)."""
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
                    "updater_id": 99999,  # matches configured bot user ID
                }
            }),
        }

        response = lambda_handler(event, lambda_context)

        body = json.loads(response["body"])
        assert body["status"] == "skipped"
        assert body["reason"] == "bot_self_update"

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
        _mock_tag_endpoints(5006)
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/5006/comments.json",
            json={"comments": [], "next_page": None},
            status=200,
        )
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

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["total_redactions"] >= 1

        mock_s3_client.put_object.assert_called_once()

    @responses.activate
    def test_ticket_update_incremental_scan(self, lambda_context, mock_s3_client):
        """Ticket update on already-redacted ticket scans only new content."""
        _mock_tag_endpoints(5008)
        # Mock fetch comments — returns the new comment
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/5008/comments.json",
            json={
                "comments": [
                    {"id": 8001, "body": "Original comment (already clean)", "author_id": 42},
                    {"id": 8002, "body": "My credit card is 4532015000001234", "author_id": 42},
                ],
                "next_page": None,
            },
            status=200,
        )
        # Mock comment redaction for the new comment
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/5008/comments/8002/redact.json",
            json={"comment": {"id": 8002}},
            status=200,
        )
        # Mock ticket update
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/5008.json",
            json={"ticket": {"id": 5008}},
            status=200,
        )

        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "event_type": "ticket.updated",
                "ticket": {
                    "id": 5008,
                    "subject": "Help with billing",
                    "description": "Previously clean description.",
                    "tags": ["pii-redacted"],
                    "status": "open",
                    "custom_fields": [],
                    "comments": [],
                    "updater_id": 42,  # NOT the bot
                    "latest_comment": {
                        "id": 8002,
                        "body": "My credit card is 4532015000001234",
                        "author_id": 42,
                        "public": True,
                    },
                }
            }),
        }

        response = lambda_handler(event, lambda_context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["status"] == "processed"
        assert body["scan_mode"] == "incremental"
        assert body["total_redactions"] >= 1

        # Verify audit log records incremental mode
        mock_s3_client.put_object.assert_called_once()
        audit_body = json.loads(mock_s3_client.put_object.call_args.kwargs["Body"])
        assert audit_body["scan_mode"] == "incremental"
