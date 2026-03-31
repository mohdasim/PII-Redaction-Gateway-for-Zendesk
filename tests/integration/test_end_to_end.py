"""End-to-end integration tests for the PII Redaction Gateway.

Tests the full pipeline: webhook -> auth -> solved check -> detect -> redact -> audit.
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
    def test_full_redaction_flow_solved_ticket(self, lambda_context, mock_s3_client):
        """Complete flow: solved ticket with SSN -> detected -> redacted -> audit."""
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
                    "status": "solved",
                    "tags": [],
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

        # Verify Zendesk ticket update was called with pii-redacted tag
        ticket_put_calls = [
            c for c in responses.calls
            if c.request.method == "PUT" and "tickets/5001.json" in c.request.url
        ]
        assert len(ticket_put_calls) >= 1
        zd_request = json.loads(ticket_put_calls[-1].request.body)
        assert "pii-redacted" in zd_request["ticket"]["additional_tags"]

        # Verify S3 audit log
        mock_s3_client.put_object.assert_called_once()
        call_kwargs = mock_s3_client.put_object.call_args.kwargs
        assert "audit/" in call_kwargs["Key"]
        assert call_kwargs["ServerSideEncryption"] == "AES256"

        audit_body = json.loads(call_kwargs["Body"])
        assert audit_body["trigger"] == "ticket_solved"
        assert "123-45-6789" not in json.dumps(audit_body)

    @responses.activate
    def test_full_flow_mixed_pii(self, lambda_context, mock_s3_client):
        """Multiple PII types in one solved ticket are all detected."""
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
                        "My email is john@example.com, "
                        "phone (555) 123-4567, SSN 456-78-9012."
                    ),
                    "status": "solved",
                    "tags": [],
                    "custom_fields": [],
                    "comments": [],
                }
            }),
        }

        response = lambda_handler(event, lambda_context)
        body = json.loads(response["body"])
        assert body["total_redactions"] >= 2

    def test_unsolved_ticket_skipped(self, lambda_context, mock_s3_client):
        """Tickets that are not solved are skipped entirely."""
        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "ticket": {
                    "id": 5003,
                    "subject": "SSN 123-45-6789",
                    "description": "Has PII but ticket is open",
                    "status": "open",
                    "tags": [],
                    "custom_fields": [],
                    "comments": [],
                }
            }),
        }

        response = lambda_handler(event, lambda_context)
        body = json.loads(response["body"])
        assert body["status"] == "skipped"
        assert body["reason"] == "not_solved"

    @responses.activate
    def test_solved_clean_ticket_no_redaction(self, lambda_context, mock_s3_client):
        """Solved tickets with no PII pass through without modification."""
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/5004/comments.json",
            json={"comments": [], "next_page": None},
            status=200,
        )

        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "ticket": {
                    "id": 5004,
                    "subject": "Question about pricing",
                    "description": "What are your enterprise plans?",
                    "status": "solved",
                    "tags": [],
                    "custom_fields": [],
                    "comments": [],
                }
            }),
        }

        response = lambda_handler(event, lambda_context)
        body = json.loads(response["body"])
        assert body["total_redactions"] == 0

    def test_already_redacted_skipped(self, lambda_context, mock_s3_client):
        """Solved tickets with pii-redacted tag are skipped."""
        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "ticket": {
                    "id": 5005,
                    "subject": "Already processed",
                    "description": "SSN: 123-45-6789",
                    "status": "solved",
                    "tags": ["pii-redacted"],
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
                "ticket": {"id": 5006, "subject": "T", "description": "D", "status": "solved", "tags": []}
            }),
        }

        response = lambda_handler(event, lambda_context)
        assert response["statusCode"] == 401

    @responses.activate
    def test_comment_pii_redacted_on_solve(self, lambda_context, mock_s3_client):
        """PII in comments is redacted via Redaction API when ticket solved."""
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
                    "status": "solved",
                    "tags": [],
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
        assert json.loads(redact_calls[0].request.body)["text"] == "321-54-9876"

    @responses.activate
    def test_zendesk_api_failure_doesnt_break_pipeline(self, lambda_context, mock_s3_client):
        """Zendesk API failure is handled gracefully — audit still written."""
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/5008/comments.json",
            json={"comments": [], "next_page": None},
            status=200,
        )
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/5008.json",
            json={"error": "Server Error"},
            status=500,
        )

        event = {
            "httpMethod": "POST",
            "path": "/webhook",
            "headers": {"X-API-Key": "test-secret-key"},
            "body": json.dumps({
                "ticket": {
                    "id": 5008,
                    "subject": "Help",
                    "description": "My SSN is 123-45-6789.",
                    "status": "solved",
                    "tags": [],
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
