"""Unit tests for the Zendesk API client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import responses

from src.services.zendesk_client import ZendeskClient


@pytest.fixture
def client():
    return ZendeskClient(
        subdomain="testcompany",
        email="bot@test.com",
        api_token="test-api-token",
    )


class TestZendeskClientAuth:
    """Tests for Zendesk authentication."""

    def test_auth_header_format(self, client):
        assert client._auth == ("bot@test.com/token", "test-api-token")

    def test_base_url(self, client):
        assert client._base_url == "https://testcompany.zendesk.com/api/v2"


class TestZendeskClientUpdateTicket:
    """Tests for ticket update operations."""

    @responses.activate
    def test_update_ticket_subject(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/123.json",
            json={"ticket": {"id": 123}},
            status=200,
        )

        result = client.update_ticket(
            ticket_id=123,
            subject="[REDACTED-SSN] inquiry",
        )

        assert result == {"ticket": {"id": 123}}
        request_body = json.loads(responses.calls[0].request.body)
        assert request_body["ticket"]["subject"] == "[REDACTED-SSN] inquiry"

    @responses.activate
    def test_update_ticket_with_comment(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/456.json",
            json={"ticket": {"id": 456}},
            status=200,
        )

        result = client.update_ticket(
            ticket_id=456,
            comment_body="PII was redacted",
        )

        request_body = json.loads(responses.calls[0].request.body)
        assert request_body["ticket"]["comment"]["body"] == "PII was redacted"
        assert request_body["ticket"]["comment"]["public"] is False

    @responses.activate
    def test_update_ticket_adds_tags(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/789.json",
            json={"ticket": {"id": 789}},
            status=200,
        )

        client.update_ticket(
            ticket_id=789,
            tags_to_add=["pii-redacted"],
        )

        request_body = json.loads(responses.calls[0].request.body)
        assert "pii-redacted" in request_body["ticket"]["additional_tags"]

    @responses.activate
    def test_update_ticket_error_raises(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/999.json",
            json={"error": "Not Found"},
            status=404,
        )

        with pytest.raises(Exception):
            client.update_ticket(ticket_id=999, subject="Test")


class TestZendeskClientApplyRedactions:
    """Tests for the apply_redactions convenience method."""

    @responses.activate
    def test_apply_redactions_with_subject(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/100.json",
            json={"ticket": {"id": 100}},
            status=200,
        )

        client.apply_redactions(
            ticket_id=100,
            redacted_subject="[REDACTED-EMAIL] account",
            redacted_description="Description with [REDACTED-SSN]",
            total_redactions=2,
        )

        request_body = json.loads(responses.calls[0].request.body)
        assert request_body["ticket"]["subject"] == "[REDACTED-EMAIL] account"
        assert "pii-redacted" in request_body["ticket"]["additional_tags"]
        assert "2 PII item(s) redacted" in request_body["ticket"]["comment"]["body"]

    @responses.activate
    def test_apply_redactions_no_subject_change(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/101.json",
            json={"ticket": {"id": 101}},
            status=200,
        )

        client.apply_redactions(
            ticket_id=101,
            redacted_subject=None,
            redacted_description=None,
            total_redactions=1,
        )

        request_body = json.loads(responses.calls[0].request.body)
        assert "subject" not in request_body["ticket"]
