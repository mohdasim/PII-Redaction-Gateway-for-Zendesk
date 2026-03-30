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


class TestZendeskClientCurrentUser:
    """Tests for fetching the current authenticated user."""

    @responses.activate
    def test_get_current_user(self, client):
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/users/me.json",
            json={"user": {"id": 99999, "name": "PII Bot", "email": "bot@test.com"}},
            status=200,
        )

        user = client.get_current_user()
        assert user["id"] == 99999
        assert user["name"] == "PII Bot"

    @responses.activate
    def test_get_current_user_error(self, client):
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/users/me.json",
            json={"error": "Unauthorized"},
            status=401,
        )

        with pytest.raises(Exception):
            client.get_current_user()


class TestZendeskClientTagManagement:
    """Tests for tag add/remove operations."""

    @responses.activate
    def test_add_tags(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/100/tags.json",
            json={"tags": ["pii-redaction-in-progress", "existing-tag"]},
            status=200,
        )

        result = client.add_tags(100, ["pii-redaction-in-progress"])
        assert result["tags"] == ["pii-redaction-in-progress", "existing-tag"]
        request_body = json.loads(responses.calls[0].request.body)
        assert request_body["tags"] == ["pii-redaction-in-progress"]

    @responses.activate
    def test_remove_tags(self, client):
        responses.add(
            responses.DELETE,
            "https://testcompany.zendesk.com/api/v2/tickets/100/tags.json",
            json={"tags": ["existing-tag"]},
            status=200,
        )

        result = client.remove_tags(100, ["pii-redaction-in-progress"])
        request_body = json.loads(responses.calls[0].request.body)
        assert request_body["tags"] == ["pii-redaction-in-progress"]

    @responses.activate
    def test_add_tags_error(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/100/tags.json",
            json={"error": "Not Found"},
            status=404,
        )

        with pytest.raises(Exception):
            client.add_tags(100, ["test-tag"])


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


class TestZendeskClientFetchComments:
    """Tests for fetching ticket comments."""

    @responses.activate
    def test_fetch_comments_single_page(self, client):
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/100/comments.json",
            json={
                "comments": [
                    {"id": 1, "body": "First comment", "author_id": 10, "public": True},
                    {"id": 2, "body": "Second comment", "author_id": 20, "public": True},
                ],
                "next_page": None,
            },
            status=200,
        )

        comments = client.fetch_ticket_comments(100)
        assert len(comments) == 2
        assert comments[0]["id"] == 1
        assert comments[1]["body"] == "Second comment"

    @responses.activate
    def test_fetch_comments_paginated(self, client):
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/100/comments.json",
            json={
                "comments": [{"id": 1, "body": "Page 1 comment"}],
                "next_page": "https://testcompany.zendesk.com/api/v2/tickets/100/comments.json?page=2",
            },
            status=200,
        )
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/100/comments.json?page=2",
            json={
                "comments": [{"id": 2, "body": "Page 2 comment"}],
                "next_page": None,
            },
            status=200,
        )

        comments = client.fetch_ticket_comments(100)
        assert len(comments) == 2
        assert comments[0]["id"] == 1
        assert comments[1]["id"] == 2

    @responses.activate
    def test_fetch_comments_empty(self, client):
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/100/comments.json",
            json={"comments": [], "next_page": None},
            status=200,
        )

        comments = client.fetch_ticket_comments(100)
        assert comments == []

    @responses.activate
    def test_fetch_comments_api_error(self, client):
        responses.add(
            responses.GET,
            "https://testcompany.zendesk.com/api/v2/tickets/100/comments.json",
            json={"error": "Not Found"},
            status=404,
        )

        with pytest.raises(Exception):
            client.fetch_ticket_comments(100)


class TestZendeskClientRedactComment:
    """Tests for comment redaction via Zendesk Redaction API."""

    @responses.activate
    def test_redact_single_string(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/100/comments/555/redact.json",
            json={"comment": {"id": 555}},
            status=200,
        )

        results = client.redact_comment(100, 555, ["123-45-6789"])
        assert len(results) == 1
        request_body = json.loads(responses.calls[0].request.body)
        assert request_body["text"] == "123-45-6789"

    @responses.activate
    def test_redact_multiple_strings(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/100/comments/555/redact.json",
            json={"comment": {"id": 555}},
            status=200,
        )

        results = client.redact_comment(100, 555, ["123-45-6789", "test@test.com"])
        assert len(results) == 2
        # First call redacts SSN, second call redacts email
        body1 = json.loads(responses.calls[0].request.body)
        body2 = json.loads(responses.calls[1].request.body)
        assert body1["text"] == "123-45-6789"
        assert body2["text"] == "test@test.com"

    @responses.activate
    def test_redact_skips_empty_strings(self, client):
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/100/comments/555/redact.json",
            json={"comment": {"id": 555}},
            status=200,
        )

        results = client.redact_comment(100, 555, ["", "123-45-6789", "  "])
        assert len(results) == 1


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

    @responses.activate
    def test_apply_redactions_with_comment_redactions(self, client):
        """Comment PII is redacted via Zendesk Redaction API before ticket update."""
        # Mock the comment redaction endpoint
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/102/comments/777/redact.json",
            json={"comment": {"id": 777}},
            status=200,
        )
        # Mock the ticket update endpoint
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/102.json",
            json={"ticket": {"id": 102}},
            status=200,
        )

        client.apply_redactions(
            ticket_id=102,
            redacted_subject=None,
            redacted_description=None,
            comment_redactions=[
                {"comment_id": 777, "redact_strings": ["123-45-6789", "test@email.com"]},
            ],
            total_redactions=2,
        )

        # 2 redact calls (one per PII string) + 1 ticket update = 3 total
        assert len(responses.calls) == 3
        # Verify comment redaction calls
        assert "redact.json" in responses.calls[0].request.url
        assert "redact.json" in responses.calls[1].request.url
        # Verify ticket update mentions comment redaction
        ticket_body = json.loads(responses.calls[2].request.body)
        assert "1 comment(s) had PII redacted" in ticket_body["ticket"]["comment"]["body"]

    @responses.activate
    def test_apply_redactions_comment_failure_doesnt_block_ticket_update(self, client):
        """If comment redaction fails, ticket update still proceeds."""
        # Comment redaction fails
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/103/comments/888/redact.json",
            json={"error": "Forbidden"},
            status=403,
        )
        # Ticket update succeeds
        responses.add(
            responses.PUT,
            "https://testcompany.zendesk.com/api/v2/tickets/103.json",
            json={"ticket": {"id": 103}},
            status=200,
        )

        # Should not raise — comment failure is logged but doesn't block
        result = client.apply_redactions(
            ticket_id=103,
            redacted_subject=None,
            redacted_description=None,
            comment_redactions=[
                {"comment_id": 888, "redact_strings": ["secret-data"]},
            ],
            total_redactions=1,
        )

        assert result == {"ticket": {"id": 103}}
