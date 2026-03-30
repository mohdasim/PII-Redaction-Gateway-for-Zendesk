"""Zendesk API client for updating tickets with redacted content.

Handles:
- Updating ticket subject and description
- Redacting individual comments via Zendesk Redaction API
- Adding the "pii-redacted" tag to prevent recursive processing
"""

from __future__ import annotations

import requests

from src.utils.logger import get_logger

logger = get_logger(__name__)


class ZendeskClient:
    """Client for Zendesk REST API interactions."""

    def __init__(self, subdomain: str, email: str, api_token: str):
        """Initialize the Zendesk client.

        Args:
            subdomain: Zendesk subdomain (e.g., "yourcompany").
            email: Zendesk agent email for API authentication.
            api_token: Zendesk API token.
        """
        self._base_url = f"https://{subdomain}.zendesk.com/api/v2"
        self._auth = (f"{email}/token", api_token)
        self._session = requests.Session()
        self._session.auth = self._auth
        self._session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def update_ticket(
        self,
        ticket_id: int,
        subject: str | None = None,
        comment_body: str | None = None,
        tags_to_add: list[str] | None = None,
    ) -> dict:
        """Update a Zendesk ticket.

        Args:
            ticket_id: The ticket ID to update.
            subject: New subject (if redacted).
            comment_body: Internal note with redaction info.
            tags_to_add: Tags to add (e.g., ["pii-redacted"]).

        Returns:
            Zendesk API response as dict.
        """
        url = f"{self._base_url}/tickets/{ticket_id}.json"

        ticket_data: dict = {}
        if subject is not None:
            ticket_data["subject"] = subject
        if tags_to_add:
            ticket_data["additional_tags"] = tags_to_add
        if comment_body:
            ticket_data["comment"] = {
                "body": comment_body,
                "public": False,  # Internal note
            }

        payload = {"ticket": ticket_data}

        response = self._session.put(url, json=payload, timeout=15)
        response.raise_for_status()

        logger.info(
            "Zendesk ticket updated",
            extra={"extra_fields": {"ticket_id": ticket_id, "status_code": response.status_code}},
        )
        return response.json()

    def redact_comment(
        self, ticket_id: int, comment_id: int, redact_strings: list[str]
    ) -> dict:
        """Redact specific strings from a ticket comment using Zendesk Redaction API.

        Args:
            ticket_id: The ticket ID.
            comment_id: The comment ID to redact.
            redact_strings: List of exact substrings to redact.

        Returns:
            Zendesk API response as dict.
        """
        url = f"{self._base_url}/tickets/{ticket_id}/comments/{comment_id}/redact.json"

        # Zendesk Redaction API accepts text to replace
        payload = {"text": redact_strings[0] if len(redact_strings) == 1 else redact_strings[0]}

        response = self._session.put(url, json=payload, timeout=15)
        response.raise_for_status()

        logger.info(
            "Zendesk comment redacted",
            extra={"extra_fields": {
                "ticket_id": ticket_id,
                "comment_id": comment_id,
            }},
        )
        return response.json()

    def apply_redactions(
        self,
        ticket_id: int,
        redacted_subject: str | None,
        redacted_description: str | None,
        total_redactions: int,
    ) -> dict:
        """Apply redacted content to a Zendesk ticket.

        Updates the ticket subject (if changed), adds an internal note
        with the redacted description, and tags the ticket.

        Args:
            ticket_id: Ticket ID.
            redacted_subject: Redacted subject text, or None if unchanged.
            redacted_description: Redacted description, or None if unchanged.
            total_redactions: Total number of PII entities redacted.

        Returns:
            Zendesk API response.
        """
        comment_parts = []
        if redacted_description:
            comment_parts.append(
                f"[PII Redaction Gateway] {total_redactions} PII item(s) redacted.\n\n"
                f"Redacted description:\n{redacted_description}"
            )
        else:
            comment_parts.append(
                f"[PII Redaction Gateway] {total_redactions} PII item(s) redacted in this ticket."
            )

        return self.update_ticket(
            ticket_id=ticket_id,
            subject=redacted_subject,
            comment_body="\n".join(comment_parts),
            tags_to_add=["pii-redacted"],
        )
