"""Zendesk API client for updating tickets with redacted content.

Handles:
- Fetching all comments for a ticket
- Updating ticket subject and description
- Redacting individual comments via Zendesk Redaction API
- Adding the "pii-redacted" tag to prevent re-processing
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

    def fetch_ticket_comments(self, ticket_id: int) -> list[dict]:
        """Fetch all comments for a ticket via Zendesk API.

        Handles pagination to retrieve all comments, not just the first page.

        Args:
            ticket_id: The ticket ID to fetch comments for.

        Returns:
            List of comment dicts, each with 'id', 'body', 'author_id',
            'public', 'created_at', etc.
        """
        url = f"{self._base_url}/tickets/{ticket_id}/comments.json"
        all_comments = []

        while url:
            response = self._session.get(url, timeout=15)
            response.raise_for_status()
            data = response.json()

            all_comments.extend(data.get("comments", []))

            # Zendesk paginates — follow next_page if present
            url = data.get("next_page")

        logger.info(
            "Fetched ticket comments",
            extra={"extra_fields": {
                "ticket_id": ticket_id,
                "comment_count": len(all_comments),
            }},
        )
        return all_comments

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
    ) -> list[dict]:
        """Redact specific strings from a ticket comment using Zendesk Redaction API.

        The Zendesk Redaction API accepts one string per call, so this method
        iterates over all strings and makes separate API calls for each.

        Args:
            ticket_id: The ticket ID.
            comment_id: The comment ID to redact.
            redact_strings: List of exact PII substrings to redact.

        Returns:
            List of Zendesk API responses (one per redacted string).
        """
        url = f"{self._base_url}/tickets/{ticket_id}/comments/{comment_id}/redact.json"
        results = []

        for pii_text in redact_strings:
            if not pii_text.strip():
                continue

            payload = {"text": pii_text}
            response = self._session.put(url, json=payload, timeout=15)
            response.raise_for_status()
            results.append(response.json())

        logger.info(
            "Zendesk comment redacted",
            extra={"extra_fields": {
                "ticket_id": ticket_id,
                "comment_id": comment_id,
                "redacted_count": len(results),
            }},
        )
        return results

    def apply_redactions(
        self,
        ticket_id: int,
        redacted_subject: str | None,
        redacted_description: str | None,
        comment_redactions: list[dict] | None = None,
        total_redactions: int = 0,
    ) -> dict:
        """Apply all redactions to a Zendesk ticket.

        Updates the ticket subject (if changed), adds an internal note
        with the redacted description, redacts PII in individual comments
        via the Redaction API, and tags the ticket to prevent re-processing.

        Args:
            ticket_id: Ticket ID.
            redacted_subject: Redacted subject text, or None if unchanged.
            redacted_description: Redacted description, or None if unchanged.
            comment_redactions: List of dicts, each with:
                - "comment_id" (int): The Zendesk comment ID
                - "redact_strings" (list[str]): PII substrings to redact
            total_redactions: Total number of PII entities redacted.

        Returns:
            Zendesk API response from the ticket update.
        """
        # 1. Redact individual comments via Zendesk Redaction API
        comments_redacted = 0
        for cr in comment_redactions or []:
            comment_id = cr.get("comment_id")
            redact_strings = cr.get("redact_strings", [])
            if not comment_id or not redact_strings:
                continue
            try:
                self.redact_comment(ticket_id, comment_id, redact_strings)
                comments_redacted += 1
            except Exception as e:
                logger.error(
                    f"Failed to redact comment {comment_id}: {e}",
                    extra={"extra_fields": {
                        "ticket_id": ticket_id,
                        "comment_id": comment_id,
                    }},
                )

        # 2. Build internal note summarizing what was redacted
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

        if comments_redacted > 0:
            comment_parts.append(
                f"\n{comments_redacted} comment(s) had PII redacted via Zendesk Redaction API."
            )

        # 3. Update ticket (subject, internal note, tag)
        return self.update_ticket(
            ticket_id=ticket_id,
            subject=redacted_subject,
            comment_body="\n".join(comment_parts),
            tags_to_add=["pii-redacted"],
        )
