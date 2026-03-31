"""Pydantic models for Zendesk webhook payloads."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class ZendeskComment(BaseModel):
    """A single comment/reply on a Zendesk ticket."""

    model_config = ConfigDict(extra="allow")

    id: int | None = None
    body: str = ""
    author_id: int | None = None
    public: bool = True
    created_at: str | None = None


class ZendeskTicket(BaseModel):
    """Zendesk ticket data from webhook payload."""

    model_config = ConfigDict(extra="allow")

    id: int
    subject: str = ""
    description: str = ""
    status: str = ""
    tags: list[str] = []
    custom_fields: list[dict[str, Any]] = []
    comments: list[ZendeskComment] = []
    latest_comment: ZendeskComment | None = None


class ZendeskWebhookPayload(BaseModel):
    """Top-level Zendesk webhook payload.

    Zendesk webhooks send different payload shapes depending on the
    trigger configuration. This model handles the common patterns:
    - Direct ticket object at root
    - Nested under a "ticket" key
    """

    model_config = ConfigDict(extra="allow")

    ticket: ZendeskTicket | None = None

    # Some webhook configs send fields at root level
    id: int | None = None
    subject: str | None = None
    description: str | None = None
    status: str | None = None
    tags: list[str] | None = None
    latest_comment: ZendeskComment | None = None

    def get_ticket(self) -> ZendeskTicket:
        """Extract the ticket from the payload, handling different shapes."""
        if self.ticket is not None:
            return self.ticket

        # Build ticket from root-level fields
        return ZendeskTicket(
            id=self.id or 0,
            subject=self.subject or "",
            description=self.description or "",
            status=self.status or "",
            tags=self.tags or [],
            latest_comment=self.latest_comment,
        )
