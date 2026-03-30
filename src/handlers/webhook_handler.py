"""Main Lambda handler for the PII Redaction Gateway webhook.

Supports both ticket.created and ticket.updated events:
- ticket.created: Full scan of subject, description, comments, custom fields
- ticket.updated (already redacted): Incremental scan of new/changed content only

Recursive loop prevention uses two mechanisms:
1. Bot user ID check — skip if the update was made by our own bot
2. In-progress tag — skip if concurrent processing is already happening

Flow:
1. Authenticate the incoming request
2. Parse the Zendesk webhook payload
3. Check for bot self-update (prevents infinite loop)
4. Check for concurrent processing (pii-redaction-in-progress tag)
5. Determine scan mode (full vs incremental)
6. Initialize Zendesk client and add in-progress tag
7. Fetch comments from Zendesk API (all or only new, based on scan mode)
8. Extract text fields to scan based on scan mode
9. Run the two-layer PII detection and redaction pipeline
10. Update Zendesk: redact content + manage tags
11. Write audit log to S3
12. Return success response
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import boto3

from src.models.zendesk_models import ZendeskWebhookPayload
from src.services.pii_detector import PIIDetector
from src.services.zendesk_client import ZendeskClient
from src.utils.auth import verify_webhook
from src.utils.config import get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Tags used for state management
TAG_REDACTED = "pii-redacted"
TAG_IN_PROGRESS = "pii-redaction-in-progress"


def lambda_handler(event: dict, context) -> dict:
    """AWS Lambda entry point for webhook processing."""
    request_id = getattr(context, "aws_request_id", "local")
    start_time = time.time()

    logger.info(
        "Webhook received",
        extra={"extra_fields": {"request_id": request_id}},
    )

    config = get_config()

    # 1. Authenticate
    if not verify_webhook(event, config.webhook_secret.get_secret_value()):
        logger.warning("Webhook authentication failed", extra={"extra_fields": {"request_id": request_id}})
        return _response(401, {"error": "Unauthorized"})

    # 2. Parse payload
    try:
        body = json.loads(event.get("body", "{}"))
        payload = ZendeskWebhookPayload.model_validate(body)
        ticket = payload.get_ticket()
    except Exception as e:
        logger.warning(f"Invalid payload: {e}", extra={"extra_fields": {"request_id": request_id}})
        return _response(400, {"error": "Invalid payload", "detail": str(e)})

    # 3. Check for bot self-update (primary loop prevention)
    if _is_bot_update(ticket, config):
        logger.info(
            "Skipping bot's own update",
            extra={"extra_fields": {"ticket_id": ticket.id, "updater_id": ticket.updater_id}},
        )
        return _response(200, {"status": "skipped", "reason": "bot_self_update"})

    # 4. Check for concurrent processing
    if TAG_IN_PROGRESS in ticket.tags:
        logger.info(
            "Skipping — redaction already in progress",
            extra={"extra_fields": {"ticket_id": ticket.id}},
        )
        return _response(200, {"status": "skipped", "reason": "redaction_in_progress"})

    # 5. Determine scan mode
    already_redacted = TAG_REDACTED in ticket.tags
    scan_mode = "incremental" if already_redacted else "full"

    logger.info(
        "Processing ticket",
        extra={"extra_fields": {
            "ticket_id": ticket.id,
            "scan_mode": scan_mode,
            "event_type": payload.event_type or "unknown",
        }},
    )

    # 6. Initialize Zendesk client and add in-progress tag
    zendesk = ZendeskClient(
        subdomain=config.zendesk_subdomain,
        email=config.zendesk_email,
        api_token=config.zendesk_api_token.get_secret_value(),
    )

    try:
        zendesk.add_tags(ticket.id, [TAG_IN_PROGRESS])
    except Exception as e:
        logger.warning(
            f"Failed to add in-progress tag: {e}",
            extra={"extra_fields": {"ticket_id": ticket.id}},
        )

    try:
        result = _process_ticket(ticket, payload, zendesk, config, scan_mode, request_id, start_time)
    finally:
        # Always remove in-progress tag, even on failure
        try:
            zendesk.remove_tags(ticket.id, [TAG_IN_PROGRESS])
        except Exception as e:
            logger.warning(
                f"Failed to remove in-progress tag: {e}",
                extra={"extra_fields": {"ticket_id": ticket.id}},
            )

    return result


def _process_ticket(ticket, payload, zendesk, config, scan_mode, request_id, start_time) -> dict:
    """Core processing logic — extracted so in-progress tag cleanup runs in finally."""

    # 7. Fetch comments from Zendesk API
    api_comments = []
    try:
        api_comments = zendesk.fetch_ticket_comments(ticket.id)
        logger.info(
            "Fetched comments from Zendesk API",
            extra={"extra_fields": {"ticket_id": ticket.id, "count": len(api_comments)}},
        )
    except Exception as e:
        logger.warning(
            f"Failed to fetch comments from Zendesk API: {e}",
            extra={"extra_fields": {"ticket_id": ticket.id}},
        )

    # 8. Extract text fields to scan based on scan mode
    fields_to_scan, comment_field_map = _build_scan_fields(
        ticket, api_comments, scan_mode,
    )

    if not fields_to_scan:
        return _response(200, {"status": "skipped", "reason": "no_text_fields"})

    # 9. Detect and redact PII in all fields
    pii_detector = PIIDetector(config)
    results = {}
    total_redactions = 0

    for field_name, text in fields_to_scan.items():
        result = pii_detector.detect_and_redact(text)
        results[field_name] = result
        total_redactions += result.redaction_count

    # 10. Update Zendesk if PII was found
    if total_redactions > 0:
        try:
            redacted_subject = (
                results["subject"].redacted_text
                if "subject" in results and results["subject"].redaction_count > 0
                else None
            )
            redacted_description = (
                results["description"].redacted_text
                if "description" in results and results["description"].redaction_count > 0
                else None
            )

            # Build comment redaction list
            comment_redactions = _build_comment_redactions(results, comment_field_map)

            zendesk.apply_redactions(
                ticket_id=ticket.id,
                redacted_subject=redacted_subject,
                redacted_description=redacted_description,
                comment_redactions=comment_redactions,
                total_redactions=total_redactions,
            )
        except Exception as e:
            logger.error(
                f"Failed to update Zendesk: {e}",
                extra={"extra_fields": {"ticket_id": ticket.id}},
            )

    # 11. Write audit log to S3
    processing_time_ms = round((time.time() - start_time) * 1000, 1)
    _write_audit_log(
        ticket_id=ticket.id,
        results=results,
        request_id=request_id,
        llm_provider=pii_detector.llm_provider_name,
        processing_time_ms=processing_time_ms,
        scan_mode=scan_mode,
        config=config,
    )

    # 12. Return response
    logger.info(
        "Processing complete",
        extra={"extra_fields": {
            "ticket_id": ticket.id,
            "scan_mode": scan_mode,
            "total_redactions": total_redactions,
            "processing_ms": processing_time_ms,
        }},
    )

    return _response(200, {
        "status": "processed",
        "ticket_id": ticket.id,
        "scan_mode": scan_mode,
        "total_redactions": total_redactions,
        "processing_time_ms": processing_time_ms,
    })


def _is_bot_update(ticket, config) -> bool:
    """Check if this webhook was triggered by the bot's own update.

    Uses the configured bot user ID if available, otherwise checks
    if the latest comment was authored by the same user as the updater.
    """
    bot_user_id = config.zendesk_bot_user_id
    if bot_user_id is not None and ticket.updater_id is not None:
        if ticket.updater_id == bot_user_id:
            return True

    # Fallback: if updater_id matches latest_comment author_id and that
    # comment is an internal note, it's likely the bot's own update
    if (
        ticket.updater_id is not None
        and ticket.latest_comment is not None
        and ticket.latest_comment.author_id == ticket.updater_id
        and not ticket.latest_comment.public
        and ticket.latest_comment.body
        and "[PII Redaction Gateway]" in ticket.latest_comment.body
    ):
        return True

    return False


def _build_scan_fields(ticket, api_comments, scan_mode):
    """Build the dict of fields to scan and comment metadata map.

    Args:
        ticket: Parsed ZendeskTicket.
        api_comments: Comments fetched from Zendesk API.
        scan_mode: "full" or "incremental".

    Returns:
        Tuple of (fields_to_scan dict, comment_field_map dict).
    """
    fields_to_scan: dict[str, str] = {}
    comment_field_map: dict[str, dict] = {}

    if scan_mode == "full":
        # Full scan: subject, description, all comments, custom fields
        fields_to_scan = _extract_scannable_fields(ticket)

        for comment in api_comments:
            body = comment.get("body", "")
            comment_id = comment.get("id")
            if body and body.strip() and comment_id:
                field_key = f"api_comment_{comment_id}"
                fields_to_scan[field_key] = body
                comment_field_map[field_key] = {
                    "comment_id": comment_id,
                    "original_text": body,
                }
    else:
        # Incremental scan: only the latest comment (the new content)
        # Also scan subject/description in case they were edited
        if ticket.subject and ticket.subject.strip():
            fields_to_scan["subject"] = ticket.subject
        if ticket.description and ticket.description.strip():
            fields_to_scan["description"] = ticket.description

        # Scan latest comment from webhook payload
        if ticket.latest_comment and ticket.latest_comment.body:
            lc = ticket.latest_comment
            # Skip if this is an internal note from the bot
            if not (not lc.public and lc.body and "[PII Redaction Gateway]" in lc.body):
                fields_to_scan["latest_comment"] = lc.body
                if lc.id:
                    comment_field_map["latest_comment"] = {
                        "comment_id": lc.id,
                        "original_text": lc.body,
                    }

        # Also check the most recent API comment (may be the new one)
        if api_comments:
            latest_api = api_comments[-1]
            body = latest_api.get("body", "")
            comment_id = latest_api.get("id")
            if body and body.strip() and comment_id:
                field_key = f"api_comment_{comment_id}"
                # Don't duplicate if already scanned via latest_comment
                if field_key not in fields_to_scan and "latest_comment" not in fields_to_scan:
                    fields_to_scan[field_key] = body
                    comment_field_map[field_key] = {
                        "comment_id": comment_id,
                        "original_text": body,
                    }
                elif field_key not in fields_to_scan:
                    # Add API comment for redaction tracking even if we already
                    # scanned it via latest_comment (for the comment_id mapping)
                    if (
                        "latest_comment" in comment_field_map
                        and comment_field_map["latest_comment"].get("comment_id") != comment_id
                    ):
                        fields_to_scan[field_key] = body
                        comment_field_map[field_key] = {
                            "comment_id": comment_id,
                            "original_text": body,
                        }

    return fields_to_scan, comment_field_map


def _extract_scannable_fields(ticket) -> dict[str, str]:
    """Extract all text fields from a ticket for full PII scanning."""
    fields = {}

    if ticket.subject and ticket.subject.strip():
        fields["subject"] = ticket.subject
    if ticket.description and ticket.description.strip():
        fields["description"] = ticket.description

    # Scan latest comment if present
    if ticket.latest_comment and ticket.latest_comment.body:
        fields["latest_comment"] = ticket.latest_comment.body

    # Scan all comments from webhook payload
    for i, comment in enumerate(ticket.comments):
        if comment.body and comment.body.strip():
            fields[f"comment_{i}"] = comment.body

    # Scan custom fields with string values
    for cf in ticket.custom_fields:
        value = cf.get("value", "")
        if isinstance(value, str) and value.strip():
            field_id = cf.get("id", f"custom_{id(cf)}")
            fields[f"custom_field_{field_id}"] = value

    return fields


def _build_comment_redactions(results, comment_field_map) -> list[dict]:
    """Extract PII substrings from comment results for the Zendesk Redaction API."""
    comment_redactions = []
    for field_key, meta in comment_field_map.items():
        if field_key in results and results[field_key].redaction_count > 0:
            original_text = meta["original_text"]
            redact_strings = [
                entity.extract_original(original_text)
                for entity in results[field_key].entities_found
            ]
            redact_strings = [s for s in redact_strings if s]
            if redact_strings:
                comment_redactions.append({
                    "comment_id": meta["comment_id"],
                    "redact_strings": redact_strings,
                })
    return comment_redactions


def _write_audit_log(
    ticket_id: int,
    results: dict,
    request_id: str,
    llm_provider: str,
    processing_time_ms: float,
    scan_mode: str,
    config,
) -> None:
    """Write audit log entry to S3.

    The audit record contains ONLY metadata about what was redacted —
    no actual PII values are stored.
    """
    now = datetime.now(timezone.utc)

    audit_record = {
        "ticket_id": str(ticket_id),
        "timestamp": now.isoformat(),
        "request_id": request_id,
        "scan_mode": scan_mode,
        "llm_provider_used": llm_provider,
        "processing_time_ms": processing_time_ms,
        "total_redactions": sum(r.redaction_count for r in results.values()),
        "redaction_summary": [],
    }

    for field_name, result in results.items():
        for entity in result.entities_found:
            audit_record["redaction_summary"].append({
                "field": field_name,
                **entity.to_audit_dict(),
            })

    # Write to S3
    s3_key = (
        f"audit/{now.year}/{now.month:02d}/{now.day:02d}/"
        f"{ticket_id}_{now.strftime('%H%M%S')}_{request_id}.json"
    )

    try:
        s3 = boto3.client("s3", region_name=config.aws_region)
        s3.put_object(
            Bucket=config.audit_s3_bucket,
            Key=s3_key,
            Body=json.dumps(audit_record, default=str),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        logger.info(
            "Audit log written to S3",
            extra={"extra_fields": {"s3_key": s3_key}},
        )
    except Exception as e:
        logger.error(
            f"Failed to write audit log to S3: {e}",
            extra={"extra_fields": {"s3_key": s3_key}},
        )


def _response(status_code: int, body: dict) -> dict:
    """Build an API Gateway Lambda proxy response."""
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "X-Content-Type-Options": "nosniff",
        },
        "body": json.dumps(body, default=str),
    }
