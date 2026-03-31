"""Main Lambda handler for the PII Redaction Gateway webhook.

Runs PII redaction when a Zendesk ticket is solved. Uses simple tag-based
loop prevention: tickets already tagged "pii-redacted" are skipped.

Flow:
1. Authenticate the incoming request
2. Parse the Zendesk webhook payload
3. Check if ticket status is "solved" — skip if not
4. Check if "pii-redacted" tag is present — skip if already processed
5. Initialize Zendesk client
6. Fetch ALL comments for the ticket from Zendesk API
7. Extract text fields to scan (subject, description, all comments, custom fields)
8. Run the two-layer PII detection and redaction pipeline
9. Update Zendesk: redact content + add "pii-redacted" tag
10. Write audit log to S3
11. Return success response
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

TAG_REDACTED = "pii-redacted"


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

    # 3. Check if ticket is solved
    if ticket.status.lower() != "solved":
        logger.info(
            "Ticket not solved, skipping",
            extra={"extra_fields": {"ticket_id": ticket.id, "status": ticket.status}},
        )
        return _response(200, {"status": "skipped", "reason": "not_solved", "ticket_status": ticket.status})

    # 4. Tag-based loop prevention
    if TAG_REDACTED in ticket.tags:
        logger.info(
            "Ticket already redacted, skipping",
            extra={"extra_fields": {"ticket_id": ticket.id}},
        )
        return _response(200, {"status": "skipped", "reason": "already_redacted"})

    logger.info(
        "Processing solved ticket",
        extra={"extra_fields": {"ticket_id": ticket.id}},
    )

    # 5. Initialize Zendesk client
    zendesk = ZendeskClient(
        subdomain=config.zendesk_subdomain,
        email=config.zendesk_email,
        api_token=config.zendesk_api_token.get_secret_value(),
    )

    # 6. Fetch ALL comments for this ticket from Zendesk API
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

    # 7. Extract text fields to scan
    fields_to_scan = _extract_scannable_fields(ticket)
    comment_field_map: dict[str, dict] = {}

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

    if not fields_to_scan:
        return _response(200, {"status": "skipped", "reason": "no_text_fields"})

    # 8. Detect and redact PII in all fields
    pii_detector = PIIDetector(config)
    results = {}
    total_redactions = 0

    for field_name, text in fields_to_scan.items():
        result = pii_detector.detect_and_redact(text)
        results[field_name] = result
        total_redactions += result.redaction_count

    # 9. Update Zendesk if PII was found
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

    # 10. Write audit log to S3
    processing_time_ms = round((time.time() - start_time) * 1000, 1)
    _write_audit_log(
        ticket_id=ticket.id,
        results=results,
        request_id=request_id,
        llm_provider=pii_detector.llm_provider_name,
        processing_time_ms=processing_time_ms,
        config=config,
    )

    # 11. Return response
    logger.info(
        "Processing complete",
        extra={"extra_fields": {
            "ticket_id": ticket.id,
            "total_redactions": total_redactions,
            "processing_ms": processing_time_ms,
        }},
    )

    return _response(200, {
        "status": "processed",
        "ticket_id": ticket.id,
        "total_redactions": total_redactions,
        "processing_time_ms": processing_time_ms,
    })


def _extract_scannable_fields(ticket) -> dict[str, str]:
    """Extract all text fields from a ticket for PII scanning."""
    fields = {}

    if ticket.subject and ticket.subject.strip():
        fields["subject"] = ticket.subject
    if ticket.description and ticket.description.strip():
        fields["description"] = ticket.description

    if ticket.latest_comment and ticket.latest_comment.body:
        fields["latest_comment"] = ticket.latest_comment.body

    for i, comment in enumerate(ticket.comments):
        if comment.body and comment.body.strip():
            fields[f"comment_{i}"] = comment.body

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
    config,
) -> None:
    """Write audit log entry to S3. No actual PII values are stored."""
    now = datetime.now(timezone.utc)

    audit_record = {
        "ticket_id": str(ticket_id),
        "timestamp": now.isoformat(),
        "request_id": request_id,
        "trigger": "ticket_solved",
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
