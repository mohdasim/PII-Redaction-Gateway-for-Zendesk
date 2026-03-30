"""Main Lambda handler for the PII Redaction Gateway webhook.

Flow:
1. Authenticate the incoming request
2. Parse the Zendesk webhook payload
3. Check for recursive processing (skip if already redacted)
4. Extract text fields to scan
5. Run the two-layer PII detection and redaction pipeline
6. Update the Zendesk ticket with redacted content
7. Write audit log to S3
8. Return success response
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


def lambda_handler(event: dict, context) -> dict:
    """AWS Lambda entry point for webhook processing.

    Args:
        event: API Gateway Lambda proxy integration event.
        context: Lambda context object.

    Returns:
        API Gateway response dict.
    """
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

    # 3. Prevent recursive processing
    if "pii-redacted" in ticket.tags:
        logger.info(
            "Ticket already redacted, skipping",
            extra={"extra_fields": {"ticket_id": ticket.id}},
        )
        return _response(200, {"status": "skipped", "reason": "already_redacted"})

    # 4. Extract text fields to scan
    fields_to_scan = _extract_scannable_fields(ticket)
    if not fields_to_scan:
        return _response(200, {"status": "skipped", "reason": "no_text_fields"})

    # 5. Detect and redact PII
    pii_detector = PIIDetector(config)
    results = {}
    total_redactions = 0

    for field_name, text in fields_to_scan.items():
        result = pii_detector.detect_and_redact(text)
        results[field_name] = result
        total_redactions += result.redaction_count

    # 6. Update Zendesk if PII was found
    if total_redactions > 0:
        try:
            zendesk = ZendeskClient(
                subdomain=config.zendesk_subdomain,
                email=config.zendesk_email,
                api_token=config.zendesk_api_token.get_secret_value(),
            )

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

            zendesk.apply_redactions(
                ticket_id=ticket.id,
                redacted_subject=redacted_subject,
                redacted_description=redacted_description,
                total_redactions=total_redactions,
            )
        except Exception as e:
            logger.error(
                f"Failed to update Zendesk: {e}",
                extra={"extra_fields": {"ticket_id": ticket.id}},
            )

    # 7. Write audit log to S3
    processing_time_ms = round((time.time() - start_time) * 1000, 1)
    _write_audit_log(
        ticket_id=ticket.id,
        results=results,
        request_id=request_id,
        llm_provider=pii_detector.llm_provider_name,
        processing_time_ms=processing_time_ms,
        config=config,
    )

    # 8. Return response
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
    """Extract text fields from a ticket that need PII scanning."""
    fields = {}

    if ticket.subject and ticket.subject.strip():
        fields["subject"] = ticket.subject
    if ticket.description and ticket.description.strip():
        fields["description"] = ticket.description

    # Scan latest comment if present
    if ticket.latest_comment and ticket.latest_comment.body:
        fields["latest_comment"] = ticket.latest_comment.body

    # Scan all comments
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


def _write_audit_log(
    ticket_id: int,
    results: dict,
    request_id: str,
    llm_provider: str,
    processing_time_ms: float,
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
        # Audit log failure should not break the pipeline
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
