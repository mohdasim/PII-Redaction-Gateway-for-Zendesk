"""Health check Lambda handler.

Simple endpoint for monitoring and load balancer health checks.
"""

from __future__ import annotations

import json


def lambda_handler(event: dict, context) -> dict:
    """Health check endpoint.

    Args:
        event: API Gateway Lambda proxy integration event.
        context: Lambda context object.

    Returns:
        API Gateway response with health status.
    """
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": json.dumps({
            "status": "healthy",
            "service": "pii-redaction-gateway",
            "version": "1.0.0",
        }),
    }
