"""Shared test fixtures and constants."""

import pytest

TEST_API_KEY = "ss_test_abc123def456ghi789jkl012mno345pqr678stu901vwx"
TEST_BASE_URL = "https://api.classifinder.tech"

SCAN_RESPONSE_JSON = {
    "request_id": "req_a1b2c3d4e5f6",
    "scan_time_ms": 7,
    "findings_count": 1,
    "findings": [
        {
            "id": "f_001",
            "type": "aws_access_key",
            "type_name": "AWS Access Key ID",
            "provider": "aws",
            "severity": "critical",
            "confidence": 0.98,
            "value_preview": "AKIA****MPLE",
            "span": {"start": 22, "end": 42},
            "context": "...AWS_ACCESS_KEY_ID=AKIA****MPLE...",
            "is_likely_test_value": False,
            "recommendation": "Rotate this key immediately.",
            "matched_pattern": "aws_access_key_v1",
        }
    ],
    "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
}

REDACT_RESPONSE_JSON = {
    "request_id": "req_x9y8z7w6v5u4",
    "scan_time_ms": 8,
    "findings_count": 1,
    "redacted_text": "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]",
    "findings": [
        {
            "id": "f_001",
            "type": "aws_access_key",
            "severity": "critical",
            "confidence": 0.98,
            "span": {"start": 22, "end": 42},
            "redacted_as": "[AWS_ACCESS_KEY_REDACTED]",
        }
    ],
    "summary": {"critical": 1, "high": 0, "medium": 0, "low": 0},
}

TYPES_RESPONSE_JSON = {
    "types_count": 1,
    "types": [
        {
            "id": "aws_access_key",
            "name": "AWS Access Key ID",
            "provider": "aws",
            "severity": "critical",
            "description": "AWS IAM access key.",
            "tags": ["cloud", "aws"],
        }
    ],
}

HEALTH_RESPONSE_JSON = {
    "status": "healthy",
    "version": "1.0.0",
    "patterns_loaded": 46,
    "uptime_seconds": 3600,
}

FEEDBACK_RESPONSE_JSON = {
    "feedback_id": "fb_abc123",
    "status": "received",
}

ERROR_401_JSON = {
    "error": {
        "code": "invalid_api_key",
        "message": "Missing, malformed, or revoked API key.",
        "retry_after": None,
    }
}

ERROR_400_JSON = {
    "error": {
        "code": "payload_too_large",
        "message": "Text size exceeds the limit.",
        "retry_after": None,
    }
}

ERROR_403_JSON = {
    "error": {
        "code": "tier_limit_exceeded",
        "message": "Feature not available on current tier.",
        "retry_after": None,
    }
}

ERROR_429_JSON = {
    "error": {
        "code": "rate_limit_exceeded",
        "message": "Rate limit exceeded.",
        "retry_after": 30,
    }
}

ERROR_500_JSON = {
    "error": {
        "code": "internal_error",
        "message": "An unexpected error occurred.",
        "retry_after": None,
    }
}
