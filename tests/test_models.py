"""Tests for Pydantic response models."""

from classifinder._models import (
    FeedbackResult,
    HealthResult,
    RedactResult,
    ScanResult,
    TypesResult,
)
from conftest import (
    FEEDBACK_RESPONSE_JSON,
    HEALTH_RESPONSE_JSON,
    REDACT_RESPONSE_JSON,
    SCAN_RESPONSE_JSON,
    TYPES_RESPONSE_JSON,
)


class TestScanResult:
    def test_parse_from_json(self):
        result = ScanResult.model_validate(SCAN_RESPONSE_JSON)
        assert result.request_id == "req_a1b2c3d4e5f6"
        assert result.scan_time_ms == 7
        assert result.findings_count == 1
        assert len(result.findings) == 1
        assert result.summary.critical == 1

    def test_finding_fields(self):
        result = ScanResult.model_validate(SCAN_RESPONSE_JSON)
        f = result.findings[0]
        assert f.type == "aws_access_key"
        assert f.type_name == "AWS Access Key ID"
        assert f.provider == "aws"
        assert f.severity == "critical"
        assert f.confidence == 0.98
        assert f.value_preview == "AKIA****MPLE"
        assert f.span.start == 22
        assert f.span.end == 42
        assert f.is_likely_test_value is False

    def test_ignores_extra_fields(self):
        data = {**SCAN_RESPONSE_JSON, "new_future_field": "ignored"}
        result = ScanResult.model_validate(data)
        assert result.request_id == "req_a1b2c3d4e5f6"

    def test_safe_mcp_ids_default_empty(self):
        # AWS secret finding — no SAFE-T mapping; field must default to empty list.
        result = ScanResult.model_validate(SCAN_RESPONSE_JSON)
        assert result.findings[0].safe_mcp_ids == []

    def test_safe_mcp_ids_deserializes(self):
        # Prompt-injection finding with SAFE-T mapping populated.
        pi_response = {
            **SCAN_RESPONSE_JSON,
            "findings": [
                {
                    **SCAN_RESPONSE_JSON["findings"][0],
                    "type": "pi_role_hijack_marker",
                    "provider": "prompt_injection",
                    "matched_pattern": "pi_role_hijack_marker_v1",
                    "safe_mcp_ids": ["SAFE-T1001", "SAFE-T1102"],
                }
            ],
        }
        result = ScanResult.model_validate(pi_response)
        assert result.findings[0].safe_mcp_ids == ["SAFE-T1001", "SAFE-T1102"]


class TestRedactResult:
    def test_parse_from_json(self):
        result = RedactResult.model_validate(REDACT_RESPONSE_JSON)
        assert result.redacted_text == "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]"
        assert result.findings_count == 1
        assert result.findings[0].redacted_as == "[AWS_ACCESS_KEY_REDACTED]"

    def test_redact_finding_fields(self):
        result = RedactResult.model_validate(REDACT_RESPONSE_JSON)
        f = result.findings[0]
        assert f.type == "aws_access_key"
        assert f.severity == "critical"
        assert f.span.start == 22


class TestTypesResult:
    def test_parse_from_json(self):
        result = TypesResult.model_validate(TYPES_RESPONSE_JSON)
        assert result.types_count == 1
        assert result.types[0].id == "aws_access_key"
        assert result.types[0].tags == ["cloud", "aws"]


class TestHealthResult:
    def test_parse_from_json(self):
        result = HealthResult.model_validate(HEALTH_RESPONSE_JSON)
        assert result.status == "healthy"
        assert result.patterns_loaded == 46


class TestFeedbackResult:
    def test_parse_from_json(self):
        result = FeedbackResult.model_validate(FEEDBACK_RESPONSE_JSON)
        assert result.feedback_id == "fb_abc123"
        assert result.status == "received"
