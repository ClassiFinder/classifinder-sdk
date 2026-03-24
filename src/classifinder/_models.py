"""Pydantic v2 response models for the ClassiFinder API."""

from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Span(_Base):
    start: int
    end: int


class SeveritySummary(_Base):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class Finding(_Base):
    id: str
    type: str
    type_name: str
    provider: str
    severity: str
    confidence: float
    value_preview: str
    span: Span
    context: Optional[str] = None
    is_likely_test_value: bool
    recommendation: str
    matched_pattern: str


class RedactFinding(_Base):
    id: str
    type: str
    severity: str
    confidence: float
    span: Span
    redacted_as: str


class TypeInfo(_Base):
    id: str
    name: str
    provider: str
    severity: str
    description: str
    tags: List[str] = []


class ScanResult(_Base):
    request_id: str
    scan_time_ms: int
    findings_count: int
    findings: List[Finding]
    summary: SeveritySummary


class RedactResult(_Base):
    request_id: str
    scan_time_ms: int
    findings_count: int
    redacted_text: str
    findings: List[RedactFinding]
    summary: SeveritySummary


class TypesResult(_Base):
    types_count: int
    types: List[TypeInfo]


class HealthResult(_Base):
    status: str
    version: str
    patterns_loaded: int
    uptime_seconds: int


class FeedbackResult(_Base):
    feedback_id: str
    status: str
