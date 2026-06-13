"""ClassiFinder SDK exception hierarchy."""

from __future__ import annotations

from typing import Any


class ClassiFinderError(Exception):
    """Base exception for all ClassiFinder SDK errors."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class AuthenticationError(ClassiFinderError):
    """401 — Invalid or missing API key."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=401)


class RateLimitError(ClassiFinderError):
    """429 — Rate limit exceeded."""

    def __init__(self, message: str, retry_after: int = 0) -> None:
        self.retry_after = retry_after
        super().__init__(message, status_code=429)


class InvalidRequestError(ClassiFinderError):
    """400 — Bad request (malformed input, payload too large, etc.)."""

    def __init__(self, message: str, code: str = "invalid_request") -> None:
        self.code = code
        super().__init__(message, status_code=400)


class ForbiddenError(ClassiFinderError):
    """403 — Feature not available on current tier."""

    def __init__(self, message: str, code: str = "tier_limit_exceeded") -> None:
        self.code = code
        super().__init__(message, status_code=403)


class ServerError(ClassiFinderError):
    """500 — Unexpected server-side error."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=500)


class APIConnectionError(ClassiFinderError):
    """Network failure, timeout, or DNS resolution failure."""

    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=None)


class SecretsDetectedError(ClassiFinderError):
    """Raised by ClassiFinderGuard in block mode when secrets are found."""

    def __init__(self, message: str, findings_count: int, findings: Any, summary: Any) -> None:
        self.findings_count = findings_count
        self.findings = findings
        self.summary = summary
        super().__init__(message, status_code=None)


class PromptInjectionDetectedError(ClassiFinderError):
    """Raised by ClassiFinderGuard when a prompt-injection marker is found and
    ``block_on_injection`` is enabled.

    ``markers`` is the list of prompt-injection type ids that fired (e.g.
    ``["pi_tool_call_injection"]``); ``findings`` carries the underlying
    finding objects for inspection / logging.
    """

    def __init__(self, message: str, markers: Any, findings: Any) -> None:
        self.markers = markers
        self.findings = findings
        super().__init__(message, status_code=None)
