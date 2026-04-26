"""Synchronous ClassiFinder client."""

from __future__ import annotations

from typing import Any

import httpx

from ._base import (
    DEFAULT_BASE_URL,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    build_headers,
    is_retryable,
    raise_for_status,
    resolve_api_key,
    sleep_for_retry,
)
from ._exceptions import APIConnectionError
from ._models import (
    FeedbackResult,
    HealthResult,
    RedactResult,
    ScanResult,
    TypesResult,
)


class ClassiFinder:
    """Synchronous client for the ClassiFinder API."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
        http2: bool = False,
        limits: httpx.Limits | None = None,
    ) -> None:
        """Construct a synchronous ClassiFinder client.

        http2: enable HTTP/2 negotiation. Defaults to False to preserve the
            existing wire behavior for callers who don't opt in. Setting
            http2=True requires the [http2] extra (httpx pulls h2 from there).
        limits: pass-through to httpx.Client(limits=). Useful for tuning the
            connection pool when fanning out many concurrent requests
            (e.g., from a CLI like cfsniff). Default leaves httpx's defaults.
        """
        self._api_key = resolve_api_key(api_key)
        self._base_url = base_url.rstrip("/")
        self._max_retries = max_retries
        self._client = httpx.Client(
            headers=build_headers(self._api_key),
            timeout=timeout,
            http2=http2,
            limits=limits if limits is not None else httpx.Limits(),
        )

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> ClassiFinder:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Make an HTTP request with retry logic."""
        url = f"{self._base_url}{path}"
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.request(method, url, **kwargs)
                raise_for_status(response)
                return response
            except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
                api_exc = APIConnectionError(str(exc))
                last_exc = api_exc
                if attempt >= self._max_retries:
                    raise api_exc from exc
                sleep_for_retry(attempt, api_exc)
            except Exception as exc:
                last_exc = exc
                if not is_retryable(exc) or attempt >= self._max_retries:
                    raise
                sleep_for_retry(attempt, exc)

        assert last_exc is not None  # pragma: no cover
        raise last_exc  # pragma: no cover

    def scan(
        self,
        text: str,
        types: list[str] | None = None,
        min_confidence: float = 0.5,
        include_context: bool = True,
    ) -> ScanResult:
        """Scan text for secrets."""
        body = {
            "text": text,
            "types": types or ["all"],
            "min_confidence": min_confidence,
            "include_context": include_context,
        }
        response = self._request("POST", "/v1/scan", json=body)
        return ScanResult.model_validate(response.json())

    def redact(
        self,
        text: str,
        types: list[str] | None = None,
        min_confidence: float = 0.5,
        redaction_style: str = "label",
    ) -> RedactResult:
        """Scan and redact secrets from text."""
        body = {
            "text": text,
            "types": types or ["all"],
            "min_confidence": min_confidence,
            "redaction_style": redaction_style,
        }
        response = self._request("POST", "/v1/redact", json=body)
        return RedactResult.model_validate(response.json())

    def get_types(self) -> TypesResult:
        """List all detectable secret types."""
        response = self._request("GET", "/v1/types")
        return TypesResult.model_validate(response.json())

    def health(self) -> HealthResult:
        """Check API health."""
        response = self._request("GET", "/v1/health")
        return HealthResult.model_validate(response.json())

    def feedback(
        self,
        request_id: str,
        finding_id: str,
        feedback_type: str,
        comment: str | None = None,
    ) -> FeedbackResult:
        """Report a false positive or false negative."""
        body = {
            "request_id": request_id,
            "finding_id": finding_id,
            "feedback_type": feedback_type,
        }
        if comment is not None:
            body["comment"] = comment
        response = self._request("POST", "/v1/feedback", json=body)
        return FeedbackResult.model_validate(response.json())
