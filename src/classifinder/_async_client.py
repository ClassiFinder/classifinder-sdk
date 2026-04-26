"""Asynchronous ClassiFinder client."""

from __future__ import annotations

from typing import Any

import httpx

from ._base import (
    DEFAULT_BASE_URL,
    DEFAULT_MAX_RETRIES,
    DEFAULT_TIMEOUT,
    async_sleep_for_retry,
    build_headers,
    is_retryable,
    raise_for_status,
    resolve_api_key,
)
from ._exceptions import APIConnectionError
from ._models import (
    FeedbackResult,
    HealthResult,
    RedactResult,
    ScanResult,
    TypesResult,
)


class AsyncClassiFinder:
    """Asynchronous client for the ClassiFinder API."""

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT,
        http2: bool = False,
        limits: httpx.Limits | None = None,
    ) -> None:
        """Construct an asynchronous ClassiFinder client.

        http2: enable HTTP/2 negotiation. Defaults to False to preserve the
            existing wire behavior for callers who don't opt in. Setting
            http2=True requires the [http2] extra (httpx pulls h2 from there).
        limits: pass-through to httpx.AsyncClient(limits=). Useful for tuning
            the connection pool when running large semaphores of concurrent
            scans. Default leaves httpx's defaults.
        """
        self._api_key = resolve_api_key(api_key)
        self._base_url = base_url.rstrip("/")
        self._max_retries = max_retries
        self._client = httpx.AsyncClient(
            headers=build_headers(self._api_key),
            timeout=timeout,
            http2=http2,
            limits=limits if limits is not None else httpx.Limits(),
        )

    async def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        await self._client.aclose()

    async def __aenter__(self) -> AsyncClassiFinder:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Make an HTTP request with retry logic."""
        url = f"{self._base_url}{path}"
        last_exc: Exception | None = None

        for attempt in range(self._max_retries + 1):
            try:
                response = await self._client.request(method, url, **kwargs)
                raise_for_status(response)
                return response
            except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError) as exc:
                api_exc = APIConnectionError(str(exc))
                last_exc = api_exc
                if attempt >= self._max_retries:
                    raise api_exc from exc
                await async_sleep_for_retry(attempt, api_exc)
            except Exception as exc:
                last_exc = exc
                if not is_retryable(exc) or attempt >= self._max_retries:
                    raise
                await async_sleep_for_retry(attempt, exc)

        assert last_exc is not None  # pragma: no cover
        raise last_exc  # pragma: no cover

    async def scan(
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
        response = await self._request("POST", "/v1/scan", json=body)
        return ScanResult.model_validate(response.json())

    async def redact(
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
        response = await self._request("POST", "/v1/redact", json=body)
        return RedactResult.model_validate(response.json())

    async def get_types(self) -> TypesResult:
        """List all detectable secret types."""
        response = await self._request("GET", "/v1/types")
        return TypesResult.model_validate(response.json())

    async def health(self) -> HealthResult:
        """Check API health."""
        response = await self._request("GET", "/v1/health")
        return HealthResult.model_validate(response.json())

    async def feedback(
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
        response = await self._request("POST", "/v1/feedback", json=body)
        return FeedbackResult.model_validate(response.json())
