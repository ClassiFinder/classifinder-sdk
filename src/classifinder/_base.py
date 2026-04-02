"""Shared logic for sync and async clients: error mapping, retry, request building."""

from __future__ import annotations

import asyncio
import os
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx

from ._exceptions import (
    APIConnectionError,
    AuthenticationError,
    ClassiFinderError,
    ForbiddenError,
    InvalidRequestError,
    RateLimitError,
    ServerError,
)

DEFAULT_BASE_URL = "https://api.classifinder.ai"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2

_RETRYABLE_STATUS_CODES = {429, 500}


def resolve_api_key(api_key: str | None) -> str:
    """Resolve API key from argument or CLASSIFINDER_API_KEY env var."""
    key = api_key or os.environ.get("CLASSIFINDER_API_KEY")
    if not key:
        raise AuthenticationError(
            "No API key provided. Pass api_key= or set the "
            "CLASSIFINDER_API_KEY environment variable."
        )
    return key


def build_headers(api_key: str) -> dict[str, str]:
    """Build default request headers."""
    return {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }


def raise_for_status(response: httpx.Response) -> None:
    """Raise the appropriate ClassiFinderError for non-2xx responses."""
    if response.status_code < 400:
        return

    try:
        body = response.json()
        error = body.get("error", {})
        message = error.get("message", response.text)
        code = error.get("code", "")
        retry_after = error.get("retry_after")
    except Exception:
        message = response.text or f"HTTP {response.status_code}"
        code = ""
        retry_after = None

    status = response.status_code

    if status == 401:
        raise AuthenticationError(message)
    elif status == 400:
        raise InvalidRequestError(message, code=code)
    elif status == 403:
        raise ForbiddenError(message, code=code)
    elif status == 429:
        raise RateLimitError(message, retry_after=retry_after or 0)
    elif status >= 500:
        raise ServerError(message)
    else:
        raise ClassiFinderError(message, status_code=status)


def is_retryable(exc: Exception) -> bool:
    """Check if an exception is retryable."""
    return isinstance(exc, (RateLimitError, ServerError, APIConnectionError))


def get_retry_delay(attempt: int, exc: Exception) -> float:
    """Calculate delay before next retry attempt."""
    if isinstance(exc, RateLimitError) and exc.retry_after > 0:
        return float(exc.retry_after)
    return float(2**attempt)


def sleep_for_retry(attempt: int, exc: Exception) -> None:
    """Sleep before a sync retry."""
    delay = get_retry_delay(attempt, exc)
    time.sleep(delay)


async def async_sleep_for_retry(attempt: int, exc: Exception) -> None:
    """Sleep before an async retry."""
    delay = get_retry_delay(attempt, exc)
    await asyncio.sleep(delay)
