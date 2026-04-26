"""Tests for the asynchronous AsyncClassiFinder client."""

import httpx
import pytest
import respx

from classifinder._async_client import AsyncClassiFinder
from classifinder._exceptions import AuthenticationError
from conftest import (
    FEEDBACK_RESPONSE_JSON,
    HEALTH_RESPONSE_JSON,
    REDACT_RESPONSE_JSON,
    SCAN_RESPONSE_JSON,
    TEST_API_KEY,
    TEST_BASE_URL,
    TYPES_RESPONSE_JSON,
)


class TestAsyncConstruction:
    def test_requires_api_key(self):
        with pytest.raises(AuthenticationError, match="No API key"):
            AsyncClassiFinder()

    async def test_async_context_manager(self):
        async with AsyncClassiFinder(api_key=TEST_API_KEY) as client:
            assert client._api_key == TEST_API_KEY

    async def test_http2_default_false_preserves_existing_behavior(self):
        """Default http2=False — h2 must not be negotiated unless caller opts in."""
        client = AsyncClassiFinder(api_key=TEST_API_KEY)
        assert client._client._transport._pool._http2 is False
        await client.close()

    async def test_http2_true_enables_negotiation(self):
        """http2=True propagates to the underlying httpx.AsyncClient."""
        client = AsyncClassiFinder(api_key=TEST_API_KEY, http2=True)
        assert client._client._transport._pool._http2 is True
        await client.close()

    async def test_custom_limits_pass_through(self):
        """A user-supplied httpx.Limits is honored (not silently overridden)."""
        custom = httpx.Limits(max_connections=50, max_keepalive_connections=20)
        client = AsyncClassiFinder(api_key=TEST_API_KEY, limits=custom)
        assert client._client._transport._pool._max_connections == 50
        assert client._client._transport._pool._max_keepalive_connections == 20
        await client.close()

    async def test_default_limits_when_none_supplied(self):
        """Omitting limits= uses httpx defaults — does not raise."""
        client = AsyncClassiFinder(api_key=TEST_API_KEY)
        assert client._client._transport._pool is not None
        await client.close()

    @respx.mock
    async def test_http2_enabled_request_round_trip(self):
        """End-to-end: http2=True doesn't break the request path under respx mock."""
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(
            api_key=TEST_API_KEY, base_url=TEST_BASE_URL, http2=True
        ) as client:
            result = await client.scan("any text")
        assert result.findings_count == 1


class TestAsyncScan:
    @respx.mock
    async def test_scan_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.scan("some text")
        assert result.request_id == "req_a1b2c3d4e5f6"
        assert result.findings[0].type == "aws_access_key"


class TestAsyncRedact:
    @respx.mock
    async def test_redact_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=REDACT_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.redact("secret text")
        assert result.redacted_text == "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]"


class TestAsyncGetTypes:
    @respx.mock
    async def test_returns_typed_result(self):
        respx.get(f"{TEST_BASE_URL}/v1/types").mock(
            return_value=httpx.Response(200, json=TYPES_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.get_types()
        assert result.types_count == 1


class TestAsyncHealth:
    @respx.mock
    async def test_returns_typed_result(self):
        respx.get(f"{TEST_BASE_URL}/v1/health").mock(
            return_value=httpx.Response(200, json=HEALTH_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.health()
        assert result.status == "healthy"


class TestAsyncFeedback:
    @respx.mock
    async def test_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/feedback").mock(
            return_value=httpx.Response(202, json=FEEDBACK_RESPONSE_JSON)
        )
        async with AsyncClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = await client.feedback(
                request_id="req_abc", finding_id="f_001", feedback_type="false_positive"
            )
        assert result.feedback_id == "fb_abc123"
