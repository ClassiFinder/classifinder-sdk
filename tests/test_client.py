"""Tests for the synchronous ClassiFinder client."""

import json

import httpx
import pytest
import respx

from classifinder._client import ClassiFinder
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


class TestClientConstruction:
    def test_requires_api_key(self):
        with pytest.raises(AuthenticationError, match="No API key"):
            ClassiFinder()

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("CLASSIFINDER_API_KEY", TEST_API_KEY)
        client = ClassiFinder()
        assert client._api_key == TEST_API_KEY
        client.close()

    def test_custom_base_url(self):
        client = ClassiFinder(api_key=TEST_API_KEY, base_url="https://custom.example.com")
        assert client._base_url == "https://custom.example.com"
        client.close()

    def test_context_manager(self):
        with ClassiFinder(api_key=TEST_API_KEY) as client:
            assert client._api_key == TEST_API_KEY

    def test_http2_default_false_preserves_existing_behavior(self):
        """Default http2=False — h2 must not be negotiated unless caller opts in."""
        client = ClassiFinder(api_key=TEST_API_KEY)
        # Path is httpx-version-specific (probed against httpx 0.28+).
        # If a future httpx changes _transport._pool layout this will fail loudly.
        assert client._client._transport._pool._http2 is False
        client.close()

    def test_http2_true_enables_negotiation(self):
        """http2=True propagates to the underlying httpx.Client."""
        client = ClassiFinder(api_key=TEST_API_KEY, http2=True)
        assert client._client._transport._pool._http2 is True
        client.close()

    def test_custom_limits_pass_through(self):
        """A user-supplied httpx.Limits is honored (not silently overridden)."""
        custom = httpx.Limits(max_connections=50, max_keepalive_connections=20)
        client = ClassiFinder(api_key=TEST_API_KEY, limits=custom)
        assert client._client._transport._pool._max_connections == 50
        assert client._client._transport._pool._max_keepalive_connections == 20
        client.close()

    def test_default_limits_when_none_supplied(self):
        """Omitting limits= uses httpx defaults — does not raise."""
        client = ClassiFinder(api_key=TEST_API_KEY)
        # Don't assert specific values (httpx defaults can change across versions),
        # just confirm the pool exists and construction succeeded.
        assert client._client._transport._pool is not None
        client.close()

    @respx.mock
    def test_http2_enabled_request_round_trip(self):
        """End-to-end: http2=True doesn't break the request path under respx mock."""
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, http2=True) as client:
            result = client.scan("any text")
        assert result.findings_count == 1


class TestScan:
    @respx.mock
    def test_scan_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = client.scan("some text with secrets")
        assert result.request_id == "req_a1b2c3d4e5f6"
        assert result.findings_count == 1
        assert result.findings[0].type == "aws_access_key"

    @respx.mock
    def test_scan_sends_correct_body(self):
        route = respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            client.scan(
                "test text", types=["aws_access_key"], min_confidence=0.8, include_context=False
            )
        body = route.calls[0].request.content
        parsed = json.loads(body)
        assert parsed["text"] == "test text"
        assert parsed["types"] == ["aws_access_key"]
        assert parsed["min_confidence"] == 0.8
        assert parsed["include_context"] is False

    @respx.mock
    def test_scan_sends_api_key_header(self):
        route = respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            client.scan("text")
        assert route.calls[0].request.headers["X-API-Key"] == TEST_API_KEY


class TestRedact:
    @respx.mock
    def test_redact_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=REDACT_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = client.redact("secret text")
        assert result.redacted_text == "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]"
        assert result.findings[0].redacted_as == "[AWS_ACCESS_KEY_REDACTED]"

    @respx.mock
    def test_redact_sends_style(self):
        route = respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=REDACT_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            client.redact("text", redaction_style="mask")
        parsed = json.loads(route.calls[0].request.content)
        assert parsed["redaction_style"] == "mask"


class TestGetTypes:
    @respx.mock
    def test_returns_typed_result(self):
        respx.get(f"{TEST_BASE_URL}/v1/types").mock(
            return_value=httpx.Response(200, json=TYPES_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = client.get_types()
        assert result.types_count == 1
        assert result.types[0].id == "aws_access_key"


class TestHealth:
    @respx.mock
    def test_returns_typed_result(self):
        respx.get(f"{TEST_BASE_URL}/v1/health").mock(
            return_value=httpx.Response(200, json=HEALTH_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = client.health()
        assert result.status == "healthy"
        assert result.patterns_loaded == 46


class TestFeedback:
    @respx.mock
    def test_returns_typed_result(self):
        respx.post(f"{TEST_BASE_URL}/v1/feedback").mock(
            return_value=httpx.Response(202, json=FEEDBACK_RESPONSE_JSON)
        )
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL) as client:
            result = client.feedback(
                request_id="req_abc", finding_id="f_001", feedback_type="false_positive"
            )
        assert result.feedback_id == "fb_abc123"
        assert result.status == "received"
