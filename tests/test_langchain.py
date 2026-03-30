"""Tests for the LangChain ClassiFinderGuard integration."""

import httpx
import pytest
import respx

from conftest import (
    TEST_API_KEY,
    TEST_BASE_URL,
    SCAN_RESPONSE_JSON,
    REDACT_RESPONSE_JSON,
)

# Build a clean-text scan response (no findings)
CLEAN_SCAN_JSON = {
    "request_id": "req_clean",
    "scan_time_ms": 1,
    "findings_count": 0,
    "findings": [],
    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
}

CLEAN_REDACT_JSON = {
    "request_id": "req_clean",
    "scan_time_ms": 1,
    "findings_count": 0,
    "redacted_text": "Hello, this is clean text.",
    "findings": [],
    "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
}


try:
    from classifinder.integrations.langchain import ClassiFinderGuard, SecretsDetectedError

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

pytestmark = pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain-core not installed")


class TestRedactMode:
    @respx.mock
    def test_redacts_and_passes_through(self):
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=REDACT_RESPONSE_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact")
        result = guard.invoke("text with AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        assert result == "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]"

    @respx.mock
    def test_clean_text_passes_through(self):
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=CLEAN_REDACT_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact")
        result = guard.invoke("Hello, this is clean text.")
        assert result == "Hello, this is clean text."


class TestBlockMode:
    @respx.mock
    def test_raises_on_secrets(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="block")
        with pytest.raises(SecretsDetectedError) as exc_info:
            guard.invoke("text with secrets")
        assert exc_info.value.findings_count == 1
        assert exc_info.value.findings[0].type == "aws_access_key"

    @respx.mock
    def test_passes_clean_text(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=CLEAN_SCAN_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="block")
        result = guard.invoke("safe text")
        assert result == "safe text"


class TestPromptValueInput:
    @respx.mock
    def test_coerces_prompt_value(self):
        """PromptValue objects should be converted via .to_string()."""

        class FakePromptValue:
            def to_string(self):
                return "text from prompt value"

        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=CLEAN_REDACT_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact")
        result = guard.invoke(FakePromptValue())
        assert result == "Hello, this is clean text."


class TestLazyClientCreation:
    def test_sync_client_created_lazily(self):
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL)
        assert guard._sync_client is None
        # After invoke, it should be populated
        with respx.mock:
            respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
                return_value=httpx.Response(200, json=CLEAN_REDACT_JSON)
            )
            guard.invoke("text")
        assert guard._sync_client is not None

    async def test_async_client_created_lazily(self):
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL)
        assert guard._async_client is None
        with respx.mock:
            respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
                return_value=httpx.Response(200, json=CLEAN_REDACT_JSON)
            )
            await guard.ainvoke("text")
        assert guard._async_client is not None


class TestFailOpen:
    @respx.mock
    def test_fail_open_passes_text_on_api_error(self):
        """When fail_open=True (default), API errors pass text through."""
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(500, json={"error": {"code": "internal_error", "message": "boom"}})
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact", max_retries=0)
        result = guard.invoke("text with maybe secrets")
        assert result == "text with maybe secrets"

    @respx.mock
    def test_fail_open_false_raises_on_api_error(self):
        """When fail_open=False, API errors propagate."""
        from classifinder._exceptions import ServerError
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(500, json={"error": {"code": "internal_error", "message": "boom"}})
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact", fail_open=False, max_retries=0)
        with pytest.raises(ServerError):
            guard.invoke("text with maybe secrets")

    @respx.mock
    def test_fail_open_still_raises_secrets_detected(self):
        """fail_open should NOT swallow SecretsDetectedError — that's intentional blocking."""
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="block", fail_open=True)
        with pytest.raises(SecretsDetectedError):
            guard.invoke("text with secrets")

    @respx.mock
    def test_fail_open_on_network_error(self):
        """Network errors should also pass through when fail_open=True."""
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(side_effect=httpx.ConnectError("refused"))
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact", max_retries=0)
        result = guard.invoke("text with maybe secrets")
        assert result == "text with maybe secrets"

    @respx.mock
    async def test_async_fail_open(self):
        """Async guard should also fail open."""
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(500, json={"error": {"code": "internal_error", "message": "boom"}})
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact", max_retries=0)
        result = await guard.ainvoke("text with maybe secrets")
        assert result == "text with maybe secrets"


class TestAsyncGuard:
    @respx.mock
    async def test_async_redact(self):
        respx.post(f"{TEST_BASE_URL}/v1/redact").mock(
            return_value=httpx.Response(200, json=REDACT_RESPONSE_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="redact")
        result = await guard.ainvoke("text with secrets")
        assert result == "AWS_ACCESS_KEY_ID=[AWS_ACCESS_KEY_REDACTED]"

    @respx.mock
    async def test_async_block(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(200, json=SCAN_RESPONSE_JSON)
        )
        guard = ClassiFinderGuard(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, mode="block")
        with pytest.raises(SecretsDetectedError):
            await guard.ainvoke("text with secrets")
