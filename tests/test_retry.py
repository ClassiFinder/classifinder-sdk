"""Tests for retry logic."""

from unittest.mock import patch

import httpx
import pytest
import respx

from classifinder._client import ClassiFinder
from classifinder._exceptions import (
    APIConnectionError,
    AuthenticationError,
    ForbiddenError,
    ServerError,
)
from conftest import (
    ERROR_429_JSON,
    ERROR_500_JSON,
    SCAN_RESPONSE_JSON,
    TEST_API_KEY,
    TEST_BASE_URL,
)


class TestRetry:
    @respx.mock
    @patch("classifinder._base.time.sleep")
    def test_retries_on_429_then_succeeds(self, mock_sleep):
        route = respx.post(f"{TEST_BASE_URL}/v1/scan")
        route.side_effect = [
            httpx.Response(429, json=ERROR_429_JSON),
            httpx.Response(200, json=SCAN_RESPONSE_JSON),
        ]
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client:
            result = client.scan("text")
        assert result.findings_count == 1
        mock_sleep.assert_called_once_with(30.0)

    @respx.mock
    @patch("classifinder._base.time.sleep")
    def test_retries_on_500_with_backoff(self, mock_sleep):
        route = respx.post(f"{TEST_BASE_URL}/v1/scan")
        route.side_effect = [
            httpx.Response(500, json=ERROR_500_JSON),
            httpx.Response(200, json=SCAN_RESPONSE_JSON),
        ]
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client:
            result = client.scan("text")
        assert result.findings_count == 1
        mock_sleep.assert_called_once_with(1.0)  # 2^0 = 1s for first retry

    @respx.mock
    @patch("classifinder._base.time.sleep")
    def test_exhausts_retries_then_raises(self, mock_sleep):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(500, json=ERROR_500_JSON)
        )
        with (
            ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client,
            pytest.raises(ServerError),
        ):
            client.scan("text")
        assert mock_sleep.call_count == 2  # retried twice before giving up

    @respx.mock
    def test_no_retry_on_401(self):
        error_json = {
            "error": {
                "code": "invalid_api_key",
                "message": "bad",
                "retry_after": None,
            }
        }
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(401, json=error_json)
        )
        with (
            ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client,
            pytest.raises(AuthenticationError),
        ):
            client.scan("text")

    @respx.mock
    def test_no_retry_on_403(self):
        error_json = {
            "error": {
                "code": "tier_limit_exceeded",
                "message": "upgrade",
                "retry_after": None,
            }
        }
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(403, json=error_json)
        )
        with (
            ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client,
            pytest.raises(ForbiddenError),
        ):
            client.scan("text")

    @respx.mock
    def test_no_retry_when_disabled(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(500, json=ERROR_500_JSON)
        )
        with (
            ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client,
            pytest.raises(ServerError),
        ):
            client.scan("text")

    @respx.mock
    @patch("classifinder._base.time.sleep")
    def test_retries_on_network_timeout(self, mock_sleep):
        route = respx.post(f"{TEST_BASE_URL}/v1/scan")
        route.side_effect = [
            httpx.ConnectError("connection refused"),
            httpx.Response(200, json=SCAN_RESPONSE_JSON),
        ]
        with ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=2) as client:
            result = client.scan("text")
        assert result.findings_count == 1
        mock_sleep.assert_called_once_with(1.0)

    @respx.mock
    def test_network_timeout_raises_api_connection_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(side_effect=httpx.ConnectError("refused"))
        with (
            ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client,
            pytest.raises(APIConnectionError),
        ):
            client.scan("text")
