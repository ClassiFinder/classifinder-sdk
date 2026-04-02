"""Tests for the exception hierarchy."""

import httpx
import pytest
import respx

from classifinder._client import ClassiFinder
from classifinder._exceptions import (
    APIConnectionError,
    AuthenticationError,
    ClassiFinderError,
    ForbiddenError,
    InvalidRequestError,
    RateLimitError,
    SecretsDetectedError,
    ServerError,
)
from conftest import (
    ERROR_400_JSON,
    ERROR_401_JSON,
    ERROR_403_JSON,
    ERROR_429_JSON,
    ERROR_500_JSON,
    TEST_API_KEY,
    TEST_BASE_URL,
)


class TestExceptionHierarchy:
    def test_all_inherit_from_base(self):
        for exc_class in (
            AuthenticationError,
            RateLimitError,
            InvalidRequestError,
            ForbiddenError,
            ServerError,
            APIConnectionError,
        ):
            assert issubclass(exc_class, ClassiFinderError)

    def test_base_has_message_and_status(self):
        e = ClassiFinderError("something broke", status_code=500)
        assert e.message == "something broke"
        assert e.status_code == 500
        assert str(e) == "something broke"

    def test_authentication_error(self):
        e = AuthenticationError("bad key")
        assert e.status_code == 401
        assert e.message == "bad key"

    def test_rate_limit_error(self):
        e = RateLimitError("too fast", retry_after=30)
        assert e.status_code == 429
        assert e.retry_after == 30

    def test_invalid_request_error(self):
        e = InvalidRequestError("too big", code="payload_too_large")
        assert e.status_code == 400
        assert e.code == "payload_too_large"

    def test_forbidden_error(self):
        e = ForbiddenError("upgrade needed", code="tier_limit_exceeded")
        assert e.status_code == 403
        assert e.code == "tier_limit_exceeded"

    def test_server_error(self):
        e = ServerError("internal error")
        assert e.status_code == 500

    def test_api_connection_error(self):
        e = APIConnectionError("timeout")
        assert e.status_code is None
        assert e.message == "timeout"

    def test_secrets_detected_error(self):
        e = SecretsDetectedError(
            "Found 2 secrets", findings_count=2, findings=["f1", "f2"], summary={"critical": 1}
        )
        assert isinstance(e, ClassiFinderError)
        assert e.findings_count == 2
        assert e.findings == ["f1", "f2"]
        assert e.summary == {"critical": 1}
        assert e.status_code is None


class TestErrorMapping:
    @respx.mock
    def test_401_raises_authentication_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(401, json=ERROR_401_JSON)
        )
        with (
            ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client,
            pytest.raises(AuthenticationError, match="Missing"),
        ):
            client.scan("text")

    @respx.mock
    def test_400_raises_invalid_request_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(400, json=ERROR_400_JSON)
        )
        with (
            ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client,
            pytest.raises(InvalidRequestError) as exc_info,
        ):
            client.scan("text")
        assert exc_info.value.code == "payload_too_large"

    @respx.mock
    def test_403_raises_forbidden_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(403, json=ERROR_403_JSON)
        )
        with (
            ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client,
            pytest.raises(ForbiddenError) as exc_info,
        ):
            client.scan("text")
        assert exc_info.value.code == "tier_limit_exceeded"

    @respx.mock
    def test_429_raises_rate_limit_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(429, json=ERROR_429_JSON)
        )
        with (
            ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client,
            pytest.raises(RateLimitError) as exc_info,
        ):
            client.scan("text")
        assert exc_info.value.retry_after == 30

    @respx.mock
    def test_500_raises_server_error(self):
        respx.post(f"{TEST_BASE_URL}/v1/scan").mock(
            return_value=httpx.Response(500, json=ERROR_500_JSON)
        )
        with (
            ClassiFinder(api_key=TEST_API_KEY, base_url=TEST_BASE_URL, max_retries=0) as client,
            pytest.raises(ServerError, match="unexpected"),
        ):
            client.scan("text")
