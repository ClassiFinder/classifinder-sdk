"""LangChain integration — ClassiFinderGuard Runnable."""

from typing import Any, List, Optional

from pydantic import ConfigDict, PrivateAttr

try:
    from langchain_core.runnables import RunnableSerializable
except ImportError:
    raise ImportError(
        "langchain-core is required for the LangChain integration. "
        "Install it with: pip install classifinder[langchain]"
    )

import logging

from .._client import ClassiFinder
from .._async_client import AsyncClassiFinder
from .._exceptions import SecretsDetectedError, ClassiFinderError
from .._models import ScanResult

logger = logging.getLogger("classifinder.langchain")


class ClassiFinderGuard(RunnableSerializable[str, str]):
    """A LangChain Runnable that scans/redacts secrets from text.

    In redact mode (default), secrets are replaced and the clean text is
    passed downstream. In block mode, an exception is raised if secrets
    are found.

    If fail_open=True (default), API errors pass text through unmodified
    so your pipeline never breaks because of ClassiFinder. Set fail_open=False
    to hard-fail on API errors if you'd rather block than risk unscanned text.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    api_key: Optional[str] = None
    mode: str = "redact"
    redaction_style: str = "label"
    types: List[str] = ["all"]
    min_confidence: float = 0.5
    base_url: str = "https://api.classifinder.ai"
    max_retries: int = 2
    timeout: float = 30.0
    fail_open: bool = True

    # Lazy-initialized clients (private attrs)
    _sync_client: Optional[ClassiFinder] = PrivateAttr(default=None)
    _async_client: Optional[AsyncClassiFinder] = PrivateAttr(default=None)

    def _get_sync_client(self) -> ClassiFinder:
        if self._sync_client is None:
            self._sync_client = ClassiFinder(
                api_key=self.api_key,
                base_url=self.base_url,
                max_retries=self.max_retries,
                timeout=self.timeout,
            )
        return self._sync_client

    def _get_async_client(self) -> AsyncClassiFinder:
        if self._async_client is None:
            self._async_client = AsyncClassiFinder(
                api_key=self.api_key,
                base_url=self.base_url,
                max_retries=self.max_retries,
                timeout=self.timeout,
            )
        return self._async_client

    def _coerce_input(self, input: Any) -> str:
        """Convert input to string, handling PromptValue objects."""
        if isinstance(input, str):
            return input
        if hasattr(input, "to_string"):
            return input.to_string()
        return str(input)

    def invoke(self, input: Any, config: Any = None, **kwargs) -> str:
        """Sync: scan/redact text and return result."""
        text = self._coerce_input(input)
        client = self._get_sync_client()

        try:
            if self.mode == "block":
                result = client.scan(
                    text=text,
                    types=self.types,
                    min_confidence=self.min_confidence,
                )
                if result.findings_count > 0:
                    raise SecretsDetectedError(
                        message=f"Found {result.findings_count} secret(s) in input text.",
                        findings_count=result.findings_count,
                        findings=result.findings,
                        summary=result.summary,
                    )
                return text
            else:
                result = client.redact(
                    text=text,
                    types=self.types,
                    min_confidence=self.min_confidence,
                    redaction_style=self.redaction_style,
                )
                return result.redacted_text
        except SecretsDetectedError:
            raise  # Always propagate — this is intentional blocking
        except ClassiFinderError as exc:
            if self.fail_open:
                logger.warning("ClassiFinder API error, passing text through: %s", exc)
                return text
            raise

    async def ainvoke(self, input: Any, config: Any = None, **kwargs) -> str:
        """Async: scan/redact text and return result."""
        text = self._coerce_input(input)
        client = self._get_async_client()

        try:
            if self.mode == "block":
                result = await client.scan(
                    text=text,
                    types=self.types,
                    min_confidence=self.min_confidence,
                )
                if result.findings_count > 0:
                    raise SecretsDetectedError(
                        message=f"Found {result.findings_count} secret(s) in input text.",
                        findings_count=result.findings_count,
                        findings=result.findings,
                        summary=result.summary,
                    )
                return text
            else:
                result = await client.redact(
                    text=text,
                    types=self.types,
                    min_confidence=self.min_confidence,
                    redaction_style=self.redaction_style,
                )
                return result.redacted_text
        except SecretsDetectedError:
            raise  # Always propagate — this is intentional blocking
        except ClassiFinderError as exc:
            if self.fail_open:
                logger.warning("ClassiFinder API error, passing text through: %s", exc)
                return text
            raise
