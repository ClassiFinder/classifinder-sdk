# ClassiFinder

Python SDK for the ClassiFinder secret detection API.

Scan text for leaked secrets and credentials, get structured findings, and redact
sensitive values -- all in a few lines of Python.

## Installation

```bash
pip install classifinder
```

## Quick Start

```python
from classifinder import ClassiFinder

client = ClassiFinder(api_key="ss_live_...")
# or set the CLASSIFINDER_API_KEY environment variable

result = client.scan("My AWS key is AKIAIOSFODNN7EXAMPLE")

for finding in result.findings:
    print(f"{finding.type_name} (severity={finding.severity}, confidence={finding.confidence})")
    print(f"  Preview: {finding.value_preview}")
```

## Redact Secrets

The `/v1/redact` endpoint replaces secrets in-place so you can safely pass text
downstream to LLMs or logging systems.

```python
result = client.redact("DB password is SuperSecret123!")

print(result.redacted_text)
# "DB password is [DATABASE_PASSWORD]!"

print(f"Redacted {result.findings_count} secret(s)")
```

## Async Support

```python
from classifinder import AsyncClassiFinder

async def main():
    client = AsyncClassiFinder(api_key="ss_live_...")
    result = await client.scan("AKIA...")
    await client.close()
```

## LangChain Integration

Guard your LLM chains against secret leakage.

```bash
pip install classifinder[langchain]
```

```python
from classifinder.integrations.langchain import ClassiFinderGuard

guard = ClassiFinderGuard(api_key="ss_live_...", mode="redact")

# Use as a standalone runnable
clean_text = guard.invoke("My token is ghp_abc123secret")

# Chain with other LangChain runnables
chain = guard | your_llm | output_parser
```

Set `mode="block"` to raise `SecretsDetectedError` instead of redacting.

## Error Handling

```python
from classifinder import ClassiFinder, AuthenticationError, RateLimitError, ClassiFinderError

client = ClassiFinder(api_key="ss_live_...")

try:
    result = client.scan("check this text")
except AuthenticationError:
    print("Invalid API key")
except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after}s")
except ClassiFinderError as e:
    print(f"API error ({e.status_code}): {e.message}")
```

## Documentation

Full API documentation: [https://classifinder.tech](https://classifinder.tech)

## License

MIT
