# ClassiFinder

Python SDK for the [ClassiFinder](https://classifinder.ai) secret detection API. Scan text for leaked secrets, get structured findings, and redact sensitive values — built for AI agents, LLM pipelines, and CI/CD.

```bash
pip install classifinder
```

## Quick Start

```python
from classifinder import ClassiFinder

client = ClassiFinder(api_key="ss_live_...")
# or set CLASSIFINDER_API_KEY env var

result = client.scan("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")

for finding in result.findings:
    print(f"{finding.type_name}: {finding.value_preview} "
          f"(severity={finding.severity}, confidence={finding.confidence})")
```

## Redact Secrets

Strip secrets from text before forwarding to LLMs, logging systems, or downstream services.

```python
result = client.redact("Deploy key: sk_live_51H7bKLkdFJH38djfh")

print(result.redacted_text)
# "Deploy key: [STRIPE_LIVE_SECRET_KEY_REDACTED]"
```

Three redaction styles:

```python
client.redact(text, redaction_style="label")  # [AWS_ACCESS_KEY_REDACTED]
client.redact(text, redaction_style="mask")   # AKIA**************
client.redact(text, redaction_style="hash")   # [REDACTED:sha256:a1b2c3d4]
```

## Async Support

Full async client with the same API surface.

```python
from classifinder import AsyncClassiFinder

async def check_text():
    async with AsyncClassiFinder(api_key="ss_live_...") as client:
        result = await client.scan("check this config")
        result = await client.redact("strip secrets from this")
```

Both clients support context managers (`with` / `async with`) for automatic connection cleanup.

## LangChain Integration

Guard your LLM chains against secret leakage with `ClassiFinderGuard` — a LangChain `Runnable` that slots into any chain.

```bash
pip install classifinder[langchain]
```

### Redact mode (default)

Secrets are replaced with safe placeholders. The chain continues with clean text.

```python
from classifinder.integrations.langchain import ClassiFinderGuard

guard = ClassiFinderGuard(api_key="ss_live_...")

# Standalone
clean = guard.invoke("My token is ghp_abc123secret")
# "My token is [GITHUB_PAT_CLASSIC_REDACTED]"

# In a chain — secrets never reach the LLM
chain = guard | your_llm | output_parser
response = chain.invoke(user_input)
```

### Block mode

Raises `SecretsDetectedError` if any secrets are found — use when you want to reject input rather than clean it.

```python
from classifinder.integrations.langchain import ClassiFinderGuard
from classifinder import SecretsDetectedError

guard = ClassiFinderGuard(api_key="ss_live_...", mode="block")

try:
    guard.invoke("sk_live_51H7bKLkdFJH38djfh")
except SecretsDetectedError as e:
    print(f"Blocked: {e.findings_count} secret(s) detected")
```

### Fail-open by default

If the ClassiFinder API is unreachable, the guard passes text through unmodified so your pipeline never breaks. Set `fail_open=False` to hard-fail instead.

```python
guard = ClassiFinderGuard(fail_open=False)  # raises on API errors
```

### Async chains

Works with `ainvoke` for async LangChain pipelines:

```python
clean = await guard.ainvoke("check this async")
```

## All Client Methods

| Method | Endpoint | Description |
|--------|----------|-------------|
| `client.scan(text, ...)` | `POST /v1/scan` | Detect secrets, return findings |
| `client.redact(text, ...)` | `POST /v1/redact` | Detect + replace secrets in text |
| `client.get_types()` | `GET /v1/types` | List all 106 detectable secret types |
| `client.health()` | `GET /v1/health` | Check API status |
| `client.feedback(...)` | `POST /v1/feedback` | Report false positives/negatives |

## Configuration

```python
client = ClassiFinder(
    api_key="ss_live_...",           # or CLASSIFINDER_API_KEY env var
    base_url="https://api.classifinder.ai",  # default
    max_retries=2,                   # retries on 429/500/timeout
    timeout=30.0,                    # seconds
)
```

Built-in retry with exponential backoff on rate limits (429), server errors (500), and timeouts.

### High-throughput tuning (optional)

For callers fanning out many concurrent requests (e.g., a CLI scanning thousands of files), the constructor accepts two extra kwargs:

```python
import httpx
from classifinder import ClassiFinder

client = ClassiFinder(
    api_key="ss_live_...",
    http2=True,                                  # enable HTTP/2 multiplexing
    limits=httpx.Limits(                         # tune the httpx connection pool
        max_connections=100,
        max_keepalive_connections=20,
    ),
)
```

Both default to safe values (HTTP/1.1, httpx defaults), so existing callers see no behavior change. `http2=True` requires the optional `[http2]` extra:

```bash
pip install classifinder[http2]
```

## Error Handling

```python
from classifinder import (
    ClassiFinder,
    ClassiFinderError,       # base class for all errors
    AuthenticationError,     # 401 — invalid API key
    RateLimitError,          # 429 — retry after e.retry_after seconds
    InvalidRequestError,     # 400 — bad request body
    ForbiddenError,          # 403
    ServerError,             # 500
    APIConnectionError,      # network/timeout
    SecretsDetectedError,    # raised by LangChain guard in block mode
)
```

## What It Detects

106 secret types across 7 categories: AWS, GCP, Azure, Stripe, GitHub, GitLab, Slack, Twilio, SendGrid, OpenAI, Anthropic, Cohere, database connection strings, SSH/PEM keys, JWTs, credit card numbers, and more.

Full list: [`GET /v1/types`](https://api.classifinder.ai/docs#/default/list_types_v1_types_get)

## Get an API Key

Free tier: 60 requests/minute, 256 KB max payload.

Get your key at [classifinder.ai](https://classifinder.ai).

## Links

- [API Documentation](https://api.classifinder.ai/docs)
- [Open-source engine](https://github.com/ClassiFinder/classifinder-engine) (MIT — audit the code that touches your data)
- [MCP Server](https://pypi.org/project/classifinder-mcp/) for Claude Code / Cursor
- [cfsniff](https://github.com/ClassiFinder/cfsniff) — CLI tool that scans your machine for leaked secrets using this SDK (`pipx install cfsniff`)

## Disclaimer

ClassiFinder is a detection aid, not a guarantee. No scanner catches 100% of secrets in 100% of formats. Use as one layer of a defense-in-depth security strategy. See our [Terms of Service](https://classifinder.ai/terms-of-service) for full details.

## License

MIT
