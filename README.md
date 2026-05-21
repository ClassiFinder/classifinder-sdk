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

## FastAPI Middleware

Scan every request body before it reaches a route handler. One middleware addition, zero changes to business logic — and any route added later is automatically covered. Calling `await request.body()` in middleware is safe; FastAPI caches the body so the downstream handler still sees it.

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from classifinder import AsyncClassiFinder

app = FastAPI()
cf = AsyncClassiFinder()  # reads CLASSIFINDER_API_KEY from env

@app.middleware("http")
async def scan_for_secrets(request: Request, call_next):
    body = await request.body()
    if body:
        result = await cf.scan(body.decode("utf-8", errors="ignore"))
        if any(f.severity in ("critical", "high") for f in result.findings):
            return JSONResponse(
                status_code=400,
                content={"error": "Sensitive data detected in request body"},
            )
    return await call_next(request)
```

Return a `JSONResponse` to block — `raise HTTPException(...)` doesn't convert to a response inside `@app.middleware("http")`.

## RAG Pre-Index Hook

Scan documents *before* they enter a vector store. Once a secret is embedded, it becomes queryable by intent — *"What are the production database credentials?"* is a valid RAG query against your own corpus, and your own model will retrieve them. Redacting at index time is the only place to fix this.

```python
from classifinder import ClassiFinder
from llama_index.core import VectorStoreIndex, Document

cf = ClassiFinder()  # reads CLASSIFINDER_API_KEY from env

def redact(docs: list[Document]) -> list[Document]:
    for doc in docs:
        result = cf.redact(doc.text)
        if result.findings_count:
            doc.text = result.redacted_text
            doc.metadata["secrets_redacted"] = result.findings_count
    return docs

index = VectorStoreIndex.from_documents(redact(load_docs()))
```

The same pattern applies to LangChain document loaders, Pinecone upserts, and Chroma `add_documents()` — call `cf.redact()` (or `cf.scan()` if you want to refuse rather than redact) on each document's text before indexing.

See the full integration guide with three real-world projects per pattern: [classifinder.ai/integrations](https://classifinder.ai/integrations).

## All Client Methods

| Method | Endpoint | Description |
|--------|----------|-------------|
| `client.scan(text, ...)` | `POST /v1/scan` | Detect secrets, return findings |
| `client.redact(text, ...)` | `POST /v1/redact` | Detect + replace secrets in text |
| `client.get_types()` | `GET /v1/types` | List all 164 detectable secret types |
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

**164 secret types** across 10 categories: cloud/infra (AWS, GCP, Azure, Vercel with the 2024+ prefixed taxonomy vcp_/vci_/vca_/vcr_/vck_, Fly.io, Doppler, Vault, Cloudflare, Dropbox, JFrog/Artifactory and more); payment (Stripe, PayPal, Shopify with 4 token types, credit cards Luhn-validated, Square); VCS (GitHub, GitLab with 10 token types including deploy/feed/runner/SCIM/k8s-agent/OAuth/feature-flag, Bitbucket, npm, PyPI, RubyGems); comms (Slack with config/session/legacy variants, Twilio, SendGrid, Mailgun, Datadog, Sentry, PagerDuty, Notion, Linear and more); database connection strings (PostgreSQL/MySQL/MongoDB/Redis/Supabase); generic SSH/PEM private keys and JWTs; **AI/LLM provider keys** (OpenAI, Anthropic user + admin, Cohere, xAI, Mistral, DeepSeek, HuggingFace user + organization, Replicate, Groq, ElevenLabs, AssemblyAI, Deepgram, LangFuse, AWS Bedrock long + short-lived, Vercel AI Gateway, Weights & Biases); DevOps/observability (Databricks, Dynatrace, LaunchDarkly, Harness, Octopus Deploy, Fastly, Gitea, TravisCI, Prefect, Infracost, Sumo Logic, Snyk, Sonar, Sourcegraph); data/analytics (ClickHouse, PlanetScale with 3 token types, PostHog, Postman, Algolia, Contentful); enterprise identity (Atlassian, 1Password, HubSpot, Mapbox, MaxMind, Zendesk).

**14 prompt-injection markers** — 4 phase-1 high-precision + 6 phase-2 medium-precision + 4 phase-3 SAFE-MCP-derived:

- **Phase 1** (structurally rare tokens, high confidence): role-hijack control tokens (ChatML / Llama / Alpaca), tool-call tag injection (`<tool_use>`, `<function_call>`, `<thinking>`), known jailbreak personas (DAN, AIM, developer mode), Unicode bidirectional override (Trojan Source / CVE-2021-42574).
- **Phase 2** (natural-language markers): zero-width Unicode smuggling, fake assistant turn (`Assistant:`, `Claude:`, `GPT:` prefixes), prompt extraction (`reveal your system prompt`), instruction override (`ignore previous instructions`), persona override (`act as…` — context-gated, opt-in via `min_confidence=0.4`), encoded payload markers (base64 + decode hint).

Validated against 5,000 real WildChat conversations: phase 1 + phase 2 catches 20.6% of in-the-wild jailbreaks (vs 12.2% with phase 1 alone — a 70% improvement). Filter to just injection markers via `types=` with the `pi_*` IDs, or scan everything (default) to catch secrets and injection attempts in one pass.

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
