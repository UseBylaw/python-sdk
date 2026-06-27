# Bylaw ALCV — Python SDK

[![PyPI](https://img.shields.io/badge/pypi-v0.6.3-blue)](https://pypi.org/project/bylaw-python/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Agent-agnostic compliance shim for SOX 404 policy enforcement. Intercepts AI agent tool calls, validates them against your policies via the ALCV Vault, and ensures only approved actions receive a cryptographically signed A-JWT (Agentic JSON Web Token).

## Quick Start

```bash
pip install bylaw-python
# Optional OpenTelemetry correlation:
pip install "bylaw-python[otel]"
```

```python
# bylaw.yaml
# enforce:
#   - tool: "stripe_*"
#     policy_id: "financial-high-risk"
#   - tool: "*"
#     policy_id: "default"

import tools
import bylaw_python as bylaw

bylaw.configure(agent_id="payments-agent")
bylaw.auto_instrument(tools)

result = tools.stripe_refund(45, "Late package")
print(result)
```

`auto_instrument()` reads `bylaw.yaml`, `bylaw.yml`, or `bylaw.json` from the current working directory by default, wraps matching functions in place, and leaves unmatched functions alone.

## Configuration

Set environment variables (prefix: `BYLAW_`):

| Variable | Default | Description |
|---|---|---|
| `BYLAW_VAULT_URL` | `http://localhost:8000` | Vault server URL |
| `BYLAW_VAULT_API_KEY` | `""` | API key for Vault auth |
| `BYLAW_VAULT_TIMEOUT` | `30.0` | Request timeout (seconds) |
| `BYLAW_VERIFY_JWT` | `true` | Verify A-JWT signatures |
| `BYLAW_JWT_ISSUER` | `alcv-vault` | Expected A-JWT issuer |
| `BYLAW_JWT_AUDIENCE` | `ledgix-sdk` | Expected A-JWT audience |
| `BYLAW_AGENT_ID` | `default-agent` | Agent identifier |
| `BYLAW_OTEL_ENABLED` | `true` | Emit OpenTelemetry span events and propagate trace context when an active span exists |

Or pass a `VaultConfig` directly:

```python
from bylaw_python import BylawClient, VaultConfig

config = VaultConfig(vault_url="https://vault.mycompany.com", vault_api_key="sk-...")
client = BylawClient(config=config)
```

## OpenTelemetry correlation

If your app already has OpenTelemetry configured, install the optional extra and leave `otel_enabled` on:

```bash
pip install "bylaw-python[otel]"
```

The SDK records clearance outcomes as span events on the active span and sends `context.telemetry.otel` to Vault so ledger entries can be correlated back to your trace by `trace_id`, `span_id`, and `request_id`.

Events:

- `bylaw.clearance.pending_review`
- `bylaw.clearance.decision`

Event attributes include request ID, decision/status fields, policy version/hash, confidence buckets, tool name, agent/session IDs, manual review flag, and latency. The SDK also injects W3C trace propagation headers into Vault HTTP calls when OpenTelemetry propagation is available.

Telemetry is best-effort: if OpenTelemetry is not installed, disabled, or no span is active, clearance behavior is unchanged. The SDK does not include raw tool args, prompt text, model output, or policy reasoning in OTel attributes.

## Manifest-driven auto-instrumentation

```python
import tools
import bylaw_python as bylaw

bylaw.configure(agent_id="payments-agent")

# Auto-discover bylaw.yaml / bylaw.yml / bylaw.json from the CWD
wrapped = bylaw.auto_instrument(tools)

# Or pass an inline manifest
bylaw.auto_instrument(
    tools,
    manifest={"enforce": [{"tool": "stripe_*", "policy_id": "financial-high-risk"}]},
)
```

YAML manifests require `pyyaml`:

```bash
pip install bylaw-python[yaml]
```

### Escape hatch

```python
@bylaw.tool
def special_refund(amount: float):
    return bylaw.current_token()

@bylaw.tool(policy_id="override-policy")
def stripe_charge(amount: float):
    return bylaw.current_token()
```

## Framework Adapters

### LangChain

```bash
pip install bylaw-python[langchain]
```

```python
from bylaw_python.adapters.langchain import BylawCallbackHandler, BylawTool

# Option 1: Callback handler (intercepts ALL tool calls)
handler = BylawCallbackHandler(client)
agent = create_agent(callbacks=[handler])

# Option 2: Wrap individual tools
guarded_tool = BylawTool.wrap(client, my_tool, policy_id="refund-policy")
```

### LlamaIndex

```bash
pip install bylaw-python[llamaindex]
```

```python
from bylaw_python.adapters.llamaindex import wrap_tool

guarded_tool = wrap_tool(client, my_function_tool, policy_id="refund-policy")
```

### CrewAI

```bash
pip install bylaw-python[crewai]
```

```python
from bylaw_python.adapters.crewai import BylawCrewAITool

guarded_tool = BylawCrewAITool.wrap(client, my_tool, policy_id="refund-policy")
```

## Context Manager

```python
from bylaw_python import VaultContext

with VaultContext(client, "stripe_refund", {"amount": 45}) as ctx:
    print(ctx.clearance.token)  # Use the A-JWT

# Async
async with VaultContext(client, "stripe_refund", {"amount": 45}) as ctx:
    print(ctx.clearance.token)
```

## Error Handling

```python
from bylaw_python import ClearanceDeniedError, VaultConnectionError, TokenVerificationError

try:
    result = process_refund(amount=5000, reason="...")
except ClearanceDeniedError as e:
    print(f"Blocked: {e.reason} (request: {e.request_id})")
except VaultConnectionError:
    print("Cannot reach Vault — fail-closed")
except TokenVerificationError:
    print("A-JWT signature invalid")
```

## Development

```bash
git clone https://github.com/bylaw-dev/python-sdk.git
cd python-sdk
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v --cov
```

## Demo

```bash
python demo.py
```

## License

MIT
