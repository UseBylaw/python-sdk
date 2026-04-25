# Ledgix ALCV — Python SDK

[![PyPI](https://img.shields.io/badge/pypi-v0.1.13-blue)](https://pypi.org/project/ledgix-python/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Agent-agnostic compliance shim for SOX 404 policy enforcement. Intercepts AI agent tool calls, validates them against your policies via the ALCV Vault, and ensures only approved actions receive a cryptographically signed A-JWT (Agentic JSON Web Token).

## Quick Start

```bash
pip install ledgix-python
```

```python
# ledgix.yaml
# enforce:
#   - tool: "stripe_*"
#     policy_id: "financial-high-risk"
#   - tool: "*"
#     policy_id: "default"

import tools
import ledgix_python as ledgix

ledgix.configure(agent_id="payments-agent")
ledgix.auto_instrument(tools)

result = tools.stripe_refund(45, "Late package")
print(result)
```

`auto_instrument()` reads `ledgix.yaml`, `ledgix.yml`, or `ledgix.json` from the current working directory by default, wraps matching functions in place, and leaves unmatched functions alone.

## Configuration

Set environment variables (prefix: `LEDGIX_`):

| Variable | Default | Description |
|---|---|---|
| `LEDGIX_VAULT_URL` | `http://localhost:8000` | Vault server URL |
| `LEDGIX_VAULT_API_KEY` | `""` | API key for Vault auth |
| `LEDGIX_VAULT_TIMEOUT` | `30.0` | Request timeout (seconds) |
| `LEDGIX_VERIFY_JWT` | `true` | Verify A-JWT signatures |
| `LEDGIX_JWT_ISSUER` | `alcv-vault` | Expected A-JWT issuer |
| `LEDGIX_JWT_AUDIENCE` | `ledgix-sdk` | Expected A-JWT audience |
| `LEDGIX_AGENT_ID` | `default-agent` | Agent identifier |

Or pass a `VaultConfig` directly:

```python
from ledgix_python import LedgixClient, VaultConfig

config = VaultConfig(vault_url="https://vault.mycompany.com", vault_api_key="sk-...")
client = LedgixClient(config=config)
```

## Manifest-driven auto-instrumentation

```python
import tools
import ledgix_python as ledgix

ledgix.configure(agent_id="payments-agent")

# Auto-discover ledgix.yaml / ledgix.yml / ledgix.json from the CWD
wrapped = ledgix.auto_instrument(tools)

# Or pass an inline manifest
ledgix.auto_instrument(
    tools,
    manifest={"enforce": [{"tool": "stripe_*", "policy_id": "financial-high-risk"}]},
)
```

YAML manifests require `pyyaml`:

```bash
pip install ledgix-python[yaml]
```

### Escape hatch

```python
@ledgix.tool
def special_refund(amount: float):
    return ledgix.current_token()

@ledgix.tool(policy_id="override-policy")
def stripe_charge(amount: float):
    return ledgix.current_token()
```

## Framework Adapters

### LangChain

```bash
pip install ledgix-python[langchain]
```

```python
from ledgix_python.adapters.langchain import LedgixCallbackHandler, LedgixTool

# Option 1: Callback handler (intercepts ALL tool calls)
handler = LedgixCallbackHandler(client)
agent = create_agent(callbacks=[handler])

# Option 2: Wrap individual tools
guarded_tool = LedgixTool.wrap(client, my_tool, policy_id="refund-policy")
```

### LlamaIndex

```bash
pip install ledgix-python[llamaindex]
```

```python
from ledgix_python.adapters.llamaindex import wrap_tool

guarded_tool = wrap_tool(client, my_function_tool, policy_id="refund-policy")
```

### CrewAI

```bash
pip install ledgix-python[crewai]
```

```python
from ledgix_python.adapters.crewai import LedgixCrewAITool

guarded_tool = LedgixCrewAITool.wrap(client, my_tool, policy_id="refund-policy")
```

## Context Manager

```python
from ledgix_python import VaultContext

with VaultContext(client, "stripe_refund", {"amount": 45}) as ctx:
    print(ctx.clearance.token)  # Use the A-JWT

# Async
async with VaultContext(client, "stripe_refund", {"amount": 45}) as ctx:
    print(ctx.clearance.token)
```

## Error Handling

```python
from ledgix_python import ClearanceDeniedError, VaultConnectionError, TokenVerificationError

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
git clone https://github.com/ledgix-dev/python-sdk.git
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
