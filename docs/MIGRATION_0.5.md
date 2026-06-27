# Migration Guide: 0.4.x → 0.5.0 (Bylaw → Bylaw)

Version 0.5.0 completes the Bylaw → Bylaw rebrand. This is a breaking release
for anyone still on the old package name or API symbols.

## Install

```bash
pip uninstall bylaw-python  # if previously installed
pip install bylaw-python
```

## Import path

```python
# Before
import bylaw_python as bylaw

# After
import bylaw_python as bylaw
```

## Renamed classes

| Before | After |
|---|---|
| `BylawClient` | `BylawClient` |
| `BylawError` | `BylawError` |
| `BylawCallbackHandler` | `BylawCallbackHandler` |
| `BylawTool` | `BylawTool` |
| `BylawToolWrapper` | `BylawToolWrapper` |
| `BylawCrewAITool` | `BylawCrewAITool` |

## Environment variables

All `BYLAW_*` variables are now `BYLAW_*`:

| Before | After |
|---|---|
| `BYLAW_VAULT_URL` | `BYLAW_VAULT_URL` |
| `BYLAW_VAULT_API_KEY` | `BYLAW_VAULT_API_KEY` |
| `BYLAW_AGENT_ID` | `BYLAW_AGENT_ID` |
| `BYLAW_JWT_AUDIENCE` | `BYLAW_JWT_AUDIENCE` |

## Manifest files

Rename your manifest file:

```bash
mv bylaw.yaml bylaw.yaml   # or .yml / .json
```

## CLI

```bash
# Before
bylaw init
bylaw status
bylaw teardown

# After
bylaw init
bylaw status
bylaw teardown
```

Local dev scaffolding now writes `docker-compose.bylaw.yml` and `.env.bylaw`.

## Vault wire protocol (unchanged)

These values remain the same until the Vault server-side rebrand ships:

- JWT audience default: `bylaw-sdk`
- Webhook signature header: `X-Bylaw-Signature`
- Audit ledger hash domain: `bylaw.audit.event.v1` / `bylaw.audit.checkpoint.v1`

No action required unless you explicitly overrode these in your config.

## Need help?

Contact `team@bylaw.dev` with `[0.5 migration]` in the subject line.
