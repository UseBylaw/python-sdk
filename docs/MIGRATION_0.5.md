# Migration Guide: 0.4.x → 0.5.0 (Ledgix → Bylaw)

Version 0.5.0 completes the Ledgix → Bylaw rebrand. This is a breaking release
for anyone still on the old package name or API symbols.

## Install

```bash
pip uninstall ledgix-python  # if previously installed
pip install bylaw-python
```

## Import path

```python
# Before
import ledgix_python as ledgix

# After
import bylaw_python as bylaw
```

## Renamed classes

| Before | After |
|---|---|
| `LedgixClient` | `BylawClient` |
| `LedgixError` | `BylawError` |
| `LedgixCallbackHandler` | `BylawCallbackHandler` |
| `LedgixTool` | `BylawTool` |
| `LedgixToolWrapper` | `BylawToolWrapper` |
| `LedgixCrewAITool` | `BylawCrewAITool` |

## Environment variables

All `LEDGIX_*` variables are now `BYLAW_*`:

| Before | After |
|---|---|
| `LEDGIX_VAULT_URL` | `BYLAW_VAULT_URL` |
| `LEDGIX_VAULT_API_KEY` | `BYLAW_VAULT_API_KEY` |
| `LEDGIX_AGENT_ID` | `BYLAW_AGENT_ID` |
| `LEDGIX_JWT_AUDIENCE` | `BYLAW_JWT_AUDIENCE` |

## Manifest files

Rename your manifest file:

```bash
mv ledgix.yaml bylaw.yaml   # or .yml / .json
```

## CLI

```bash
# Before
ledgix init
ledgix status
ledgix teardown

# After
bylaw init
bylaw status
bylaw teardown
```

Local dev scaffolding now writes `docker-compose.bylaw.yml` and `.env.bylaw`.

## Vault wire protocol (unchanged)

These values remain the same until the Vault server-side rebrand ships:

- JWT audience default: `ledgix-sdk`
- Webhook signature header: `X-Ledgix-Signature`
- Audit ledger hash domain: `ledgix.audit.event.v1` / `ledgix.audit.checkpoint.v1`

No action required unless you explicitly overrode these in your config.

## Need help?

Contact `team@bylaw.dev` with `[0.5 migration]` in the subject line.
