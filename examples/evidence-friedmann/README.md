# Evidence enforcement — Friedmann sample (Python)

A minimal, end-to-end sample showing Bylaw evidence enforcement wired into an
agent **purely through `bylaw.yaml`**. Five fake advisory tools become
evidence-aware with no Bylaw-specific code inside them and **no manual fact-ID
passing** — source tools auto-register evidence, and the protected action plus
the customer-facing output are checked against that evidence before they run.

This is the GA "can a customer run it in under 30 minutes?" reference.

## What it demonstrates

| Tool | Manifest `kind` | What Bylaw does |
|---|---|---|
| `get_customer_profile` | source / `profile` | registers `date_of_birth`, `risk_profile` |
| `search_account_statement` | source / `uploaded_document` | registers `balance_now`, `balance_prev` |
| `calculate_projection` | source / `tool_call` | registers `account_a`, `account_b` |
| `generate_recommendation` | action | **check-action** — requires authoritative profile evidence |
| `send_advisor_response` | output | **check-output** — every financial number must be grounded |

The advisor response says the portfolio is *"up 12% this quarter"* — and `12%`
recomputes deterministically as `percent_change(balance_now, balance_prev)`
= `(44800 − 40000) / 40000 × 100`, so it grounds. A second response claims
*"move $52,000 into bonds"* — `$52,000` is grounded in nothing, so it is
flagged (observe) or blocked (enforce).

## Setup (≈5 minutes)

```bash
# 1. Install the SDK. Published users:
pip install bylaw-python          # imports as `bylaw_python`
# In this repo, the local package imports as `bylaw_python` (the example uses it).
pip install -e ../..

# 2. Point at a Vault running the default financial evidence contract.
export BYLAW_VAULT_URL=http://localhost:8000
export BYLAW_VAULT_API_KEY=lx_test_your_key
```

## Run

```bash
# Observe — records what WOULD be blocked, never blocks. The safe first rollout.
python run.py

# Enforce — flip both evidence modes on; the fabricated $52,000 is blocked live.
python run.py --enforce
```

Observe → enforce is the whole adoption path: roll out in observe, watch the
dashboard / replay to confirm no false positives, then flip to enforce.

## The only configuration is `bylaw.yaml`

There is no Bylaw code in `tools.py`. `run.py` calls `configure()` +
`auto_instrument(tools, manifest="bylaw.yaml")` once at startup; everything else
is the manifest. To enforce a new tool, add an `enforce` entry — no code change.

> Published-package note: with `pip install bylaw-python` the import is
> `import bylaw_python as bylaw`. This in-repo example imports the local
> `bylaw_python` module; the API is identical.
