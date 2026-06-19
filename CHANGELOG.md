# Changelog

All notable changes to `bylaw-python` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0]

### Breaking changes — Ledgix → Bylaw rebrand

The SDK has been rebranded from Ledgix to Bylaw. See
[`docs/MIGRATION_0.5.md`](docs/MIGRATION_0.5.md) for the full migration guide.

#### Package & CLI
- PyPI package: `bylaw-python` (replaces `ledgix-python`)
- CLI command: `bylaw` (replaces `ledgix`)
- Import path: `bylaw_python` (replaces `ledgix_python`)

#### Renamed public API
- `LedgixClient` → `BylawClient`
- `LedgixError` → `BylawError`
- `LedgixCallbackHandler` → `BylawCallbackHandler`
- `LedgixTool` → `BylawTool` (LangChain adapter)
- `LedgixToolWrapper` → `BylawToolWrapper` (LlamaIndex adapter)
- `LedgixCrewAITool` → `BylawCrewAITool`

#### Configuration
- Environment variable prefix: `BYLAW_` (replaces `LEDGIX_`)
- Manifest filenames: `bylaw.yaml` / `bylaw.yml` / `bylaw.json` (replaces `ledgix.*`)
- Dev compose file: `docker-compose.bylaw.yml` (replaces `docker-compose.ledgix.yml`)

#### Unchanged (Vault wire protocol)
- JWT audience default remains `ledgix-sdk` until the Vault server rebrand ships
- Audit ledger hash prefixes (`ledgix.audit.*`) unchanged for merkle compatibility
- Webhook header `X-Ledgix-Signature` unchanged until Vault emits the new header

## [0.4.0]

### Breaking changes — categorical confidence buckets

This release replaces the legacy decimal `confidence: float` field with five
categorical buckets (`extra_high | high | medium | low | none`), and splits
the overloaded `approved=True + confidence=0.00` "needs human review"
sentinel into an explicit `decision_status` field
(`approved | denied | approved_pending_review`). See
[`docs/MIGRATION_0.4.md`](docs/MIGRATION_0.4.md) for the migration guide.

> Note: the wire format change is breaking, but the SemVer bump is 0.3.1 →
> 0.4.0 (still in 0.x.0). The 0.x line is pre-1.0 and minor bumps are
> allowed to carry breaking changes per SemVer §4. Customers pinning
> `^0.3` will NOT auto-upgrade; they must explicitly bump to `^0.4`
> after reading the migration guide.

#### `ClearanceResponse` — fields removed
- `approved: bool`
- `confidence: float`
- `minimum_confidence_score: float`

#### `ClearanceResponse` — fields added
- `decision_status: Literal["approved", "denied", "approved_pending_review"]`
- `confidence_bucket: Literal["extra_high", "high", "medium", "low", "none"]`
- `minimum_confidence_bucket: Literal[...]` (same five values)
- `is_approved` property — convenience boolean for the common
  "may the agent proceed?" check, returns `True` for both `approved` and
  `approved_pending_review`.

#### `LedgerEntry`
- `confidence_bucket` and `decision_status` added (populated for
  canonical_version=2 events).
- Legacy `confidence: float` and `approved: bool` retained on the model so
  canonical_version=1 hash verification of historical rows still works.

#### Why this changed
The previous design overloaded `confidence=0.00` to mean both "extreme low
confidence" (deny path) and "needs human review" (gated approval). Customer
code doing `if response.confidence < threshold: reject` would accidentally
reject the very review-pending decisions the platform was trying to surface.
The bucket migration retires the cents-level decimal precision the model
couldn't reliably produce and gives review-pending its own dedicated state.

#### Migration in one line
- Old: `if response.approved and response.confidence >= 0.8: ...`
- New: `if response.decision_status == "approved": ...`
  (or `if response.is_approved: ...` if you also want to treat
  `approved_pending_review` as "may proceed eventually").

## [0.3.1]

### Added
- `ClearanceRequest.data_categories`, `purpose`, and
  `processing_register_ref` — Phase 2 GDPR Article 30 processing-register
  matching. When set, the Vault's pre-LLM validator chain checks for an
  active register that covers the (data_categories ⊇ requested,
  purpose ∈ register.purposes, recipient ∈ register.recipients) tuple.
  Unmatched requests deny with `reason_code='processing_no_register_match'`.
- `ClearanceRequest.dataset_ref` — Phase 6 dataset lineage. Logical
  reference (filename, S3 path, table name, etc.) for the production
  data this action reads/writes. Auto-derived dataset sheets group on
  this field for row counts, schema fingerprints, and consent-basis
  breakdowns.
- All four fields are also surfaced as kwargs on `enforce()`, `tool()`,
  `vault_enforce()`, and `VaultContext` so the high-level decorator API
  can populate them without dropping to `BylawClient.request_clearance`.
- `/mint-token` cache-replay forwards the new fields alongside the 0.3.0
  destination set.

### Compatibility
- Backwards-compatible. All four fields are optional. Vault ignores
  unknown wire fields prior to the matching schema migration; older SDKs
  continue to work against the new Vault.

## [0.3.0]

### Added
- `ClearanceRequest.destination_uri`, `destination_provider`, and
  `destination_account_ref` — typed counterparty attribution that replaces
  per-tool guessing in downstream policy checks. All three fields are
  optional; existing callers are unaffected.
- `bylaw_python.counterparty.extract()` — best-effort SDK-side hint that
  fills the new fields when the caller doesn't supply them. Recognizes
  Stripe (`api_key` prefix → 12-char account ref), Twilio (`account_sid`),
  Slack (`team_id` / `workspace`), AWS Bedrock (`model_id`), OpenAI
  (`organization`), Anthropic (`organization`), and a generic URL-host
  fallback. The Vault re-runs its own extractor chain server-side, so
  this is a hint — caller-supplied values always win.
- `/mint-token` cache-replay path forwards the destination fields so
  re-minted A-JWTs share attribution with the original decision.

### Compatibility
- Backwards-compatible against Vault 0.x (Vault ignores unknown wire
  fields prior to the matching schema migration). Older SDKs continue
  to work against the new Vault — destination columns are simply NULL
  on those rows.

## [0.2.1]
- Honor `Retry-After` on 429 from Vault backpressure.

## [0.2.0]
- Idempotency-Key on POSTs, JWKS async lock, adapter dedup.
- Security: JWKS kid matching, jti replay detection.
- HITL: `PendingApproval`, `review_mode="detach"`, `verify_webhook`.
