# Migrating from `bylaw-python` 0.3.x to 0.4.0

`0.4.0` is a breaking release. The wire format between the SDK and the
Vault now uses **categorical confidence buckets** instead of a decimal
0.00–1.00 score, and **`decision_status`** is a separate field instead
of being encoded into the magic value `confidence=0.00 + approved=True`.

> The version bump is 0.3.1 → 0.4.0 (still pre-1.0). Per SemVer §4 the
> 0.x line is allowed to carry breaking changes on minor bumps.
> Customers on `^0.3` will not auto-upgrade — they must explicitly
> bump their pin to `^0.4` after reading this guide.

This document maps every legacy field to its replacement.

## Field map

| Legacy 0.3.x | New 0.4.0 |
|---|---|
| `response.approved: bool` | `response.decision_status: "approved" \| "denied" \| "approved_pending_review"` |
| `response.confidence: float` | `response.confidence_bucket: "extra_high" \| "high" \| "medium" \| "low" \| "none"` |
| `response.minimum_confidence_score: float` | `response.minimum_confidence_bucket` (same five values) |

## Common code patterns

### "Did the agent get approval?"

**Old:**
```python
if response.approved:
    do_thing()
```

**New (recommended):**
```python
if response.decision_status == "approved":
    do_thing()
```

**New (more permissive — treats review-pending as "eventually allowed"):**
```python
if response.is_approved:  # property: covers both approved + approved_pending_review
    do_thing()
```

### "Reject low-confidence calls"

**Old:**
```python
if response.confidence < 0.8:
    reject_or_route_to_human()
```

**New:**
```python
if response.decision_status == "approved_pending_review":
    route_to_human()
elif response.decision_status == "denied":
    reject()
else:
    proceed()
```

> Note: the explicit `decision_status` makes the legacy float comparison
> obsolete. The Vault no longer surfaces review-pending decisions as
> "below threshold"; it routes them via the new field directly. Customer
> code that checked the float threshold would accidentally reject
> review-pending decisions in 0.3.x — that footgun is gone.

### "Show confidence to the user"

**Old:**
```python
print(f"Confidence: {response.confidence:.2%}")
```

**New:**
```python
labels = {
    "extra_high": "Extra high",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "none": "None",
}
print(f"Confidence: {labels[response.confidence_bucket]}")
```

### "Configure the tenant's review threshold"

**Old (via the customer dashboard or `PUT /review-settings`):**
```json
{ "minimum_confidence_score": 0.80 }
```

**New:**
```json
{ "minimum_confidence_bucket": "high" }
```

## Bucket → numeric correspondence

If you need to map between the two for analytics or audit, the buckets
correspond to these midpoints (used internally by the Vault for
canonical_version=1 ledger compatibility):

| Bucket | Midpoint | Legacy float range |
|---|---|---|
| `extra_high` | 0.95 | `[0.92, 1.00]` |
| `high` | 0.85 | `[0.81, 0.91]` |
| `medium` | 0.60 | `[0.40, 0.80]` |
| `low` | 0.20 | `[0.01, 0.39]` |
| `none` | 0.00 | exactly `0.00` (legacy review-pending sentinel) |

## Why this changed

The senior engineer who reviewed the LLM-as-judge prompt identified two
failure modes that the bucket migration eliminates:

1. **The decimal confidence was fake precision.** LLMs don't have
   calibrated probabilities at cent-level granularity; the `0.93` vs
   `0.96` distinction was noise. Five categorical buckets matched to
   evidence shape ("exact match, all evidence" → `extra_high`) is what
   the model can actually produce.

2. **The 0.00 sentinel overloaded the confidence field.** Encoding
   "needs human review" as `confidence=0.00 + approved=True` was a
   footgun for any consumer doing `if confidence < threshold: reject` —
   they'd accidentally reject the review-pending decisions the platform
   was trying to surface. Splitting `decision_status` into its own field
   makes the routing semantics explicit.

## Where to ask questions

- General SDK questions: file an issue on the `bylaw-python` repo.
- Migration help: ping `team@bylaw.dev` with `[0.4 migration]` in the
  subject line.
- Vault wire-format questions: see the `vault` repo's
  `docs/api/clearance.md`.
