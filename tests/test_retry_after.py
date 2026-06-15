# Ledgix ALCV — Retry-After / 429 backpressure tests
#
# Vault's Scale & Reliability §2.1 work added proactive backpressure: when
# the clearance queue is past its watermark, Vault emits 429 + Retry-After
# instead of blocking up to 5s on a full channel. The SDK must:
#   1. Honor Retry-After verbatim (capped at 60s safety net).
#   2. NOT count 429s against the max_retries budget — they're cooperative.
#   3. Give up after MAX_CONSECUTIVE_429 sustained 429s with QueueSaturatedError
#      (so a melting Vault doesn't pin the SDK forever).
#   4. Fall back to jittered backoff if the 429 has no Retry-After header.
#
# These four properties are what makes the SDK + Vault backpressure loop
# stable instead of cascading.

from __future__ import annotations

import time

import httpx
import pytest
import respx
from httpx import Response

from ledgix_python import LedgixClient, VaultConfig
from ledgix_python.exceptions import QueueSaturatedError
from ledgix_python.models import ClearanceRequest


def _client_with_max_retries(max_retries: int = 0) -> LedgixClient:
    """Build a client wired for fast tests: zero base delay, no JWT verify."""
    return LedgixClient(
        config=VaultConfig(
            vault_url="https://vault.test",
            vault_api_key="test-api-key",
            vault_timeout=5.0,
            verify_jwt=False,
            agent_id="test-agent",
            session_id="test-session",
            max_retries=max_retries,
            retry_base_delay=0.0,
        )
    )


@respx.mock
def test_429_with_retry_after_sleeps_for_header_value(monkeypatch):
    """Plan §3.1 case 1: a 429 + Retry-After: 2 should drive a ~2s sleep
    via time.sleep, then succeed on the next call."""
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    approved = {
        "status": "approved",
        "decision_status": "approved",
        "token": "test-token",
        "reason": "ok",
        "request_id": "req-001",
    }
    respx.post("https://vault.test/request-clearance").mock(
        side_effect=[
            Response(429, headers={"Retry-After": "2"}, json={"error": "queue near capacity"}),
            Response(200, json=approved),
        ]
    )

    client = _client_with_max_retries(max_retries=0)
    try:
        result = client.request_clearance(
            ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 25})
        )
        assert result.is_approved is True
        # Exactly one sleep, of ~2 seconds (the Retry-After value).
        assert sleeps, "SDK should have slept after 429"
        assert any(abs(s - 2.0) < 0.01 for s in sleeps), f"expected 2s sleep, got {sleeps}"
    finally:
        client.close()


@respx.mock
def test_429_without_header_falls_back_to_jitter(monkeypatch):
    """Plan §3.1 case 2: a 429 without Retry-After should still sleep, but
    use the jittered backoff (with our 0.0 base delay = 0s)."""
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    approved = {
        "status": "approved",
        "decision_status": "approved",
        "token": "test-token",
        "reason": "ok",
        "request_id": "req-fallback",
    }
    respx.post("https://vault.test/request-clearance").mock(
        side_effect=[
            Response(429, json={"error": "queue near capacity"}),  # no header
            Response(200, json=approved),
        ]
    )

    client = _client_with_max_retries(max_retries=0)
    try:
        result = client.request_clearance(
            ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 25})
        )
        assert result.is_approved is True
        # SDK fell through to _backoff_delay (0s base in test config), so the
        # sleep is recorded as 0 — the important property is that we still
        # retried and didn't pop the request as a hard error.
        assert sleeps, "SDK should still attempt to sleep before retrying"
    finally:
        client.close()


@respx.mock
def test_429_does_not_consume_retry_budget(monkeypatch):
    """Plan §3.1 case 3: with max_retries=0, a transport error should fail
    immediately, but 429s should NOT — they're cooperative backoff. We send
    3 consecutive 429s then a 200; SDK should sail through all of them
    despite max_retries=0."""
    monkeypatch.setattr(time, "sleep", lambda s: None)

    approved = {
        "status": "approved",
        "decision_status": "approved",
        "token": "test-token",
        "reason": "ok",
        "request_id": "req-budget",
    }
    respx.post("https://vault.test/request-clearance").mock(
        side_effect=[
            Response(429, headers={"Retry-After": "1"}, json={"error": "near cap"}),
            Response(429, headers={"Retry-After": "1"}, json={"error": "near cap"}),
            Response(429, headers={"Retry-After": "1"}, json={"error": "near cap"}),
            Response(200, json=approved),
        ]
    )

    client = _client_with_max_retries(max_retries=0)  # transport errors die immediately
    try:
        result = client.request_clearance(
            ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 25})
        )
        assert result.is_approved is True
        assert result.request_id == "req-budget"
    finally:
        client.close()


@respx.mock
def test_consecutive_429s_raise_queue_saturated(monkeypatch):
    """Plan §3.1 case 4: after MAX_CONSECUTIVE_429 sustained 429s with no
    success, the SDK gives up with QueueSaturatedError so callers can fail
    fast instead of looping indefinitely."""
    monkeypatch.setattr(time, "sleep", lambda s: None)

    # 11 consecutive 429s — one over the limit (MAX_CONSECUTIVE_429 = 10).
    respx.post("https://vault.test/request-clearance").mock(
        return_value=Response(429, headers={"Retry-After": "1"}, json={"error": "queue full"})
    )

    client = _client_with_max_retries(max_retries=0)
    try:
        with pytest.raises(QueueSaturatedError) as exc_info:
            client.request_clearance(
                ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 25})
            )
        # The exception carries the wave count + last Retry-After, useful for
        # operator visibility in caller logs.
        assert exc_info.value.attempts >= 10
        assert exc_info.value.last_retry_after == 1.0
    finally:
        client.close()


@respx.mock
def test_retry_after_capped_at_safety_net(monkeypatch):
    """A misbehaving server emitting Retry-After: 9999 must NOT pin the SDK
    for hours. The cap (MAX_RETRY_AFTER_SECONDS = 60s) is a defensive limit."""
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    approved = {
        "status": "approved",
        "decision_status": "approved",
        "token": "test-token",
        "reason": "ok",
        "request_id": "req-cap",
    }
    respx.post("https://vault.test/request-clearance").mock(
        side_effect=[
            Response(429, headers={"Retry-After": "9999"}, json={"error": "queue full"}),
            Response(200, json=approved),
        ]
    )

    client = _client_with_max_retries(max_retries=0)
    try:
        client.request_clearance(
            ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 25})
        )
        # The single sleep should be capped at 60s, not 9999s.
        assert sleeps, "SDK should have slept after 429"
        assert max(sleeps) <= 60.0, f"sleep was not capped: {sleeps}"
    finally:
        client.close()


@respx.mock
def test_invalid_retry_after_falls_back_gracefully(monkeypatch):
    """A garbage Retry-After value (e.g. an HTTP-date or junk) must not crash
    the SDK — it should fall through to jittered backoff, same as no header."""
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    approved = {
        "status": "approved",
        "decision_status": "approved",
        "token": "test-token",
        "reason": "ok",
        "request_id": "req-junk",
    }
    respx.post("https://vault.test/request-clearance").mock(
        side_effect=[
            Response(429, headers={"Retry-After": "not-a-number"}, json={}),
            Response(200, json=approved),
        ]
    )

    client = _client_with_max_retries(max_retries=0)
    try:
        result = client.request_clearance(
            ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 25})
        )
        assert result.is_approved is True
        assert sleeps  # still slept, just via the jitter fallback
    finally:
        client.close()


@pytest.mark.asyncio
@respx.mock
async def test_async_429_honors_retry_after(monkeypatch):
    """Async path mirrors the sync path: same Retry-After honoring, same
    QueueSaturatedError ceiling. We only need one focused async test because
    the body of `_async_retry` is structurally identical to `_sync_retry`."""
    import asyncio

    sleeps: list[float] = []

    async def fake_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    approved = {
        "status": "approved",
        "decision_status": "approved",
        "token": "test-token",
        "reason": "ok",
        "request_id": "req-async",
    }
    respx.post("https://vault.test/request-clearance").mock(
        side_effect=[
            Response(429, headers={"Retry-After": "3"}, json={}),
            Response(200, json=approved),
        ]
    )

    client = _client_with_max_retries(max_retries=0)
    try:
        result = await client.arequest_clearance(
            ClearanceRequest(tool_name="stripe_refund", tool_args={"amount": 25})
        )
        assert result.is_approved is True
        assert any(abs(s - 3.0) < 0.01 for s in sleeps), f"expected 3s sleep, got {sleeps}"
    finally:
        await client.aclose()
