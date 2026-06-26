"""Fake advisory tools for the Ledgix evidence-enforcement sample.

These are deliberately plain functions returning canned data — the point of the
sample is that they become evidence-aware purely through ``ledgix.yaml`` +
``auto_instrument``, with no Ledgix-specific code in the tools themselves.

The scenario is "Friedmann", a conservative retirement client.
"""
from __future__ import annotations


def get_customer_profile(customer_id: str) -> dict:
    """Stored profile. Source/`profile` — authoritative for DOB + risk."""
    return {
        "customer_id": customer_id,
        "name": "Margaret Friedmann",
        "date_of_birth": "1958-04-12",
        "risk_profile": "conservative",
    }


def search_account_statement(customer_id: str, query: str = "") -> dict:
    """Uploaded brokerage statement. Source/`uploaded_document` — carries this
    and prior quarter balances, which ground a stated growth percentage."""
    return {
        "customer_id": customer_id,
        "document": "Q2-2026 brokerage statement",
        "balance_now": 44800.0,
        "balance_prev": 40000.0,
    }


def calculate_projection(customer_id: str) -> dict:
    """Calculation tool. Source/`tool_call` — sub-account balances whose sum
    (account_a + account_b = 44,800) grounds a stated total."""
    return {
        "customer_id": customer_id,
        "account_a": 30000.0,
        "account_b": 14800.0,
    }


def generate_recommendation(customer_id: str) -> dict:
    """Protected action. Gated by check-action against the profile facts."""
    return {
        "customer_id": customer_id,
        "action": "rebalance_to_60_40",
        "rationale": "Conservative profile; shift toward fixed income.",
    }


def send_advisor_response(customer_id: str, message: str) -> dict:
    """Customer-facing output. Gated by check-output — every financial number in
    `message` must be grounded in registered evidence."""
    return {"customer_id": customer_id, "message": message}
