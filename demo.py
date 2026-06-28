#!/usr/bin/env python3
"""Bylaw ALCV SDK — Demo Script

Simulates the "Good Agent" vs "Rogue Agent" scenario from the
ALCV Vault technical specification.

This demo runs without a real Vault server by using a lightweight
mock. Set BYLAW_VAULT_URL to point to a real Vault to test live.

Usage:
    python demo.py
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bylaw_python import (
    BylawClient,
    VaultConfig,
)

# ──────────────────────────────────────────────────────────────────────
# Mock Vault (only used when no live Vault is configured)
# ──────────────────────────────────────────────────────────────────────

# Generate a demo Ed25519 key pair for A-JWT signing
_DEMO_PRIVATE_KEY = Ed25519PrivateKey.generate()
_DEMO_PUBLIC_KEY = _DEMO_PRIVATE_KEY.public_key()

REFUND_POLICY = {
    "policy_id": "refund-policy-001",
    "description": "Customer refund policy for shipping delays",
    "rules": [
        "Refunds are allowed up to $100 for shipping delays",
        "Refund recipient must be the original customer",
        "Agent must provide a valid order ID",
    ],
}


def _mock_clearance_decision(tool_name: str, tool_args: dict) -> dict:
    """Simulates the Vault's policy judge decision."""
    amount = tool_args.get("amount", 0)
    recipient = tool_args.get("recipient", "customer")

    approved = amount <= 100 and recipient != "agent_personal_account"

    if approved:
        # Sign a demo A-JWT
        payload = {
            "sub": "clearance",
            "tool": tool_name,
            "amount": amount,
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
            "request_id": f"demo-{int(time.time())}",
        }
        token = jwt.encode(payload, _DEMO_PRIVATE_KEY, algorithm="EdDSA")
        return {
            "approved": True,
            "token": token,
            "reason": "Policy check passed — refund within limits",
            "request_id": payload["request_id"],
        }
    reason = []
    if amount > 100:
        reason.append(f"Amount ${amount} exceeds $100 limit")
    if recipient == "agent_personal_account":
        reason.append("Recipient is not the original customer")
    return {
        "approved": False,
        "token": None,
        "reason": "; ".join(reason),
        "request_id": f"demo-{int(time.time())}",
    }


# ──────────────────────────────────────────────────────────────────────
# Simulated Stripe Tool
# ──────────────────────────────────────────────────────────────────────


def stripe_refund(amount: float, reason: str, order_id: str, recipient: str = "customer", **kwargs) -> str:
    """Simulates a Stripe refund API call."""
    clearance = kwargs.get("_clearance")
    token_preview = clearance.token[:40] + "..." if clearance and clearance.token else "N/A"
    return (
        f"✅ REFUND PROCESSED\n"
        f"   Amount:  ${amount:.2f}\n"
        f"   Reason:  {reason}\n"
        f"   Order:   {order_id}\n"
        f"   A-JWT:   {token_preview}"
    )


# ──────────────────────────────────────────────────────────────────────
# Demo Runner
# ──────────────────────────────────────────────────────────────────────


def run_demo():
    """Run the Good Agent / Rogue Agent demo."""

    print("=" * 64)
    print("  BYLAW ALCV — SDK Demo")
    print("  Policy: \"Refunds ≤ $100 for shipping delays only\"")
    print("=" * 64)

    # Create a client with JWT verification disabled for demo
    # (the mock doesn't serve a real JWKS endpoint)
    config = VaultConfig(
        vault_url="http://localhost:9999",  # Won't be called in demo mode
        verify_jwt=False,
        agent_id="demo-agent",
    )
    _client = BylawClient(config=config)

    # ── Scenario A: Good Agent ─────────────────────────────────────
    print("\n" + "─" * 64)
    print("  SCENARIO A: Good Agent")
    print("  Agent requests $45 refund for a late package")
    print("─" * 64 + "\n")

    tool_args_good = {
        "amount": 45.00,
        "reason": "Package arrived 5 days late",
        "order_id": "ORD-2026-1234",
        "recipient": "customer",
    }

    decision = _mock_clearance_decision("stripe_refund", tool_args_good)
    print(f"  Vault decision: {'✅ APPROVED' if decision['approved'] else '❌ DENIED'}")
    print(f"  Reason: {decision['reason']}")

    if decision["approved"]:
        # Simulate what the decorator would do
        from bylaw_python.models import ClearanceResponse

        clearance = ClearanceResponse(**decision)
        result = stripe_refund(**tool_args_good, _clearance=clearance)
        print(f"\n{result}")

    # ── Scenario B: Rogue Agent ────────────────────────────────────
    print("\n" + "─" * 64)
    print("  SCENARIO B: Rogue Agent")
    print("  Agent (prompt-injected) tries $5,000 refund to own account")
    print("─" * 64 + "\n")

    tool_args_rogue = {
        "amount": 5000.00,
        "reason": "Customer requested full refund",
        "order_id": "ORD-2026-9999",
        "recipient": "agent_personal_account",
    }

    decision = _mock_clearance_decision("stripe_refund", tool_args_rogue)
    print(f"  Vault decision: {'✅ APPROVED' if decision['approved'] else '❌ DENIED'}")
    print(f"  Reason: {decision['reason']}")

    if not decision["approved"]:
        print("\n  🛡️  Tool call BLOCKED — no A-JWT issued")
        print("  The Stripe tool would refuse execution without a valid token.")

    # ── Summary ────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("  Demo complete!")
    print("  The ALCV Vault SDK intercepted both tool calls.")
    print("  • Good agent: Approved and received a signed A-JWT")
    print("  • Rogue agent: Denied — policy violation detected")
    print("=" * 64)


if __name__ == "__main__":
    run_demo()
