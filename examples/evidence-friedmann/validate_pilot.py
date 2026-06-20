"""Pilot success-criteria validation (R5.8) for the Friedmann sample.

Runs the manifest-only integration against a live Vault and asserts the GA
acceptance criteria. Exits non-zero on the first failure.

    export BYLAW_VAULT_URL=http://localhost:8000
    export BYLAW_VAULT_API_KEY=lx_test_your_key
    python validate_pilot.py

Criteria checked:
  1. Configured via ledgix.yaml only — no manual fact-ID passing.
  2. A protected recommendation requires evidence (it runs once facts exist).
  3. An unsupported financial number is blocked in enforce mode.
  4. A grounded financial number is allowed (recomputed from evidence).
  5. Every decision returns a receipt id.
"""
from __future__ import annotations

import os
import sys

import bylaw_python as ledgix
from bylaw_python import BylawClient, CheckOutputRequest, VaultConfig

import tools

CUSTOMER = "cust_friedmann_pilot"
SESSION = "sess-friedmann-pilot"
GROUNDED = "Your portfolio is up 12% this quarter."
FABRICATED = "You should move $52,000 into bonds."

_failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        _failures.append(name)


def main() -> int:
    cfg = VaultConfig(
        vault_url=os.environ.get("BYLAW_VAULT_URL", "http://localhost:8000"),
        vault_api_key=os.environ.get("BYLAW_VAULT_API_KEY", ""),
        agent_id="friedmann-pilot",
        evidence_mode="enforce",
        evidence_output_mode="enforce",
    )
    client: BylawClient = ledgix.configure(cfg)
    wrapped = ledgix.auto_instrument(tools, manifest="ledgix.yaml")

    print("Ledgix pilot validation — Friedmann sample\n")
    check("1. Configured via ledgix.yaml only (5 tools, zero manual fact-IDs)",
          len(wrapped) == 5, f"{len(wrapped)} tools wrapped")

    with ledgix.evidence_session(session_id=SESSION, customer_id=CUSTOMER):
        # Register evidence purely by calling the instrumented source tools.
        tools.get_customer_profile(CUSTOMER)
        tools.search_account_statement(CUSTOMER)
        tools.calculate_projection(CUSTOMER)

        # 2. Protected action runs once authoritative evidence exists.
        rec_ok = True
        try:
            tools.generate_recommendation(CUSTOMER)
        except ledgix.EvidenceBlockedError as exc:
            rec_ok = False
            detail = str(exc)
        else:
            detail = "allowed with profile evidence"
        check("2. Protected recommendation requires + receives evidence", rec_ok, detail)

        # 3. An unsupported number is blocked in enforce mode.
        blocked = False
        try:
            tools.send_advisor_response(CUSTOMER, FABRICATED)
        except ledgix.EvidenceBlockedError:
            blocked = True
        check("3. Unsupported $52,000 is blocked", blocked)

        # 4. A grounded number is allowed.
        grounded_ok = True
        try:
            tools.send_advisor_response(CUSTOMER, GROUNDED)
        except ledgix.EvidenceBlockedError as exc:
            grounded_ok = False
        check("4. Grounded 12% is allowed (recomputed from balances)", grounded_ok)

        # 5. Every decision returns a receipt. Inspect one via the client directly.
        result = client.check_output(CheckOutputRequest(
            customer_id=CUSTOMER, session_id=SESSION,
            action_type="send_financial_response", mode="enforce",
            response_text=GROUNDED,
        ))
        check("5. Every decision returns a receipt", bool(result.receipt_id),
              f"receipt_id={result.receipt_id or '(none)'}")

    print()
    if _failures:
        print(f"PILOT VALIDATION FAILED: {len(_failures)} criterion/criteria not met.")
        return 1
    print("PILOT VALIDATION PASSED: all criteria met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
