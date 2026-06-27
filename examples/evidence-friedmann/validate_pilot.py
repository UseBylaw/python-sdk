"""Pilot success-criteria validation (R5.8) for the Friedmann sample.

Runs the manifest-only integration against a live Vault and asserts the GA
acceptance criteria. Exits non-zero on the first failure.

    export BYLAW_VAULT_URL=http://localhost:8000
    export BYLAW_VAULT_API_KEY=lx_test_your_key
    python validate_pilot.py

Criteria checked:
  1. Configured via bylaw.yaml only — no manual fact-ID passing.
  2. A protected recommendation requires evidence (it runs once facts exist).
  3. An unsupported financial number is blocked in enforce mode.
  4. A grounded financial number is allowed (recomputed from evidence).
  5. Every decision returns a receipt id.
"""
from __future__ import annotations

import os
import sys

import bylaw_python as bylaw
from bylaw_python import BylawClient, VaultConfig

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
    client: BylawClient = bylaw.configure(cfg)
    wrapped = bylaw.auto_instrument(tools, manifest="bylaw.yaml")
    decision_receipts: list[tuple[str, str]] = []
    original_check_action = client.check_action
    original_check_output = client.check_output

    def record_decision(
        kind: str, result: bylaw.CheckActionResult
    ) -> bylaw.CheckActionResult:
        decision_receipts.append((kind, result.receipt_id))
        return result

    def recording_check_action(
        request: bylaw.CheckActionRequest,
    ) -> bylaw.CheckActionResult:
        return record_decision("check-action", original_check_action(request))

    def recording_check_output(
        request: bylaw.CheckOutputRequest,
    ) -> bylaw.CheckActionResult:
        return record_decision("check-output", original_check_output(request))

    client.check_action = recording_check_action  # type: ignore[method-assign]
    client.check_output = recording_check_output  # type: ignore[method-assign]

    print("Bylaw pilot validation — Friedmann sample\n")
    check("1. Configured via bylaw.yaml only (5 tools, zero manual fact-IDs)",
          len(wrapped) == 5, f"{len(wrapped)} tools wrapped")

    with bylaw.evidence_session(session_id=SESSION, customer_id=CUSTOMER):
        # Register evidence purely by calling the instrumented source tools.
        tools.get_customer_profile(CUSTOMER)
        tools.search_account_statement(CUSTOMER)
        tools.calculate_projection(CUSTOMER)

        # 2. Protected action runs once authoritative evidence exists.
        rec_ok = True
        try:
            tools.generate_recommendation(CUSTOMER)
        except bylaw.EvidenceBlockedError as exc:
            rec_ok = False
            detail = str(exc)
        else:
            detail = "allowed with profile evidence"
        check("2. Protected recommendation requires + receives evidence", rec_ok, detail)

        # 3. An unsupported number is blocked in enforce mode.
        blocked = False
        try:
            tools.send_advisor_response(CUSTOMER, FABRICATED)
        except bylaw.EvidenceBlockedError:
            blocked = True
        check("3. Unsupported $52,000 is blocked", blocked)

        # 4. A grounded number is allowed.
        grounded_ok = True
        try:
            tools.send_advisor_response(CUSTOMER, GROUNDED)
        except bylaw.EvidenceBlockedError as exc:
            grounded_ok = False
        check("4. Grounded 12% is allowed (recomputed from balances)", grounded_ok)

        # 5. Every wrapped check-action/check-output decision returns a receipt.
        expected_decisions = 3
        receipt_count = sum(1 for _, receipt_id in decision_receipts if receipt_id)
        missing_receipts = [kind for kind, receipt_id in decision_receipts if not receipt_id]
        detail = (
            f"{receipt_count}/{expected_decisions} instrumented decisions returned receipts"
        )
        if missing_receipts:
            detail += f"; missing: {', '.join(missing_receipts)}"
        check("5. Every decision returns a receipt",
              len(decision_receipts) == expected_decisions
              and receipt_count == expected_decisions,
              detail)

    print()
    if _failures:
        print(f"PILOT VALIDATION FAILED: {len(_failures)} criterion/criteria not met.")
        return 1
    print("PILOT VALIDATION PASSED: all criteria met.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
