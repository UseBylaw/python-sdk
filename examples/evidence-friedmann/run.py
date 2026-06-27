"""Run the Friedmann evidence-enforcement sample against a live Vault.

    python run.py            # observe mode  — records would-decisions, never blocks
    python run.py --enforce  # enforce mode  — an ungrounded number is blocked

Everything is configured by bylaw.yaml. The agent passes no fact IDs by hand:
source tools auto-register evidence, and the protected action + customer-facing
output are checked against that evidence before they run.

Point it at a Vault with:
    export BYLAW_VAULT_URL=http://localhost:8000
    export BYLAW_VAULT_API_KEY=lx_test_your_key
"""
from __future__ import annotations

import argparse
import logging
import os

# In this repo the SDK module is `bylaw_python`; the published package
# (`bylaw-python`) imports as `bylaw_python`. Either alias works the same.
import bylaw_python as bylaw

import tools

CUSTOMER = "cust_friedmann"
SESSION = "sess-friedmann-1"

# A grounded number (12% = percent_change(balance_now=44800, balance_prev=40000)).
GROUNDED = "Good news — your portfolio is up 12% this quarter. I recommend rebalancing toward fixed income."
# A fabricated number ($52,000 is grounded in nothing).
FABRICATED = "You should move $52,000 into long-dated bonds right away."


def banner(title: str) -> None:
    print(f"\n{'=' * 68}\n  {title}\n{'=' * 68}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--enforce", action="store_true", help="block on ungrounded output")
    args = parser.parse_args()

    mode = "enforce" if args.enforce else "observe"
    # Surface the SDK's observe-mode "would_*" lines.
    logging.basicConfig(level=logging.INFO, format="    [%(name)s] %(message)s")

    bylaw.configure(
        vault_url=os.environ.get("BYLAW_VAULT_URL", "http://localhost:8000"),
        vault_api_key=os.environ.get("BYLAW_VAULT_API_KEY", ""),
        agent_id="friedmann-advisor",
        evidence_mode=mode,          # gates the protected action
        evidence_output_mode=mode,   # gates the customer-facing output
    )
    wrapped = bylaw.auto_instrument(tools, manifest="bylaw.yaml")
    banner(f"Bylaw evidence enforcement — {mode.upper()} mode")
    print("  Instrumented tools (via bylaw.yaml, zero manual fact-IDs):")
    for name in wrapped:
        print(f"    - {name}")

    with bylaw.evidence_session(session_id=SESSION, customer_id=CUSTOMER):
        banner("1. Source tools auto-register evidence")
        prof = tools.get_customer_profile(CUSTOMER)
        print(f"  profile: {prof['name']} (dob {prof['date_of_birth']}, {prof['risk_profile']})")
        stmt = tools.search_account_statement(CUSTOMER)
        print(f"  statement: balance_now={stmt['balance_now']} balance_prev={stmt['balance_prev']}")
        calc = tools.calculate_projection(CUSTOMER)
        print(f"  calculation: account_a={calc['account_a']} account_b={calc['account_b']}")

        banner("2. Protected action — check-action (needs authoritative evidence)")
        rec = tools.generate_recommendation(CUSTOMER)
        print(f"  recommendation produced: {rec['action']}")

        banner("3a. Customer-facing output — a GROUNDED number (12% from balances)")
        try:
            tools.send_advisor_response(CUSTOMER, GROUNDED)
            print("  sent ✓  (12% recomputes from balance_now/balance_prev)")
        except bylaw.EvidenceBlockedError as exc:
            print(f"  BLOCKED: {exc}")

        banner("3b. Customer-facing output — a FABRICATED number ($52,000)")
        try:
            tools.send_advisor_response(CUSTOMER, FABRICATED)
            if mode == "enforce":
                print("  sent ✓  (unexpected — should have been blocked)")
            else:
                print("  sent ✓  (observe: recorded would_deny above, not blocked)")
        except bylaw.EvidenceBlockedError as exc:
            print(f"  BLOCKED ✗  {exc}")

    banner("Done")
    print("  Run again with --enforce to see the fabricated number blocked live.\n")


if __name__ == "__main__":
    main()
