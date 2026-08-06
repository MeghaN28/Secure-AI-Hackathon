"""
CI merge gate.

Two things changed here:

1. Scoring used to be a copy-pasted duplicate of agent.py's
   calculate_readiness_score, so the score the report presented to a
   reviewer and the score that (in theory) gated the merge could quietly
   drift apart. Both now call pqc_analysis.calculate_security_score.

2. This script previously wasn't called by the CI workflow at all -
   the README described it as "the CI merge gate" but nothing ever
   invoked it, so no PR was ever actually blocked by it. It's now wired
   into .github/workflows/pqc-security-scan.yml as a real step. It also
   now checks output/guardrail_results.json: a low-but-passing security
   score no longer overrides a blocking guardrail violation (e.g. a
   hallucinated report), and a missing guardrail file - which would mean
   the AI report step didn't run or didn't finish - fails the gate rather
   than being silently treated as "fine".
"""

import json
import os
import sys

import config
from pqc_analysis import calculate_security_score

FINDINGS_FILE = "output/security_findings.json"
GUARDRAIL_FILE = "output/guardrail_results.json"


def load_guardrail_status():
    """
    Returns (blocking: bool, error: str | None).
    error is set when guardrail results can't be verified at all, which is
    itself treated as a gate failure - a merge gate that can't confirm the
    guardrails ran isn't a gate.
    """
    if not os.path.exists(GUARDRAIL_FILE):
        return True, (
            f"{GUARDRAIL_FILE} not found - the AI report step may not have run "
            "or may have failed before writing results."
        )

    try:
        with open(GUARDRAIL_FILE) as f:
            results = json.load(f)
    except json.JSONDecodeError as e:
        return True, f"{GUARDRAIL_FILE} is not valid JSON: {e}"

    pre = results.get("pre_generation", {})
    post = results.get("post_generation", {})
    blocking = bool(pre.get("blocking")) or bool(post.get("blocking"))
    return blocking, None


def main():
    with open(FINDINGS_FILE) as f:
        findings = json.load(f)

    score = calculate_security_score(findings)

    guardrail_blocking, guardrail_error = load_guardrail_status()

    print("=" * 50)
    print(f"Security Score: {score}%")
    print(f"Required Score: {config.MINIMUM_SECURITY_SCORE}%")
    if guardrail_error:
        print(f"Guardrail Status: UNVERIFIED - {guardrail_error}")
    else:
        print(f"Guardrail Status: {'BLOCKING VIOLATION(S)' if guardrail_blocking else 'clear'}")
    print("=" * 50)

    failed = False

    if score < config.MINIMUM_SECURITY_SCORE:
        print("❌ Security score is below the required threshold.")
        failed = True

    if guardrail_error:
        print(f"❌ Guardrail status could not be verified: {guardrail_error}")
        failed = True
    elif guardrail_blocking:
        print("❌ AI guardrails reported a blocking violation - the report is not "
              "trustworthy enough to gate a merge on.")
        failed = True

    if failed:
        print("❌ SECURITY GATE FAILED")
        print("Merge blocked.")
        sys.exit(1)
    else:
        print("✅ SECURITY GATE PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
