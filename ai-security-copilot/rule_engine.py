"""
PQC Rule Validation Gate.

This script used to re-run its own CBOM analysis (with different
normalization and finding_id logic than cbom_parser.py) and overwrite
output/security_findings.json - creating two competing analyzers whose
results diverged depending on run order, and whichever ran last in CI
silently won. See pqc_analysis.py's docstring for the full story.

cbom_parser.py is now the single analyzer and single writer of
output/security_findings.json. This script's job is to verify that file
is well-formed (schema) and still consistent with the current rule book
(pqc_rules.json) before remediation planning, the AI report, or the
merge gate are allowed to trust it - catching drift, corruption, or a
stale/hand-edited findings file between pipeline stages.
"""

import json
import sys

from pqc_analysis import normalize_algorithm
from schema_validation import SchemaValidationError, validate

RULE_FILE = "pqc_rules.json"
FINDINGS_FILE = "output/security_findings.json"


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def validate_against_rulebook(findings, rules):
    """
    Cross-check each finding's risk against the current rule book,
    keyed by normalized algorithm name (mirrors pqc_analysis.build_rule_lookup).
    """
    normalized_rules = {normalize_algorithm(name): rule for name, rule in rules.items()}

    errors = []
    for finding in findings:
        algo_key = finding.get("normalized_algorithm") or normalize_algorithm(finding.get("asset", ""))
        rule = normalized_rules.get(algo_key)

        if rule is None:
            errors.append(
                f"Finding '{finding.get('finding_id')}' references algorithm "
                f"'{finding.get('asset')}' which is not in {RULE_FILE}."
            )
            continue

        if rule.get("risk") and rule.get("risk") != finding.get("risk"):
            errors.append(
                f"Finding '{finding.get('finding_id')}' has risk="
                f"'{finding.get('risk')}' but {RULE_FILE} currently says risk="
                f"'{rule.get('risk')}' for {finding.get('asset')} "
                "(findings file is stale relative to the rule book)."
            )

    return errors


def main():
    try:
        findings = load_json(FINDINGS_FILE)
    except FileNotFoundError:
        print(
            f"❌ {FINDINGS_FILE} not found. Run cbom_parser.py before rule_engine.py.",
            file=sys.stderr,
        )
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ {FINDINGS_FILE} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    rules = load_json(RULE_FILE)

    try:
        validate(findings, "findings_schema.json", FINDINGS_FILE)
    except SchemaValidationError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)

    rulebook_errors = validate_against_rulebook(findings, rules)
    if rulebook_errors:
        print(
            f"❌ {FINDINGS_FILE} failed rule-book consistency check "
            f"({len(rulebook_errors)} issue(s)):"
        )
        for err in rulebook_errors:
            print(f"  - {err}")
        sys.exit(1)

    print(
        f"✅ {FINDINGS_FILE}: schema valid, {len(findings)} finding(s) "
        f"consistent with {RULE_FILE}."
    )


if __name__ == "__main__":
    main()
