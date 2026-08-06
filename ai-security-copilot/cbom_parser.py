"""
CBOM -> PQC findings analyzer.

This is the single analyzer in the pipeline and the single writer of
`output/security_findings.json`. It used to duplicate (with subtly
different logic) what rule_engine.py also did, and both scripts wrote to
the same output file - whichever ran later in CI silently won, which
meant the AI report and the remediation plan could end up built from
different, inconsistent findings. rule_engine.py no longer analyzes
anything; it validates what this script produces. See pqc_analysis.py
for the shared analysis/scoring logic and rule_engine.py's docstring for
the validation step.
"""

import json
import os
import sys

from pqc_analysis import analyze_cbom
from schema_validation import SchemaValidationError, validate

CBOM_FILE = "app-cbom-final.json"
RULE_FILE = "pqc_rules.json"
OUTPUT_FILE = "output/security_findings.json"


def load_json(file_path):
    with open(file_path, "r") as file:
        return json.load(file)


def save_results(findings, output_file=OUTPUT_FILE):
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "w") as f:
        json.dump(findings, f, indent=4)


def main():
    try:
        cbom = load_json(CBOM_FILE)
    except json.JSONDecodeError as e:
        print(f"❌ {CBOM_FILE} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    rules = load_json(RULE_FILE)

    try:
        validate(cbom, "cbom_schema.json", CBOM_FILE)
    except SchemaValidationError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)

    findings = analyze_cbom(cbom, rules)

    # Fail loud rather than silently producing an empty, confident-looking
    # downstream report when the CBOM was structurally valid but contained
    # nothing our rule book recognizes (e.g. a scan against the wrong app).
    if not findings and cbom.get("components"):
        print(
            "⚠️  CBOM parsed successfully but matched zero PQC rules against "
            f"{len(cbom.get('components', []))} component(s). Findings will be empty - "
            "verify this is expected before trusting downstream results.",
            file=sys.stderr,
        )

    print("\n===== PQC SECURITY FINDINGS =====\n")
    print("Total findings:", len(findings))

    for finding in findings:
        print("\n--------------------------------")
        print("Algorithm:", finding["asset"])
        print("Risk:", finding["risk"])
        print("Priority:", finding["priority"])
        print("Evidence Count:", len(finding["evidence"]))
        print("Migration:", finding["migration"])

    save_results(findings)

    print("\nSaved:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
