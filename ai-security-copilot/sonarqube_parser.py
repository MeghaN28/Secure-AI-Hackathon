"""
SonarQube findings parser.

Previously this trusted every SonarQube export file as well-formed and
would fail with an opaque traceback (or silently produce partial data) on
anything malformed. Each file is now schema-checked before parsing so a
truncated or corrupted scan is caught here instead of quietly flowing
into the rule engine, remediation plan, and AI report.
"""

import json
import os
import sys

from schema_validation import SchemaValidationError, validate

SONAR_FILES = [
    "input/sonarqube-report.json",
    "input/sonarqube-vulnerabilities.json",
    "input/sonarqube-hotspots.json",
]


OUTPUT_FILE = "output/sonar_findings.json"


def load_json(file_path):
    with open(file_path, "r") as file:
        return json.load(file)


def parse_sonar_findings():
    findings = []

    for file_path in SONAR_FILES:
        try:
            data = load_json(file_path)
        except FileNotFoundError:
            print(f"Skipping missing file: {file_path}")
            continue
        except json.JSONDecodeError as e:
            print(f"❌ {file_path} is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)

        try:
            validate(data, "sonarqube_schema.json", file_path)
        except SchemaValidationError as e:
            print(f"❌ {e}", file=sys.stderr)
            sys.exit(1)

        # Normal Sonar Issues API response
        for issue in data.get("issues", []):
            findings.append(
                {
                    "source": file_path,
                    "component": issue.get("component"),
                    "line": issue.get("line"),
                    "severity": issue.get("severity"),
                    "type": issue.get("type"),
                    "rule": issue.get("rule"),
                    "message": issue.get("message"),
                }
            )

        # Sonar Security Hotspots API response
        for hotspot in data.get("hotspots", []):
            findings.append(
                {
                    "source": file_path,
                    "component": hotspot.get("component"),
                    "line": hotspot.get("line"),
                    "severity": hotspot.get("vulnerabilityProbability"),
                    "type": "SECURITY_HOTSPOT",
                    "rule": hotspot.get("ruleKey"),
                    "message": hotspot.get("message"),
                }
            )

    return findings


if __name__ == "__main__":
    results = parse_sonar_findings()

    os.makedirs("output", exist_ok=True)

    with open(OUTPUT_FILE, "w") as file:
        json.dump(results, file, indent=4)

    print(f"Saved Sonar findings: {OUTPUT_FILE}")
    print(f"Total findings: {len(results)}")
