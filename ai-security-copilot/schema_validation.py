"""
Shared JSON Schema validation helpers.

The pipeline previously trusted CBOM and SonarQube inputs - and its own
intermediate outputs - as ground truth with no structural checks. A
truncated or malformed scan would silently flow through the rule engine,
the remediation planner, and the AI report and produce a confident but
wrong result, including the score that gates merges. These helpers make
that failure loud and immediate instead of silent.
"""

import json
import os
import sys

from jsonschema import Draft7Validator

SCHEMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schemas")


class SchemaValidationError(Exception):
    """Raised when data fails schema validation. Message includes all errors."""


def _load_schema(schema_name: str) -> dict:
    path = os.path.join(SCHEMA_DIR, schema_name)
    with open(path, "r") as f:
        return json.load(f)


def validate(data, schema_name: str, source_label: str) -> None:
    """
    Validate `data` against the named schema (a filename under schemas/).
    Raises SchemaValidationError with an aggregated, readable message if
    invalid. Callers decide whether to catch it or let it kill the step.
    """
    schema = _load_schema(schema_name)
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))

    if errors:
        details = "\n".join(
            f"  - {'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
            for e in errors[:20]
        )
        more = f"\n  ... and {len(errors) - 20} more" if len(errors) > 20 else ""
        raise SchemaValidationError(
            f"{source_label} failed schema validation against {schema_name} "
            f"({len(errors)} error(s)):\n{details}{more}"
        )


def validate_or_exit(data, schema_name: str, source_label: str) -> None:
    """Convenience wrapper for CLI pipeline steps: validate or exit(1)."""
    try:
        validate(data, schema_name, source_label)
    except SchemaValidationError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)
