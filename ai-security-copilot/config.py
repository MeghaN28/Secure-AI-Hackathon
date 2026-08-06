"""
Central configuration for the PQC security pipeline.

Previously the LLM provider/model and the merge-gate threshold were
hardcoded inline (agent.py imported `mistralai` directly and hardcoded
`model="mistral-small-latest"`; security_gate.py hardcoded
`MINIMUM_SECURITY_SCORE = 60`). A product customer had no way to point
the pipeline at a different LLM (e.g. Claude) or tune the merge-gate
threshold without editing source.

Everything here is overridable via environment variables (or a `.env`
file, loaded through python-dotenv) so deployments can change behavior
without touching code.
"""

import os

from dotenv import load_dotenv

load_dotenv()


def _get_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _get_int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    try:
        return int(val)
    except ValueError:
        return default


# ---------------------------------------------------------------------------
# LLM provider selection
# ---------------------------------------------------------------------------
# Supported: "mistral", "anthropic". This is the knob a product customer
# flips to run the report generator on Claude instead of Mistral - no code
# changes required. See llm_client.py.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "mistral").strip().lower()

MISTRAL_MODEL = os.getenv("MISTRAL_MODEL", "mistral-small-latest")
MISTRAL_API_KEY = os.getenv("MISTRAL_API_KEY")

ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

LLM_MAX_TOKENS = _get_int("LLM_MAX_TOKENS", 4096)

# ---------------------------------------------------------------------------
# Security gate
# ---------------------------------------------------------------------------
MINIMUM_SECURITY_SCORE = _get_int("MINIMUM_SECURITY_SCORE", 60)

# ---------------------------------------------------------------------------
# Guardrail enforcement
# ---------------------------------------------------------------------------
# When true (default), agent.py and security_gate.py treat a blocking
# guardrail violation as build-breaking instead of advisory-only. This is
# what makes "guardrail failed" actually stop a merge rather than just
# print a warning that nothing downstream ever looks at.
GUARDRAILS_BLOCK_ON_FAILURE = _get_bool("GUARDRAILS_BLOCK_ON_FAILURE", True)

# Minimum violation severity that counts as "blocking". One of:
# "low", "medium", "high", "critical".
GUARDRAIL_BLOCK_SEVERITY = os.getenv("GUARDRAIL_BLOCK_SEVERITY", "high").strip().lower()

# ---------------------------------------------------------------------------
# File paths (centralized so tests/CI can override them consistently)
# ---------------------------------------------------------------------------
OUTPUT_DIR = os.getenv("PQC_OUTPUT_DIR", "output")
