"""
Canonical CBOM -> PQC findings analysis and scoring.

Before this module existed, `cbom_parser.py` and `rule_engine.py` each
implemented their own version of "read the CBOM, match against
pqc_rules.json, produce findings" - with different normalization,
different dedup behavior, and different finding_id schemes - and both
wrote to the same file, `output/security_findings.json`. Whichever one
ran last in CI silently won, and the AI report, the remediation plan,
and the merge gate could each end up reasoning about a different set of
findings depending on run order.

Similarly, `agent.py` (calculate_readiness_score) and `security_gate.py`
(calculate_security_score) each had their own copy-pasted scoring
function.

This module is now the single source of truth for both. `cbom_parser.py`
is the only script that runs this analysis and writes
`output/security_findings.json`; `rule_engine.py` was repurposed into a
validation gate that checks that file instead of re-deriving it (see
rule_engine.py's module docstring).
"""

SEVERITY_PENALTY = {
    "Critical": 30,
    "High": 20,
    "Medium": 10,
    "Low": 0,
}

# Longer/more specific patterns must come first, otherwise e.g. "AES128"
# would match inside "AES128GCM" before the more specific entry is tried.
ALGORITHM_MAP = [
    ("RSAOAEP", "RSA-OAEP"),
    ("RSA2048", "RSA"),
    ("AES256CBCPKCS5", "AES-256"),
    ("AES256GCM", "AES-256"),
    ("AES256", "AES-256"),
    ("AES128GCM", "AES-128"),
    ("AES128CBCPKCS5", "AES-128"),
    ("AES128", "AES-128"),
    ("SHA256", "SHA-256"),
    ("SHA1", "SHA-1"),
    ("HMACSHA1", "SHA-1"),
    ("MD5", "MD5"),
    ("3DES", "3DES"),
    ("DES", "DES"),
    ("MLKEM", "ML-KEM"),
    ("MLDSA", "ML-DSA"),
]


def normalize_algorithm(name):
    """Normalize an algorithm name for lookup (strip separators, uppercase)."""
    if not name:
        return ""

    name = name.upper()
    for old in ("-", "_", " "):
        name = name.replace(old, "")

    return name


def extract_algorithm(asset):
    """Extract a canonical algorithm name from a CycloneDX CBOM asset."""
    name = asset.get("name", "")
    if not name:
        return None

    normalized = normalize_algorithm(name)

    for pattern, algorithm in ALGORITHM_MAP:
        if pattern in normalized:
            return algorithm

    return None


def extract_evidence(asset):
    """Extract source-location evidence (file/line/context) from a CBOM asset."""
    evidence = asset.get("evidence", {})
    occurrences = evidence.get("occurrences", [])

    return [
        {
            "location": item.get("location"),
            "line": item.get("line"),
            "context": item.get("additionalContext"),
        }
        for item in occurrences
    ]


def build_rule_lookup(rules):
    """Build a normalized algorithm-name -> rule lookup table, with known aliases."""
    lookup = {}

    for algorithm, rule in rules.items():
        lookup[normalize_algorithm(algorithm)] = rule

    # Aliases without modifying the rule book JSON.
    if "SHA1" in lookup:
        lookup["SHA-1"] = lookup["SHA1"]
    if "SHA-1" in lookup:
        lookup["SHA1"] = lookup["SHA-1"]
    if "RSA2048" in lookup:
        lookup["RSA"] = lookup["RSA2048"]

    return lookup


def analyze_cbom(cbom, rules):
    """
    Analyze a CBOM against the PQC rule book and return a deduplicated
    list of findings (one entry per distinct algorithm, with evidence
    from every occurrence merged together).
    """
    rules_lookup = build_rule_lookup(rules)

    findings = {}

    for asset in cbom.get("components", []):
        if asset.get("type") != "cryptographic-asset":
            continue

        algorithm = extract_algorithm(asset)
        if not algorithm:
            continue

        normalized = normalize_algorithm(algorithm)
        if normalized not in rules_lookup:
            continue

        rule = rules_lookup[normalized]

        if normalized not in findings:
            findings[normalized] = {
                "finding_id": f"PQC-{normalized}-001",
                "asset": algorithm,
                "normalized_algorithm": normalized,
                "risk": rule.get("risk"),
                "category": rule.get("category"),
                "priority": rule.get("priority"),
                "reason": rule.get("reason"),
                "migration": rule.get("migration"),
                "recommended_algorithm": rule.get("recommended_algorithm", []),
                "transition_strategy": rule.get("transition_strategy", "Unknown"),
                "migration_wave": rule.get("migration_wave", "Unknown"),
                "estimated_effort": rule.get("estimated_effort", "Unknown"),
                "estimated_hours": rule.get("estimated_hours", "Unknown"),
                "owner": rule.get("owner", "Security Team"),
                "nist_reference": rule.get("nist_reference", []),
                "confidence": rule.get("confidence", "Medium"),
                "auto_fix": rule.get("auto_fix", False),
                "evidence": [],
            }

        findings[normalized]["evidence"].extend(extract_evidence(asset))

    return list(findings.values())


def calculate_security_score(findings):
    """
    Score overall PQC readiness from 0-100 based on the highest-risk,
    deduplicated findings. Shared by agent.py (report readiness score)
    and security_gate.py (merge-gate score) so the two can never diverge.
    """
    analyzed_assets = set()
    total_penalty = 0

    for finding in findings:
        asset = finding.get("asset")
        if asset in analyzed_assets:
            continue
        analyzed_assets.add(asset)

        risk = finding.get("risk", "Low")
        total_penalty += SEVERITY_PENALTY.get(risk, 0)

    # Scale penalty: cap max deduction at 80 points so score reflects
    # readiness rather than just count of findings. A fully vulnerable
    # codebase still retains a non-zero score to indicate the assessment
    # itself completed.
    num_assets = len(analyzed_assets) if analyzed_assets else 1
    max_possible_penalty = num_assets * 30  # worst case: all Critical
    normalized_penalty = (total_penalty / max_possible_penalty) * 80 if max_possible_penalty else 0

    score = round(100 - normalized_penalty)
    return max(score, 0)
