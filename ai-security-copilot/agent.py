import json
import os
from rag_retriever import retrieve_knowledge

# Dual-compatibility import for mistralai SDK v1.0+ and legacy v0.x
try:
    from mistralai import Mistral
    LEGACY_SDK = False
except ImportError:
    try:
        from mistralai.client import MistralClient
        LEGACY_SDK = True
    except ImportError:
        raise ImportError(
            "The 'mistralai' package is missing or corrupted. "
            "Ensure 'mistralai>=1.0.0' is installed."
        )

FINDINGS_FILE = "output/security_findings.json"
REMEDIATION_FILE = "output/remediation_plan.json"
REPORT_FILE = "output/quantum_security_report.md"


def load_findings():
    with open(FINDINGS_FILE, "r") as f:
        return json.load(f)


def load_remediation_plan():
    with open(REMEDIATION_FILE, "r") as f:
        return json.load(f)


def ask_mistral(prompt: str) -> str:
    """Queries Mistral AI API supporting both modern Mistral v1+ and legacy v0.x SDKs."""
    api_key = os.getenv("MISTRAL_API_KEY")
    if not api_key:
        raise ValueError("Environment variable MISTRAL_API_KEY is not set.")

    system_content = (
        "You are a Senior Post Quantum Cryptography Security Engineer. "
        "Generate enterprise security migration assessments."
    )

    if LEGACY_SDK:
        client = MistralClient(api_key=api_key)
        response = client.chat(
            model="mistral-small-latest",
            messages=[
                {"role": "system", "content": system_content},
                {"role": "user", "content": prompt},
            ],
        )
    else:
        client = Mistral(api_key=api_key)
        response = client.chat.complete(
            model="mistral-small-latest",
            messages=[
                {"role": "system", "content": system_content},
                {"role": "user", "content": prompt},
            ],
        )

    return response.choices[0].message.content


def calculate_readiness_score(findings):
    score = 100
    severity_penalty = {
        "Critical": 30,
        "High": 20,
        "Medium": 10,
        "Low": 0,
    }

    analyzed_assets = set()

    for finding in findings:
        asset = finding.get("asset")

        if asset in analyzed_assets:
            continue

        analyzed_assets.add(asset)
        risk = finding.get("risk", "Low")
        score -= severity_penalty.get(risk, 0)

    return max(score, 0)


def generate_migration_waves(findings):
    waves = {
        "Wave 1 - Immediate": [],
        "Wave 2 - High Priority": [],
        "Wave 3 - Optimization": [],
    }

    for finding in findings:
        risk = finding.get("risk")

        if risk in ["Critical", "High"]:
            waves["Wave 1 - Immediate"].append(finding["asset"])
        elif risk == "Medium":
            waves["Wave 2 - High Priority"].append(finding["asset"])
        else:
            waves["Wave 3 - Optimization"].append(finding["asset"])

    return waves


def build_prompt(findings, remediation_plan):
    knowledge_context = []

    for finding in findings:
        risk = finding.get("risk")

        # Skip safe algorithms
        if risk == "Low":
            continue

        query = (
            f"{finding['asset']} "
            f"{finding['category']} "
            f"NIST migration guidance "
            f"post quantum cryptography"
        )

        evidence = retrieve_knowledge(query)

        knowledge_context.append(
            {
                "finding_id": finding["finding_id"],
                "asset": finding["asset"],
                "risk": finding["risk"],
                "category": finding["category"],
                "priority": finding["priority"],
                "reason": finding["reason"],
                "migration": finding["migration"],
                "recommended_algorithm": finding["recommended_algorithm"],
                "transition_strategy": finding["transition_strategy"],
                "migration_wave": finding["migration_wave"],
                "estimated_effort": finding["estimated_effort"],
                "estimated_hours": finding["estimated_hours"],
                "owner": finding["owner"],
                "nist_reference": finding["nist_reference"],
                "confidence": finding["confidence"],
                "evidence": evidence,
            }
        )

    readiness_score = calculate_readiness_score(findings)
    migration_waves = generate_migration_waves(findings)

    prompt = f"""
You are a Senior Post Quantum Cryptography Security Engineer.

Generate an enterprise security migration assessment.

You have:
1. CBOM cryptographic evidence
2. Security rule engine findings
3. NIST knowledge base evidence
4. Remediation planning intelligence

IMPORTANT RULES:

- Only discuss algorithms present in findings.
- Do not invent vulnerabilities.
- Do not assume missing evidence.
- Every recommendation must reference provided evidence.
- If evidence is missing, explicitly state "No evidence available".
- Do not create fake files, locations, or line numbers.
- Migration recommendations must come from the remediation plan.
- Migration roadmap must only use provided migration waves.

Generate the report in this format:

# Quantum Security Assessment

## Quantum Readiness Score

Score: {readiness_score}%

## Executive Summary

Explain:
- Current quantum readiness
- Main cryptographic risks
- Overall migration urgency

## Findings

For every finding:

### Asset: <Asset Name>

Finding ID:
Risk:
Category:
Priority:
Why it matters:
Evidence:
Reference only CBOM evidence provided.

Migration Assessment:
Current State:
Target State:
Migration Recommendation:
Recommended Algorithm:
Transition Strategy:
Migration Wave:
Estimated Effort:
Estimated Hours:
Owner:
Confidence:
Auto Fix Available:

## NIST Guidance

Use only retrieved NIST evidence.

Mention:
- FIPS references
- Migration guidance
- PQC standards

## Migration Roadmap

Wave 1 - Immediate
Critical and high-risk migrations.

Wave 2 - High Priority
Medium-risk improvements.

Wave 3 - Optimization
Long-term improvements.

## Limitations

Explain:
- Assessment scope
- Evidence limitations
- Unknown cryptographic assets
- Implementation dependencies

Security Data:
{json.dumps(knowledge_context, indent=2)}

Remediation Plan:
{json.dumps(remediation_plan, indent=2)}

Migration Waves:
{json.dumps(migration_waves, indent=2)}
"""

    return prompt


if __name__ == "__main__":
    findings = load_findings()
    remediation_plan = load_remediation_plan()

    print(f"Analyzing {len(findings)} security findings...\n")

    prompt = build_prompt(findings, remediation_plan)
    response = ask_mistral(prompt)

    print("\n===== AI SECURITY REPORT =====\n")
    print(response)

    # Ensure output directory exists before writing
    os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
    with open(REPORT_FILE, "w") as f:
        f.write(response)

    print("\nSaved report:", REPORT_FILE)