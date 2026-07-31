import json
import subprocess
from rag_retriever import retrieve_knowledge


FINDINGS_FILE = "output/security_findings.json"


def load_findings():

    with open(FINDINGS_FILE, "r") as f:
        return json.load(f)



def ask_ollama(prompt):

    result = subprocess.run(
        [
            "ollama",
            "run",
            "llama3.1"
        ],
        input=prompt,
        text=True,
        capture_output=True
    )

    if result.returncode != 0:
        return result.stderr

    return result.stdout



def calculate_readiness_score(findings):

    score = 100

    severity_penalty = {
        "Critical": 30,
        "High": 20,
        "Medium": 10,
        "Low": 0
    }


    for finding in findings:

        risk = finding.get(
            "risk",
            "Low"
        )

        score -= severity_penalty.get(
            risk,
            0
        )


    if score < 0:
        score = 0


    return score



def generate_migration_waves(findings):

    waves = {
        "Wave 1 - Immediate": [],
        "Wave 2 - High Priority": [],
        "Wave 3 - Optimization": []
    }


    for finding in findings:

        risk = finding.get(
            "risk"
        )


        if risk in ["Critical", "High"]:

            waves["Wave 1 - Immediate"].append(
                finding["asset"]
            )


        elif risk == "Medium":

            waves["Wave 2 - High Priority"].append(
                finding["asset"]
            )


        else:

            waves["Wave 3 - Optimization"].append(
                finding["asset"]
            )


    return waves



def build_prompt(findings):

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
                "asset": finding["asset"],
                "risk": finding["risk"],
                "priority": finding["priority"],
                "reason": finding["reason"],
                "migration": finding["migration"],
                "code_evidence": finding["evidence"],
                "nist_reference": evidence
            }
        )


    readiness_score = calculate_readiness_score(findings)

    migration_waves = generate_migration_waves(findings)


    prompt = f"""

You are a senior Post-Quantum Cryptography Security Engineer.

Your task is NOT to summarize JSON.

Your task is to create a security assessment report for engineers.

Use only the evidence provided.

DO NOT:
- Explain the JSON structure
- Describe the input format
- Add unrelated vulnerabilities
- Mention algorithms not present in findings


Generate the report in this format:


# Quantum Security Assessment


## Quantum Readiness Score

Score: {readiness_score}%


## Executive Summary

Explain the current quantum security posture.


## Critical Findings

For each finding include:

Asset:
Risk:
Priority:

Why it matters:

Evidence:

Migration Recommendation:


## NIST Guidance

Explain relevant NIST guidance from the retrieved evidence.


## Migration Roadmap

Wave 1:
Immediate fixes

Wave 2:
High priority migration

Wave 3:
Optimization


## Uncertainty

Explain limitations of this assessment.



Security Data:

{json.dumps(knowledge_context, indent=2)}


Migration Waves:

{json.dumps(migration_waves, indent=2)}


"""


    return prompt


if __name__ == "__main__":


    findings = load_findings()


    print(
        f"Analyzing {len(findings)} security findings...\n"
    )


    prompt = build_prompt(
        findings
    )


    response = ask_ollama(
        prompt
    )


    print(
        "\n===== AI SECURITY REPORT =====\n"
    )


    print(response)