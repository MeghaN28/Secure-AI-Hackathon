import json
import subprocess
from cbom_parser import analyze_cbom


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

    return result.stdout


def build_prompt(findings):

    prompt = """
You are a Post Quantum Cryptography Security Copilot.

Analyze the following crypto security findings.

Rules:
- Only use the provided evidence.
- Do not invent vulnerabilities.
- Explain risk clearly.
- Provide migration recommendations.
- Mention uncertainty when evidence is incomplete.

Findings:

"""

    prompt += json.dumps(
        findings,
        indent=2
    )

    return prompt


if __name__ == "__main__":

    findings = analyze_cbom(
        "app-cbom-final.json",
        "pqc_rules.json"
    )

    print(f"Analyzing {len(findings)} findings...\n")

    prompt = build_prompt(findings)

    response = ask_ollama(prompt)

    print("\n===== AI SECURITY REPORT =====\n")

    print(response)