import json
import os
import sys

import config
from rag_retriever import retrieve_knowledge
from guardrails import GuardrailRunner
from llm_client import ask_llm
from pqc_analysis import calculate_security_score


SECURITY_CONTEXT_FILE = "output/combined_security_context.json"

REMEDIATION_FILE = "output/remediation_plan.json"

REPORT_FILE = "output/quantum_security_report.md"

GUARDRAIL_RESULTS_FILE = "output/guardrail_results.json"


def load_security_context():
    with open(SECURITY_CONTEXT_FILE, "r") as f:
        return json.load(f)


def load_remediation_plan():
    with open(REMEDIATION_FILE, "r") as f:
        return json.load(f)


def generate_migration_waves(findings):
    waves = {
        "Wave 1 - Immediate": [],
        "Wave 2 - High Priority": [],
        "Wave 3 - Optimization": [],
    }

    for finding in findings:
        risk = finding.get("risk")

        if risk in ["Critical", "High"]:
            waves["Wave 1 - Immediate"].append(finding.get("asset"))
        elif risk == "Medium":
            waves["Wave 2 - High Priority"].append(finding.get("asset"))
        else:
            waves["Wave 3 - Optimization"].append(finding.get("asset"))

    return waves


def build_prompt(context, remediation_plan, sonar_findings, evidence_by_finding):
    """
    Build the report-generation prompt.

    `sonar_findings` and `evidence_by_finding` are passed in explicitly
    (rather than re-derived from `context` / re-fetched from the vector
    store here) so the caller can hand in the guardrail-sanitized versions.
    Previously this function called retrieve_knowledge() a second time with
    unsanitized queries, which meant even when the prompt-injection
    guardrail detected and "sanitized" evidence, that sanitized copy was
    never actually the thing sent to the LLM.
    """

    pqc_findings = context.get("pqc_findings", [])

    knowledge_context = []

    for finding in pqc_findings:
        risk = finding.get("risk")

        if risk == "Low":
            continue

        evidence = evidence_by_finding.get(finding.get("finding_id"), [])

        knowledge_context.append(
            {
                "finding_id": finding.get("finding_id"),
                "asset": finding.get("asset"),
                "risk": finding.get("risk"),
                "category": finding.get("category"),
                "priority": finding.get("priority"),
                "reason": finding.get("reason"),
                "migration": finding.get("migration"),
                "recommended_algorithm": finding.get("recommended_algorithm"),
                "transition_strategy": finding.get("transition_strategy"),
                "migration_wave": finding.get("migration_wave"),
                "estimated_effort": finding.get("estimated_effort"),
                "estimated_hours": finding.get("estimated_hours"),
                "owner": finding.get("owner"),
                "nist_reference": finding.get("nist_reference"),
                "confidence": finding.get("confidence"),
                "evidence": evidence,
            }
        )

    readiness_score = calculate_security_score(pqc_findings)

    migration_waves = generate_migration_waves(pqc_findings)

    # Explicit allow-list of every algorithm name the LLM is permitted to
    # use, derived directly from evidence (current findings + their
    # recommended replacements). "Only discuss algorithms present in
    # findings" alone wasn't enough - models still add generic asides like
    # "you should also avoid DES/RC4" as general security education, which
    # the hallucination guardrail then (correctly) blocks. Naming the exact
    # allowed set removes the ambiguity that produced that failure mode.
    allowed_algorithms = sorted(
        {finding.get("asset") for finding in pqc_findings if finding.get("asset")}
        | {
            algo
            for finding in pqc_findings
            for algo in (finding.get("recommended_algorithm") or [])
        }
    )

    prompt = f"""

You are a Senior Application Security and
Post Quantum Cryptography Security Engineer.


Generate an enterprise security assessment.


You have:

1. CBOM cryptographic evidence

2. PQC migration rule findings

3. SonarQube source code vulnerabilities

4. SonarQube security hotspot findings

5. NIST knowledge base evidence

6. Remediation planning intelligence



IMPORTANT RULES:

- Only discuss algorithms present in findings.

- You may name ONLY the following cryptographic algorithms anywhere in the
  report: {", ".join(allowed_algorithms) if allowed_algorithms else "(none present in findings)"}.
  Do not name any other algorithm for any reason - not as a generic
  example, not as "other legacy algorithms to also avoid", not in the
  Executive Summary, NIST Guidance, or Limitations sections. If you want to
  make a general point about legacy cryptography, make it without naming a
  specific algorithm that isn't in the list above.

- Do not invent vulnerabilities.

- Do not assume missing evidence.

- Every recommendation must reference provided evidence.

- If evidence is missing, explicitly state:
  "No evidence available".

- Do not create fake files or line numbers.

- If SonarQube provides component and line,
  include exact source location.

- Explain relationship between code issue
  and cryptographic risk.

- Migration recommendations must come
  from remediation plan.

- Every template field below (Finding ID, Risk, Category, File, Line, etc.)
  must be filled in with a real value from the evidence. Never leave a
  field label with nothing after it - if there is genuinely no value,
  write "No evidence available" instead of leaving it blank.

- REMINDER: the only algorithms you may name anywhere in the report are:
  {", ".join(allowed_algorithms) if allowed_algorithms else "(none present in findings)"}.



Generate report:



# Quantum Security Assessment



## Quantum Readiness Score

Score: {readiness_score}%



## Executive Summary

Explain:

- Current quantum readiness

- Main cryptographic risks

- Application security risks

- Overall migration urgency



## Findings



For every PQC finding:



### Asset: <Asset Name>


Finding ID:

Risk:

Category:

Priority:

Why it matters:

Evidence:


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



## Code Security Findings (SonarQube)



For every Sonar finding:



File:

Line:

Severity:

Type:

Rule:

Message:


Security Impact:


Recommended Fix:




## NIST Guidance


Use only retrieved NIST evidence.



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




PQC Security Data:

{json.dumps(knowledge_context, indent=2)}



SonarQube Findings:

{json.dumps(sonar_findings, indent=2)}



Remediation Plan:

{json.dumps(remediation_plan, indent=2)}



Migration Waves:

{json.dumps(migration_waves, indent=2)}

"""

    return prompt


def _write_outputs(response, pre_result, post_result):
    os.makedirs("output", exist_ok=True)

    with open(REPORT_FILE, "w") as f:
        f.write(response)

    guardrail_report = {
        "pre_generation": pre_result,
        "post_generation": post_result,
    }
    with open(GUARDRAIL_RESULTS_FILE, "w") as f:
        json.dump(guardrail_report, f, indent=2, default=str)

    print("\nSaved report:", REPORT_FILE)
    print("Saved guardrail results:", GUARDRAIL_RESULTS_FILE)


if __name__ == "__main__":

    context = load_security_context()

    remediation_plan = load_remediation_plan()

    pqc_findings = context.get("pqc_findings", [])

    sonar_findings = context.get("sonarqube_findings", [])

    print(
        f"Analyzing "
        f"{len(pqc_findings)} PQC findings "
        f"and "
        f"{len(sonar_findings)} SonarQube findings..."
    )

    # --- Collect RAG evidence once, keyed by finding, and reuse it both for
    # guardrail validation and for the prompt itself (previously this was
    # fetched twice with two different code paths). ---
    evidence_by_finding = {}
    all_rag_evidence = []
    for finding in pqc_findings:
        if finding.get("risk") == "Low":
            continue
        query = (
            f"{finding['asset']} "
            f"{finding['category']} "
            "NIST migration guidance "
            "post quantum cryptography"
        )
        evidence = retrieve_knowledge(query)
        evidence_by_finding[finding.get("finding_id")] = evidence
        all_rag_evidence.extend(evidence)

    # --- GUARDRAIL 1: Pre-Generation (Prompt Injection) ---
    print("\n🛡️  Running pre-generation guardrails...")
    guardrails = GuardrailRunner(
        pqc_findings=pqc_findings,
        sonar_findings=sonar_findings,
        rag_evidence=all_rag_evidence,
    )
    pre_result = guardrails.run_pre_generation()

    if not pre_result["passed"]:
        print(
            f"⚠️  Prompt Injection detected: "
            f"{pre_result['threat_count']} threat(s) found."
        )
        print(f"   Action: {pre_result['recommendation']}")
    else:
        print("✅ Pre-generation check passed (no injection threats).")

    # --- Actually use the sanitized inputs to build the prompt. This is the
    # fix for "sanitized input computed then discarded": every prompt is now
    # built from injection_guard-sanitized RAG evidence and SonarQube text,
    # not just when a threat happens to be detected (cheap, no-op when
    # inputs are clean, and closes the gap either way). ---
    sanitized_evidence_by_finding = {
        finding_id: [
            {
                "content": guardrails.injection_guard.sanitize_text(e.get("content", "")),
                "source": e.get("source", ""),
            }
            for e in evidence
        ]
        for finding_id, evidence in evidence_by_finding.items()
    }
    sanitized_sonar_findings = pre_result["sanitized_sonar_findings"]

    # --- Generate Report ---
    prompt = build_prompt(
        context,
        remediation_plan,
        sanitized_sonar_findings,
        sanitized_evidence_by_finding,
    )

    response = ask_llm(prompt)

    # --- GUARDRAIL 2 & 3: Post-Generation (Hallucination + Output) ---
    print("\n🛡️  Running post-generation guardrails...")
    post_result = guardrails.run_post_generation(response)

    hallucination = post_result["hallucination_check"]
    output_val = post_result["output_validation"]

    if hallucination["passed"]:
        print("✅ Hallucination check passed.")
    else:
        print(
            f"⚠️  Hallucination issues: "
            f"{hallucination['violation_count']} violation(s)"
        )
        for v in hallucination["violations"]:
            print(f"   - [{v['severity'].upper()}] {v['detail']}")

    if output_val["passed"]:
        print("✅ Output validation passed.")
    else:
        print(
            f"⚠️  Output issues: "
            f"{output_val['violation_count']} violation(s)"
        )
        for v in output_val["violations"]:
            print(f"   - [{v['severity'].upper()}] {v['detail']}")

    print(f"\n📊 Report completeness: {output_val['completeness_score']}%")
    print(f"📊 Overall: {post_result['recommendation']}")

    # --- Output ---
    print("\n===== AI SECURITY REPORT =====\n")

    print(response)

    _write_outputs(response, pre_result, post_result)

    # --- GUARDRAIL ENFORCEMENT ---
    # Previously a guardrail failure only printed a warning; the script
    # always exited 0, so the "security gate" downstream had nothing to
    # gate on and the workflow never actually blocked anything. Outputs are
    # written above *before* we exit non-zero, so the uploaded artifact and
    # PR comment still show exactly what failed and why.
    blocking = pre_result["blocking"] or post_result["blocking"]

    if blocking and config.GUARDRAILS_BLOCK_ON_FAILURE:
        print(
            "\n❌ GUARDRAIL GATE FAILED: one or more violations met or exceeded "
            f"the blocking severity threshold ('{config.GUARDRAIL_BLOCK_SEVERITY}'). "
            "Failing this step. Set GUARDRAILS_BLOCK_ON_FAILURE=false to make this "
            "advisory-only."
        )
        sys.exit(1)

    print("\n✅ Guardrail gate passed.")
