import json
import os
from datetime import datetime

from rag_retriever import retrieve_knowledge

try:
    from mistralai import Mistral

except ImportError as e:
    raise ImportError(
        "Could not import Mistral SDK. "
        "Ensure mistralai>=1.0.0 is installed."
    ) from e


SECURITY_CONTEXT_FILE = "output/combined_security_context.json"
REMEDIATION_FILE = "output/remediation_plan.json"
REPORT_FILE = "output/quantum_security_report.md"


def load_json(path):

    with open(path, "r") as f:
        return json.load(f)



def load_security_context():

    return load_json(
        SECURITY_CONTEXT_FILE
    )



def load_remediation_plan():

    return load_json(
        REMEDIATION_FILE
    )



def ask_mistral(prompt):

    api_key = os.getenv(
        "MISTRAL_API_KEY"
    )


    if not api_key:
        raise ValueError(
            "MISTRAL_API_KEY is missing"
        )


    client = Mistral(
        api_key=api_key
    )


    response = client.chat.complete(

        model="mistral-small-latest",

        messages=[

            {
                "role": "system",
                "content": """

You are a Senior Application Security Engineer
specializing in Post Quantum Cryptography.

Generate enterprise security assessments.

STRICT RULES:

- Use only provided evidence.
- Never invent vulnerabilities.
- Never invent dates.
- Never invent files or line numbers.
- Never change calculated scores.
- If evidence is missing say:
  'No evidence available'.

"""
            },

            {
                "role": "user",
                "content": prompt
            }

        ]

    )


    return response.choices[0].message.content



def normalize_risk(value):

    if not value:
        return "LOW"

    return value.upper()



def calculate_readiness_score(findings):

    score = 100


    penalty = {

        "CRITICAL": 35,

        "HIGH": 20,

        "MEDIUM": 10,

        "LOW": 5

    }


    processed = set()


    for finding in findings:


        asset = finding.get(
            "asset"
        )


        if asset in processed:
            continue


        processed.add(asset)


        risk = normalize_risk(
            finding.get("risk")
        )


        score -= penalty.get(
            risk,
            0
        )


    return max(
        score,
        0
    )



def generate_migration_waves(findings):

    waves = {

        "Wave 1 - Immediate": [],

        "Wave 2 - High Priority": [],

        "Wave 3 - Optimization": []

    }


    for finding in findings:


        asset = finding.get(
            "asset"
        )


        risk = normalize_risk(
            finding.get("risk")
        )


        if risk in [
            "CRITICAL",
            "HIGH"
        ]:

            waves[
                "Wave 1 - Immediate"
            ].append(asset)


        elif risk == "MEDIUM":

            waves[
                "Wave 2 - High Priority"
            ].append(asset)


        else:

            waves[
                "Wave 3 - Optimization"
            ].append(asset)


    return waves



def build_prompt(
    context,
    remediation_plan
):


    pqc_findings = context.get(
        "pqc_findings",
        []
    )


    sonar_findings = context.get(
        "sonarqube_findings",
        []
    )


    assessment_date = datetime.now().strftime(
        "%Y-%m-%d"
    )


    knowledge_context = []


    for finding in pqc_findings:


        risk = normalize_risk(
            finding.get("risk")
        )


        if risk == "LOW":
            continue



        query = (

            f"{finding.get('asset')} "
            f"{finding.get('category')} "
            "NIST PQC migration guidance"

        )


        evidence = retrieve_knowledge(
            query
        )


        knowledge_context.append({

            "finding_id":
                finding.get("finding_id"),

            "asset":
                finding.get("asset"),

            "risk":
                finding.get("risk"),

            "category":
                finding.get("category"),

            "reason":
                finding.get("reason"),

            "migration":
                finding.get("migration"),

            "recommended_algorithm":
                finding.get(
                    "recommended_algorithm"
                ),

            "transition_strategy":
                finding.get(
                    "transition_strategy"
                ),

            "migration_wave":
                finding.get(
                    "migration_wave"
                ),

            "evidence":
                evidence

        })



    readiness_score = calculate_readiness_score(
        pqc_findings
    )


    migration_waves = generate_migration_waves(
        pqc_findings
    )



    prompt = f"""

Assessment Date:
{assessment_date}


Prepared by:
Senior Application Security &
Post Quantum Cryptography Engineer


Scope:

Cryptographic assets,
source code vulnerabilities,
and migration readiness.



IMPORTANT:

The readiness score below is calculated by
the security engine.

Do not modify it.

Quantum Readiness Score:

{readiness_score}%



Generate report:


# Quantum Security Assessment



## Executive Summary


Explain:

- Current quantum readiness
- Cryptographic risks
- Application security risks
- Migration urgency



## PQC Findings


For every finding include:


Asset:

Finding ID:

Risk:

Category:

Priority:

Why it matters:


Evidence:

Only use CBOM evidence.



Migration Assessment:


Current State:

Target State:

Recommended Algorithm:

Transition Strategy:

Migration Wave:

Estimated Effort:

Owner:

Confidence:



## SonarQube Code Security Findings


For every finding include:


File:

Line:

Severity:

Type:

Rule:

Message:


Security Impact:


Recommended Fix:


Use exact Sonar evidence only.



## NIST Guidance


Use retrieved knowledge only.



## Migration Roadmap


{json.dumps(
    migration_waves,
    indent=2
)}



## Limitations


Explain:

- Assessment scope
- Evidence limitations
- Unknown crypto assets
- Implementation dependencies



PQC Evidence:

{json.dumps(
    knowledge_context,
    indent=2
)}



Sonar Evidence:

{json.dumps(
    sonar_findings,
    indent=2
)}



Remediation Plan:

{json.dumps(
    remediation_plan,
    indent=2
)}

"""


    return prompt



if __name__ == "__main__":


    context = load_security_context()

    remediation_plan = load_remediation_plan()


    pqc_findings = context.get(
        "pqc_findings",
        []
    )


    sonar_findings = context.get(
        "sonarqube_findings",
        []
    )


    print(
        f"Analyzing "
        f"{len(pqc_findings)} PQC findings "
        f"and "
        f"{len(sonar_findings)} SonarQube findings"
    )


    prompt = build_prompt(
        context,
        remediation_plan
    )


    report = ask_mistral(
        prompt
    )


    os.makedirs(
        "output",
        exist_ok=True
    )


    with open(
        REPORT_FILE,
        "w"
    ) as f:

        f.write(report)


    print(
        "Saved report:",
        REPORT_FILE
    )