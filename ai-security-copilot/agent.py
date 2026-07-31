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
- Never invent files or line numbers.
- Never invent cryptographic algorithms.
- Never create fake NIST references.
- Never modify the provided Quantum Readiness Score.
- Copy the calculated score exactly.
- If evidence is missing write:
  "No evidence available."

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


    if not findings:

        return 100



    score = 100


    analyzed = set()



    for finding in findings:


        algorithm = finding.get(
            "asset",
            ""
        ).upper()



        if algorithm in analyzed:

            continue


        analyzed.add(
            algorithm
        )



        # Quantum vulnerable public key crypto

        if "RSA-OAEP" in algorithm:

            score -= 20


        elif "RSA" in algorithm:

            score -= 20



        # Weak hashes

        elif "MD5" in algorithm:

            score -= 15



        elif "SHA1" in algorithm or "SHA-1" in algorithm:

            score -= 10



        # Symmetric algorithms

        elif "AES-128" in algorithm:

            score -= 5



        # PQC adoption

        elif (
            "ML-KEM" in algorithm
            or
            "ML-DSA" in algorithm
        ):

            score += 10



    return max(
        min(score,100),
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



    assessment_date = datetime.utcnow().strftime(
        "%Y-%m-%d"
    )



    knowledge_context = []



    for finding in pqc_findings:


        risk = normalize_risk(
            finding.get("risk")
        )



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



IMPORTANT SECURITY ENGINE OUTPUT:

Quantum Readiness Score:

{readiness_score}%


Display this exact value.

DO NOT modify it.

DO NOT recalculate it.



Generate:



# Quantum Security Assessment



## Executive Summary


Include:

- Current quantum readiness
- Main cryptographic risks
- Application security risks
- Migration urgency



## Quantum Readiness Score


Score:

{readiness_score}%


Explain the score using only provided findings.



## PQC Findings



For every finding:


Asset:

Finding ID:

Risk:

Category:

Priority:

Why it matters:


Evidence:

Use CBOM evidence only.



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



For every Sonar finding:


File:

Line:

Severity:

Type:

Rule:

Message:


Security Impact:

Recommended Fix:


Use exact SonarQube data only.



## NIST Guidance


Use retrieved knowledge only.

If unavailable:

"No NIST evidence available."



## Migration Roadmap


{json.dumps(
    migration_waves,
    indent=2
)}



## Limitations


Include:

- Assessment scope
- Evidence limitations
- Unknown cryptographic assets
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



    score = calculate_readiness_score(
        pqc_findings
    )



    print(
        f"Analyzing {len(pqc_findings)} PQC findings "
        f"and {len(sonar_findings)} SonarQube findings"
    )



    print(
        "Calculated Quantum Readiness Score:",
        score,
        "%"
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