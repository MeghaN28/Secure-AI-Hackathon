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



SECURITY_CONTEXT_FILE = (
    "output/combined_security_context.json"
)

REMEDIATION_FILE = (
    "output/remediation_plan.json"
)

REPORT_FILE = (
    "output/quantum_security_report.md"
)



def load_json(path):

    with open(
        path,
        "r"
    ) as file:

        return json.load(file)



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


Your task is to generate an enterprise security
assessment report.


STRICT SECURITY RULES:


1. Evidence Grounding

- Use ONLY provided:
  - CBOM findings
  - SonarQube findings
  - Remediation plan
  - Retrieved NIST knowledge


2. Hallucination Prevention

- Never invent vulnerabilities.
- Never invent algorithms.
- Never invent files.
- Never invent line numbers.
- Never invent NIST references.
- Never invent migration standards.


3. NIST Rules

- Only use NIST information from the provided
  retrieval context.
- If retrieval context is empty write:

"No NIST evidence available."


4. Score Rules

- The Quantum Readiness Score is calculated
  by the security engine.
- Copy the provided score exactly.
- Never recalculate or modify it.


5. Evidence Rules

If evidence is missing write:

"No evidence available."


6. SonarQube Rules

Only use exact:
- file names
- line numbers
- rules
- severity
- messages

from SonarQube evidence.


Generate professional enterprise security
documentation.

"""

            },


            {

                "role": "user",

                "content": prompt

            }

        ]

    )


    return (
        response
        .choices[0]
        .message
        .content
    )



def normalize_algorithm(name):

    if not name:

        return ""

    return (
        name
        .upper()
        .replace("-", "")
        .replace("_", "")
        .replace(" ", "")
    )



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


        algorithm = normalize_algorithm(

            finding.get(
                "asset",
                ""
            )

        )



        if algorithm in analyzed:

            continue



        analyzed.add(
            algorithm
        )



        # Quantum vulnerable public key crypto

        if (
            "RSAOAEP" in algorithm
            or
            algorithm == "RSA"
        ):

            score -= 20



        # Weak hashes

        elif "MD5" in algorithm:

            score -= 15



        elif "SHA1" in algorithm:

            score -= 10



        # Symmetric crypto

        elif "AES128" in algorithm:

            score -= 5



        # PQC adoption

        elif (
            "MLKEM" in algorithm
            or
            "MLDSA" in algorithm
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

            finding.get(
                "risk"
            )

        )



        if risk in [

            "CRITICAL",
            "HIGH"

        ]:


            waves[
                "Wave 1 - Immediate"
            ].append(
                asset
            )



        elif risk == "MEDIUM":


            waves[
                "Wave 2 - High Priority"
            ].append(
                asset
            )



        else:


            waves[
                "Wave 3 - Optimization"
            ].append(
                asset
            )



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



    readiness_score = calculate_readiness_score(
        pqc_findings
    )



    migration_waves = generate_migration_waves(
        pqc_findings
    )



    pqc_context = []

    nist_context = []



    for finding in pqc_findings:


        asset = finding.get(
            "asset",
            ""
        )


        category = finding.get(
            "category",
            ""
        )



        query = (

            f"{asset} "
            f"{category} "
            "NIST FIPS PQC migration "
            "replacement guidance"

        )



        retrieved = retrieve_knowledge(
            query
        )



        if not retrieved:

            retrieved = [

                "No NIST evidence available."

            ]



        nist_context.append({

            "algorithm":
                asset,

            "category":
                category,

            "retrieved_nist_guidance":
                retrieved

        })



        pqc_context.append({

            "finding_id":
                finding.get(
                    "finding_id"
                ),


            "asset":
                asset,


            "risk":
                finding.get(
                    "risk"
                ),


            "category":
                category,


            "priority":
                finding.get(
                    "priority"
                ),


            "reason":
                finding.get(
                    "reason"
                ),


            "migration":
                finding.get(
                    "migration"
                ),


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
                finding.get(
                    "evidence",
                    []
                )

        })





    prompt = f"""

# Quantum Security Assessment


Assessment Date:

{assessment_date}



Prepared By:

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

DO NOT change it.

DO NOT recalculate it.



Generate the following report:



# Executive Summary


Include:

- Current quantum readiness
- Major cryptographic risks
- Application security risks
- Migration urgency



# Quantum Readiness Score


Score:

{readiness_score}%


Explain only using provided findings.



# PQC Findings


For every cryptographic finding:


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



# SonarQube Code Security Findings


For every SonarQube finding:


File:

Line:

Severity:

Type:

Rule:

Message:


Security Impact:

Recommended Fix:


Use only provided SonarQube data.



# NIST Guidance


IMPORTANT:

Use ONLY the retrieved NIST knowledge below.


Rules:

- Do not create FIPS references.
- Do not create SP references.
- Do not use outside knowledge.
- If missing write:

"No NIST evidence available."



# Migration Roadmap


{json.dumps(
    migration_waves,
    indent=2
)}



# Limitations


Include:

- Assessment scope
- Evidence limitations
- Unknown cryptographic assets
- Implementation dependencies



========================

PQC Evidence:

{json.dumps(
    pqc_context,
    indent=2
)}



========================

Retrieved NIST Knowledge:

{json.dumps(
    nist_context,
    indent=2
)}



========================

SonarQube Evidence:

{json.dumps(
    sonar_findings,
    indent=2
)}



========================

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



    score = calculate_readiness_score(
        pqc_findings
    )



    print(
        "Quantum Readiness Score:",
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
    ) as file:

        file.write(
            report
        )



    print(
        "Saved report:",
        REPORT_FILE
    )