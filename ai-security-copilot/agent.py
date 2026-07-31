import json
import os

from rag_retriever import retrieve_knowledge

try:
    from mistralai import Mistral

except ImportError as e:
    raise ImportError(
        "Could not import 'Mistral' from 'mistralai'. "
        "Please ensure 'mistralai>=1.0.0' is installed correctly."
    ) from e


SECURITY_CONTEXT_FILE = "output/combined_security_context.json"

REMEDIATION_FILE = "output/remediation_plan.json"

REPORT_FILE = "output/quantum_security_report.md"



def load_security_context():

    with open(
        SECURITY_CONTEXT_FILE,
        "r"
    ) as f:

        return json.load(f)



def load_remediation_plan():

    with open(
        REMEDIATION_FILE,
        "r"
    ) as f:

        return json.load(f)



def ask_mistral(prompt: str) -> str:

    api_key = os.getenv(
        "MISTRAL_API_KEY"
    )


    if not api_key:

        raise ValueError(
            "Environment variable MISTRAL_API_KEY is not set."
        )


    client = Mistral(
        api_key=api_key
    )


    response = client.chat.complete(

        model="mistral-small-latest",

        messages=[

            {
                "role": "system",

                "content": (

                    "You are a Senior Application Security "
                    "and Post Quantum Cryptography Security Engineer. "

                    "Generate enterprise security migration "
                    "assessments using provided evidence only."

                ),

            },

            {
                "role": "user",

                "content": prompt,

            },

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


        asset = finding.get(
            "asset"
        )


        if asset in analyzed_assets:

            continue


        analyzed_assets.add(
            asset
        )


        risk = finding.get(
            "risk",
            "Low"
        )


        score -= severity_penalty.get(
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


        "Wave 3 - Optimization": [],


    }



    for finding in findings:


        risk = finding.get(
            "risk"
        )


        if risk in [
            "Critical",
            "High"
        ]:

            waves[
                "Wave 1 - Immediate"
            ].append(
                finding.get("asset")
            )


        elif risk == "Medium":

            waves[
                "Wave 2 - High Priority"
            ].append(
                finding.get("asset")
            )


        else:

            waves[
                "Wave 3 - Optimization"
            ].append(
                finding.get("asset")
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


    knowledge_context = []



    for finding in pqc_findings:


        risk = finding.get(
            "risk"
        )


        if risk == "Low":

            continue



        query = (

            f"{finding['asset']} "

            f"{finding['category']} "

            "NIST migration guidance "

            "post quantum cryptography"

        )



        evidence = retrieve_knowledge(
            query
        )



        knowledge_context.append(

            {


                "finding_id":
                    finding.get(
                        "finding_id"
                    ),


                "asset":
                    finding.get(
                        "asset"
                    ),


                "risk":
                    finding.get(
                        "risk"
                    ),


                "category":
                    finding.get(
                        "category"
                    ),


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


                "estimated_effort":
                    finding.get(
                        "estimated_effort"
                    ),


                "estimated_hours":
                    finding.get(
                        "estimated_hours"
                    ),


                "owner":
                    finding.get(
                        "owner"
                    ),


                "nist_reference":
                    finding.get(
                        "nist_reference"
                    ),


                "confidence":
                    finding.get(
                        "confidence"
                    ),


                "evidence":
                    evidence,

            }

        )



    readiness_score = calculate_readiness_score(
        pqc_findings
    )


    migration_waves = generate_migration_waves(
        pqc_findings
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

{json.dumps(
    knowledge_context,
    indent=2
)}



SonarQube Findings:

{json.dumps(
    sonar_findings,
    indent=2
)}



Remediation Plan:

{json.dumps(
    remediation_plan,
    indent=2
)}



Migration Waves:

{json.dumps(
    migration_waves,
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
        f"{len(sonar_findings)} SonarQube findings..."

    )



    prompt = build_prompt(
        context,
        remediation_plan
    )



    response = ask_mistral(
        prompt
    )



    print(
        "\n===== AI SECURITY REPORT =====\n"
    )


    print(
        response
    )



    os.makedirs(
        "output",
        exist_ok=True
    )



    with open(
        REPORT_FILE,
        "w"
    ) as f:

        f.write(
            response
        )



    print(
        "\nSaved report:",
        REPORT_FILE
    )