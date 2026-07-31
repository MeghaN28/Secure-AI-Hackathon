import json


RULE_FILE = "pqc_rules.json"
CBOM_FILE = "app-cbom-final.json"
OUTPUT_FILE = "output/security_findings.json"


def load_rules():
    with open(RULE_FILE, "r") as f:
        return json.load(f)


def load_cbom():
    with open(CBOM_FILE, "r") as f:
        return json.load(f)


def normalize_algorithm(name):
    """
    Normalize algorithm names so CBOM names
    match rule book entries.
    
    Examples:
    SHA-1   -> SHA1
    SHA_1   -> SHA1
    AES-128 -> AES128
    """

    if not name:
        return ""

    name = name.upper()
    name = name.replace("-", "")
    name = name.replace("_", "")
    name = name.replace(" ", "")

    return name


def build_normalized_rules(rules):
    """
    Create normalized lookup table.
    """

    normalized_rules = {}

    for algorithm, rule in rules.items():
        normalized_rules[normalize_algorithm(algorithm)] = rule

    return normalized_rules
def extract_evidence(evidence):

    occurrences = evidence.get("occurrences", [])

    extracted = []

    for item in occurrences[:5]:

        extracted.append({
            "location": item.get("location"),
            "line": item.get("line"),
            "context": item.get("additionalContext")
        })

    return extracted


def analyze_cbom(cbom, rules):

    findings = []

    normalized_rules = build_normalized_rules(rules)

    for asset in cbom.get("components", []):

        if asset.get("type") != "cryptographic-asset":
            continue

        crypto_properties = asset.get("cryptoProperties", {})

        if crypto_properties.get("assetType") != "algorithm":
            continue


        raw_algorithm = asset.get("name")

        algorithm = normalize_algorithm(raw_algorithm)


        if algorithm in normalized_rules:

            rule = normalized_rules[algorithm]

            findings.append({

                "asset": raw_algorithm,

                "normalized_algorithm": algorithm,

                "risk": rule["risk"],

                "category": rule["category"],

                "priority": rule["priority"],

                "reason": rule["reason"],

                "migration": rule["migration"],

                "evidence": extract_evidence(asset.get("evidence", {}))

            })


    return findings



def save_results(findings):

    with open(OUTPUT_FILE, "w") as f:
        json.dump(findings, f, indent=2)



if __name__ == "__main__":

    rules = load_rules()

    cbom = load_cbom()


    findings = analyze_cbom(cbom, rules)


    print("\n===== PQC SECURITY FINDINGS =====")

    print("Total findings:", len(findings))


    for finding in findings:

        print(
            f"{finding['asset']} | "
            f"{finding['risk']} | "
            f"{finding['priority']}"
        )


    save_results(findings)


    print("\nSaved:", OUTPUT_FILE)