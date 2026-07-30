import json


def load_json(file_path):
    with open(file_path, "r") as file:
        return json.load(file)



def extract_algorithm(asset):
    """
    Extract algorithm information from CycloneDX CBOM cryptoProperties
    """

    crypto = asset.get("cryptoProperties", {})

    search_text = json.dumps(crypto).upper()

    # Common crypto algorithms
    algorithms = [
        "RSA-OAEP",
        "RSA",
        "AES",
        "AES-128",
        "AES-256",
        "SHA-1",
        "SHA1",
        "SHA-256",
        "SHA256",
        "MD5",
        "DES",
        "3DES",
        "HMAC",
        "ML-KEM",
        "ML-DSA"
    ]

    for algo in algorithms:
        if algo in search_text:
            return algo

    # Handle key/material based detection
    asset_type = (
        crypto
        .get("assetType", "")
        .lower()
    )

    related = (
        crypto
        .get("relatedCryptoMaterialProperties", {})
        .get("type", "")
        .lower()
    )

    if "secret-key" in related:
        return "AES"

    if "public-key" in related:
        return "RSA"

    if "private-key" in related:
        return "RSA"

    if "message-digest" in related:
        return "SHA-256"

    return None


def extract_location(asset):
    evidence = asset.get("evidence", {})

    occurrences = evidence.get("occurrences", [])

    if occurrences:
        occurrence = occurrences[0]

        return {
            "file": occurrence.get("location"),
            "line": occurrence.get("line")
        }

    return {
        "file": "Unknown",
        "line": None
    }


def analyze_cbom(cbom_file, rules_file):

    cbom = load_json(cbom_file)
    rules = load_json(rules_file)

    findings = []

    for asset in cbom.get("components", []):

        if asset.get("type") != "cryptographic-asset":
            continue

        algorithm = extract_algorithm(asset)

        if algorithm and algorithm in rules:

            finding = {
                "asset": asset.get("name"),
                "algorithm": algorithm,
                "location": extract_location(asset),
                "risk": rules[algorithm]["risk"],
                "reason": rules[algorithm]["reason"],
                "migration": rules[algorithm]["migration"],
                "priority": rules[algorithm]["priority"]
            }

            findings.append(finding)

    return findings


if __name__ == "__main__":

    findings = analyze_cbom(
        "app-cbom-final.json",
        "pqc_rules.json"
    )

    print("\n===== PQC SECURITY FINDINGS =====\n")

    print(f"Total findings: {len(findings)}\n")

    for finding in findings[:10]:

        print("--------------------------------")
        print("Algorithm :", finding["algorithm"])
        print("Risk      :", finding["risk"])
        print("Location  :", finding["location"])
        print("Reason    :", finding["reason"])
        print("Migration :", finding["migration"])