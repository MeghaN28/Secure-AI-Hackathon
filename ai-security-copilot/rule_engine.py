import yaml

with open("rules/pqc_rules.yaml") as f:
    rules = yaml.safe_load(f)

print("Loaded Rules:")
for rule in rules["rules"]:
    print(rule["id"], "-", rule["name"])