# PQC Security Assessment Workspace

This repository is a multi-component security engineering workspace focused on post-quantum cryptography (PQC) readiness assessment, cryptographic inventory analysis, and remediation planning.

The project combines:

- a Python-based CBOM and PQC rule analysis pipeline
- a GitHub Actions CI workflow for automated security scanning
- supporting tooling for cryptography rule validation and remediation generation
- sample applications and security labs used for vulnerability and migration demonstrations

## Repository Structure

- `ai-security-copilot/` — main Python workflow for CBOM parsing, rule evaluation, remediation planning, and AI-powered report generation.
- `cbom-reports/` — generated or curated CBOM artifacts used for analysis.
- `cbomkit-theia/` — Go-based CBOM tooling and related scanner components.
- `sonar-cryptography/` — cryptography-focused rules, engine components, and plugin logic.
- `wrongsecrets/` — intentionally vulnerable reference application used for security experimentation.
- `sonarqube/` — local SonarQube installation and supporting runtime components.
- `.github/workflows/pqc-security-scan.yml` — CI workflow that runs the PQC scan pipeline on pull requests and pushes.

## What the Pipeline Does

The primary flow in `ai-security-copilot/` performs the following steps:

1. Load the CBOM input from the repository.
2. Parse cryptographic assets and their evidence.
3. Evaluate them against PQC risk rules.
4. Produce a security finding set.
5. Generate a migration/remediation plan.
6. Build an AI-generated report summarizing the quantum-readiness posture.

## Quick Start

### Prerequisites

- Python 3.11+
- `pip`
- Access to a Mistral API key via GitHub Actions secret or local environment
- Optional local model/runtime support for Ollama if you want to test the AI-driven workflow outside CI

### Install Python Dependencies

```bash
cd ai-security-copilot
pip install -r requirements.txt
```

### Run the Pipeline Locally

```bash
cd ai-security-copilot
python3 cbom_parser.py
python3 rule_engine.py
python3 remediation_engine.py
python3 agent.py
```

This produces the report and supporting artifacts in the `output/` directory.

## CI Workflow

The repository includes a GitHub Actions workflow at `.github/workflows/pqc-security-scan.yml` that runs the full scan automatically for pull requests and branch pushes.

The workflow:

- checks out the repository
- sets up Python
- installs dependencies
- verifies the Mistral SDK
- runs CBOM parsing and rule analysis
- generates remediation guidance
- creates the security assessment report
- uploads the report as an artifact
- comments the report on pull requests

## Outputs

Key generated outputs are stored under `ai-security-copilot/output/`:

- `security_findings.json`
- `remediation_plan.json`
- `quantum_security_report.md`

## Security Focus

This project is designed to help teams:

- inventory cryptographic dependencies from CBOM data
- identify algorithms that are not quantum-safe
- prioritize migration effort by risk and timeline
- generate actionable remediation recommendations
- capture evidence for governance and engineering review

## Notes

This workspace is intentionally heterogeneous and combines scanning, policy, planning, and demonstration components. The main operational pipeline is centered in `ai-security-copilot/`, while the other directories provide supporting toolchains, scanners, and reference workloads.
