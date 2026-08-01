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
- `wrongsecrets/` — intentionally vulnerable reference application used for security experimentation - https://github.com/OWASP/wrongsecrets
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

> **Main Project & PR:** The primary implementation is located in the **`fea_guardrail_1`** branch. That branch contains the complete AI Security Copilot pipeline, GitHub Actions workflow, RAG integration, automated report generation, and the associated pull request with all major changes.


