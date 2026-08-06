# PQC Security Assessment Workspace

An AI-powered security engineering platform for post-quantum cryptography (PQC) readiness assessment. It combines CBOM analysis, SonarQube integration, NIST knowledge retrieval (RAG), and LLM-driven report generation with built-in AI guardrails. 

Intentionally vulnerable reference application used for security experimentation - https://github.com/OWASP/wrongsecrets

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CI/CD Pipeline                            │
│                  (.github/workflows/pqc-security-scan.yml)       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  CBOM Parser ──► Rule Validation Gate ──► Remediation Engine     │
│  (only writer of      (schema + rule-book                       │
│   security_findings)   consistency check)                       │
│       │                                                          │
│  SonarQube Parser ──► Sonar Integration                          │
│  (schema-validated)                                              │
│       │                                                          │
│  NIST PDFs ──► Ingest Documents ──► Vector DB (RAG)              │
│       │                                                          │
│       └──────────► AI Agent (Mistral or Claude) ◄── RAG Retriever│
│                          │                                       │
│                    ┌─────┴─────┐                                 │
│                    │ Guardrails │  (enforced - blocking          │
│                    ├───────────┤   violations fail the step)     │
│                    │ 1. Prompt Injection Protection (sanitizes   │
│                    │    inputs actually used in the prompt)      │
│                    │ 2. Hallucination Detection                  │
│                    │ 3. Output Validation (incl. unfilled        │
│                    │    template field detection)                │
│                    └───────────┘                                 │
│                          │                                       │
│                    Security Report + Guardrail Results            │
│                          │                                       │
│                    Security Gate (score + guardrail enforcement) │
│                          │                                       │
│                    PR Comment (GitHub)                            │
└─────────────────────────────────────────────────────────────────┘
```

LLM provider, gate threshold, and guardrail blocking strictness are all
configurable via environment variables - see `ai-security-copilot/config.py`
and the [Configuration](#configuration) section below.
> **Main Project & PR:** The primary implementation is located in the **`fea_guardrail_1`**  branch https://github.com/MeghaN28/Secure-AI-Hackathon/tree/fea_guardrail_1.  That branch contains the complete AI Security Copilot pipeline, GitHub Actions workflow, RAG integration, automated report generation, and the associated pull request with all major changes.
And the PR to be looked at is : https://github.com/MeghaN28/Secure-AI-Hackathon/pull/4

## Repository Structure

- `ai-security-copilot/` — main Python workflow for CBOM parsing, rule evaluation, remediation planning, and AI-powered report generation.
- `cbom-reports/` — generated or curated CBOM artifacts used for analysis.
- `cbomkit-theia/` — Go-based CBOM tooling and related scanner components.
- `sonar-cryptography/` — cryptography-focused rules, engine components, and plugin logic.
- `wrongsecrets/` — intentionally vulnerable reference application used for security experimentation - https://github.com/OWASP/wrongsecrets
- `sonarqube/` — local SonarQube installation and supporting runtime components.
- `.github/workflows/pqc-security-scan.yml` — CI workflow that runs the PQC scan pipeline on pull requests and pushes.

## Repository Structure

```
Secure-AI-Hackathon/
├── .github/workflows/
│   └── pqc-security-scan.yml        # CI pipeline (runs on PR/push)
├── ai-security-copilot/
│   ├── agent.py                      # Orchestrates LLM report generation + guardrail enforcement
│   ├── guardrails.py                 # AI guardrails (hallucination, injection, output)
│   ├── llm_client.py                 # Provider-agnostic LLM call (Mistral or Claude, via config.py)
│   ├── config.py                     # Central config: LLM provider/model, thresholds, gate policy
│   ├── pqc_analysis.py               # Single canonical CBOM analyzer + shared scoring logic
│   ├── schema_validation.py          # JSON Schema validation helpers
│   ├── cbom_parser.py                # Validates + analyzes CBOM JSON; sole writer of security_findings.json
│   ├── rule_engine.py                # Validation gate: schema + rule-book consistency check (no longer analyzes)
│   ├── remediation_engine.py         # Generates migration/remediation plans
│   ├── sonarqube_parser.py           # Validates + parses SonarQube vulnerability reports
│   ├── sonar_integration.py          # Combines CBOM + SonarQube context
│   ├── ingest_documents.py           # Indexes NIST PDFs into vector DB (RAG)
│   ├── rag_retriever.py              # Retrieves NIST evidence via similarity search
│   ├── query_knowledge_base.py       # Interactive RAG query tool
│   ├── embedding_config.py           # HuggingFace embedding model configuration
│   ├── security_gate.py              # CI merge gate (score threshold + guardrail enforcement)
│   ├── pqc_rules.json                # PQC risk rules with NIST references (single rule book in active use)
│   ├── app-cbom-final.json           # CBOM input (cryptographic inventory)
│   ├── requirements.txt              # Python dependencies
│   ├── schemas/
│   │   ├── cbom_schema.json          # Structural contract for CBOM input
│   │   ├── sonarqube_schema.json     # Structural contract for SonarQube input
│   │   └── findings_schema.json      # Structural contract for security_findings.json
│   ├── input/
│   │   ├── sonarqube-report.json     # SonarQube code analysis report
│   │   ├── sonarqube-vulnerabilities.json
│   │   └── sonarqube-hotspots.json   # Security hotspot findings
│   ├── knowledge_base/
│   │   ├── nist/
│   │   │   ├── NIST.FIPS.203.pdf     # ML-KEM standard
│   │   │   └── NIST.FIPS.204.pdf     # ML-DSA standard
│   │   └── migration/
│   │       └── pqc-migration-nist-sp-1800-38b-preliminary-draft.pdf
│   └── test/
│       └── VulnerableCrypto.java     # Sample vulnerable code for testing
├── cbomkit-theia/                    # CBOM tooling (Go-based scanner)
├── wrongsecrets/                     # Intentionally vulnerable reference app
└── README.md
```

## Pipeline Steps

| Step | Script | Purpose |
|------|--------|---------|
| 1 | `cbom_parser.py` | Validate CBOM against schema, analyze it, write `security_findings.json` (single writer) |
| 2 | `rule_engine.py` | Validate `security_findings.json` against schema + rule book; fails the job if inconsistent |
| 3 | `sonarqube_parser.py` | Validate + parse SonarQube vulnerability/hotspot reports |
| 4 | `sonar_integration.py` | Merge CBOM and SonarQube findings into unified context |
| 5 | `remediation_engine.py` | Generate prioritized remediation plan |
| 6 | `ingest_documents.py` | Index NIST PDFs into ChromaDB vector store |
| 7 | `agent.py` | Generate AI security report; enforces guardrails (exits non-zero on a blocking violation) |
| 8 | `security_gate.py` | CI merge gate - fails if score < threshold **or** guardrails reported a blocking violation |

Steps 1-2 used to be two independent CBOM analyzers that both wrote
`security_findings.json`, so whichever ran last in CI silently determined
what the rest of the pipeline saw. `cbom_parser.py` is now the only
analyzer/writer; `rule_engine.py` only validates its output (see
`pqc_analysis.py`'s docstring for details).

## AI Guardrails

The system includes three guardrails that validate AI-generated output, and
all three can now actually stop the pipeline, not just warn:

| Guardrail | Phase | What it checks |
|-----------|-------|---------------|
| Prompt Injection Protection | Pre-generation | Scans RAG documents and SonarQube data for injection attempts; sanitized text is what's actually sent to the LLM (not just reported) |
| Hallucination Detection | Post-generation | Verifies algorithms, NIST references, file paths, and risk levels against source evidence |
| Output Validation | Post-generation | Ensures report has required sections, valid score, no fabricated references, and no unfilled template fields (a report can no longer claim "100% complete" while containing blank `Finding ID:` / `Risk:` fields) |

A violation at or above `GUARDRAIL_BLOCK_SEVERITY` (default `high`) makes
`agent.py` exit non-zero **after** writing the report and
`guardrail_results.json`, so the failure is visible in the PR comment and
uploaded artifact, not just swallowed. `security_gate.py` independently
checks `guardrail_results.json` as part of the merge gate, so even if
someone reruns `agent.py` locally and ignores its exit code, the gate still
catches it. Set `GUARDRAILS_BLOCK_ON_FAILURE=false` to make guardrails
advisory-only again.

## Configuration

All of the following are environment variables (a `.env` file in
`ai-security-copilot/` also works, via `python-dotenv`). Nothing is
hardcoded in source anymore - see `config.py`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `LLM_PROVIDER` | `mistral` | `mistral` or `anthropic` - which model generates the report (`llm_client.py`) |
| `MISTRAL_MODEL` | `mistral-small-latest` | Mistral model name |
| `MISTRAL_API_KEY` | - | Required when `LLM_PROVIDER=mistral` |
| `ANTHROPIC_MODEL` | `claude-sonnet-4-5` | Claude model name |
| `ANTHROPIC_API_KEY` | - | Required when `LLM_PROVIDER=anthropic` |
| `MINIMUM_SECURITY_SCORE` | `60` | Merge-gate score threshold (`security_gate.py`) |
| `GUARDRAILS_BLOCK_ON_FAILURE` | `true` | Whether a blocking guardrail violation fails the pipeline |
| `GUARDRAIL_BLOCK_SEVERITY` | `high` | Minimum violation severity treated as blocking (`low`/`medium`/`high`/`critical`) |

## Quick Start

### Prerequisites

- Python 3.11+
- An API key for whichever `LLM_PROVIDER` you use (`MISTRAL_API_KEY` or `ANTHROPIC_API_KEY`)

### Install Dependencies

```bash
cd ai-security-copilot
pip install -r requirements.txt
```

### Run Locally

```bash
cd ai-security-copilot

# Step 1: Analyze CBOM (single analyzer, writes security_findings.json)
python cbom_parser.py

# Step 2: Validate that output against the rule book
python rule_engine.py

# Step 3: Parse SonarQube + combine context
python sonarqube_parser.py
python sonar_integration.py

# Step 4: Build the remediation plan
python remediation_engine.py

# Step 5: Build knowledge base (required once)
python ingest_documents.py

# Step 6: Generate report with guardrails (fails if a blocking violation occurs)
python agent.py

# Step 7: Merge gate (score + guardrail check)
python security_gate.py
```

Outputs are written to `ai-security-copilot/output/`:
- `quantum_security_report.md` — full security assessment
- `guardrail_results.json` — guardrail validation results, including `blocking` status
- `security_findings.json` — deduplicated PQC findings (single source of truth)
- `remediation_plan.json` — migration plan

## CI/CD Integration

The GitHub Actions workflow (`.github/workflows/pqc-security-scan.yml`) runs automatically on:
- Pull requests to `main`
- Pushes to any branch

It executes the full pipeline (including the security gate) and posts the
security report + guardrail validation table as a PR comment. To make this
an actual merge block, mark the `pqc-scan` job as a required status check in
branch protection - the job now genuinely fails when the gate fails, so
required-check enforcement does what it says.

### Required Secrets / Variables

| Name | Type | Purpose |
|------|------|---------|
| `MISTRAL_API_KEY` | Secret | Mistral AI API access for report generation (default provider) |
| `ANTHROPIC_API_KEY` | Secret | Claude API access, only needed if `LLM_PROVIDER=anthropic` |
| `LLM_PROVIDER` | Variable | `mistral` (default) or `anthropic` |
| `MINIMUM_SECURITY_SCORE` | Variable | Overrides the default `60` merge-gate threshold |
| `GUARDRAIL_BLOCK_SEVERITY` | Variable | Overrides the default `high` blocking threshold |

## Key Technologies

- **LLM**: Mistral or Claude, selected via `LLM_PROVIDER` (`llm_client.py`)
- **RAG**: LangChain + ChromaDB + HuggingFace embeddings (`all-MiniLM-L6-v2`)
- **Knowledge Base**: NIST FIPS 203, FIPS 204, SP 1800-38B
- **Code Analysis**: SonarQube findings integration (schema-validated)
- **Cryptographic Inventory**: CBOM (Cryptographic Bill of Materials), schema-validated
- **CI/CD**: GitHub Actions with a real, enforced security gate and PR comment integration

## Security Focus

This project helps teams:
- Inventory cryptographic dependencies from CBOM data
- Identify algorithms vulnerable to quantum computing attacks
- Prioritize migration by risk level and NIST guidance
- Generate actionable, evidence-backed remediation plans
- Validate AI outputs to prevent hallucinated security advice
- Automate security assessment in CI/CD pipelines


# test
