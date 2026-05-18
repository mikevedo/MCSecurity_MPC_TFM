# MCP Security Audit PoC

Terminal-based cloud security audit system using MCP, LangGraph, Prowler CLI, and local LLMs.

A user types a request in the terminal → LangGraph orchestrates agents → Prowler scans Azure or AWS → findings are normalized → a Markdown CIS report is generated.

---

## Architecture

```
Terminal Chat
    → LangGraph
    → CIS Agent (interprets request, filters findings)
    → MCP Client → MCP Server → Prowler CLI → Azure / AWS APIs
    → Normalizer
    → Doc Agent (generates narrative)
    → Jinja2 → Markdown Report
```

---

## Prerequisites

Install these before setting up the project.

### 1. Python 3.13

```bash
# macOS
brew install python@3.13
```

### 2. uv (package manager)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 3. Prowler CLI (via Homebrew — do NOT use pip/uv add)

```bash
brew install prowler
prowler --version  # must be 5.26.1 or later
```

> Prowler must be installed as a system tool, not as a Python dependency.
> The MCP Server calls it as a subprocess — `prowler azure ...`

### 4. Ollama + qwen2.5-coder:14b

```bash
# Install Ollama
brew install ollama

# Pull the model
ollama pull qwen2.5-coder:14b

# Start Ollama (keep running in background)
ollama serve
```

### 5. Azure CLI (for real Azure scans — skip for fixture mode)

```bash
brew install azure-cli
az login
az account set --subscription <your-subscription-id>
```

> The signed-in user needs **Reader** role on the target subscription.

### 6. AWS CLI (for real AWS scans — skip for fixture mode)

```bash
brew install awscli
aws configure
```

> Credentials must have at minimum read-only access to the target account.

---

## Setup

```bash
# Clone and enter the project
git clone <repo-url>
cd Poc_MCP

# Install Python dependencies
uv sync
```

---

## Run

### Fixture mode (no cloud account needed)

Uses a pre-captured real scan of 197 Azure CIS findings.

```bash
FIXTURE_MODE=1 uv run python -m backend.app.chat
```

### Production mode (real scan)

```bash
uv run python -m backend.app.chat
```

Example prompts:
```
Run a CIS security audit on Azure subscription 1e11569b-de29-4e51-ad5e-8f7facd3d07f and report only the failed findings
Run a CIS security audit on AWS account 123456789012 and report only the failed findings
```

Reports are saved to `backend/app/artifacts/reports/`.

---

## LLM options

The pipeline uses a single LLM instance built in `backend/app/poc_graph.py`. Two options are available — only one should be active at a time.

### Option A — Local via Ollama (default)

No API key needed. Requires Ollama running with the model pulled.

```python
# poc_graph.py — already active by default
llm = ChatOllama(model="qwen2.5-coder:14b", format="json", temperature=0)
```

### Option B — Claude via Anthropic API

```bash
uv add langchain-anthropic
export ANTHROPIC_API_KEY=sk-ant-...
```

Then in `poc_graph.py`, comment out Option A and uncomment Option B:

```python
# llm = ChatOllama(model="qwen2.5-coder:14b", format="json", temperature=0)
llm = ChatAnthropic(model="claude-sonnet-4-6", temperature=0)
```

---

## Tests

```bash
uv run pytest
# 183 passed
```

---

## Stack

| Layer | Technology |
|-------|-----------|
| Agent orchestration | LangGraph |
| LLM | qwen2.5-coder:14b via Ollama |
| MCP layer | FastMCP (bundled in `mcp>=1.27`) |
| Security scanner | Prowler CLI 5.26.1+ |
| Cloud auth | Azure CLI / AWS CLI |
| Data contracts | Pydantic v2 |
| Reporting | Jinja2 + Markdown |
| Testing | pytest |
| Package manager | uv |

---

## Project structure

```
backend/app/
    chat.py               # terminal entrypoint
    poc_contracts.py      # shared Pydantic models
    poc_graph.py          # LangGraph graph
    agents/               # CIS Agent, Doc Agent
    services/             # MCPClient, ScanService, ReportStorage
    normalizers/          # Prowler OCSF → internal schema
    reporting/            # Jinja2 generator + templates
    artifacts/            # raw/, normalized/, selected/, reports/

MCP_SERVER/
    server_multicloud.py        # FastMCP server — dispatches by provider
    tools/azure/prowler.py      # Azure Prowler execution
    tools/aws/prowler.py        # AWS Prowler execution
    auth/azure_cli_auth.py
    auth/aws_cli_auth.py

tests/
    fixtures/prowler_azure_sample.json  # 197 real Azure CIS findings
    fixtures/prowler_aws_sample.json    # real AWS CIS findings
```

---

## Fixture mode vs production

| | Fixture mode | Production |
|-|-------------|------------|
| Prowler runs | No | Yes |
| Cloud credentials | Not needed | Required |
| LLM (Ollama) | Required | Required |
| Output | Same pipeline, same report | Same pipeline, same report |

The only difference is whether Prowler calls the cloud provider. Everything else — agents, normalizer, reporting — runs identically.
