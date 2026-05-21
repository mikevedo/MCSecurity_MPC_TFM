# MCP Security Audit PoC

Terminal-based cloud security audit system using MCP, LangGraph, Prowler CLI, and Claude (Anthropic API).

Two modes at startup:
- **Report wizard** — step-by-step CIS compliance report via Prowler (Azure + AWS)
- **Security chat** — free-form Q&A about your cloud accounts (AWS via boto3, Azure via Prowler)

---

## Architecture

### Report wizard flow

```
Terminal → Report Wizard (no LLM)
    → LangGraph
    → CIS Agent (builds scan request + report policy)
    → MCP Client → MCP Server → Prowler CLI → Azure / AWS APIs
    → Normalizer (OCSF → internal schema)
    → Doc Agent (generates narrative)
    → Jinja2 → Markdown Report
```

### Chat Q&A flow

```
Terminal → Security Chat
    → Intent detection (account question vs. general)

    AWS:  ReAct Agent (Claude) → 6 boto3 domain tools (IAM, S3, EBS, CloudTrail, VPC, EC2)
                               → direct answer

    Azure: LangGraph → Prowler → Normalizer → Claude → answer
```

---

## Prerequisites

### 1. Python 3.13

```bash
brew install python@3.13
```

### 2. uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 3. Anthropic API key

The chat Q&A and report narrative flows use Claude claude-sonnet-4-6.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

### 4. Prowler CLI (via Homebrew — do NOT use pip/uv add)

Required for report wizard and Azure chat scans. Not used for AWS chat Q&A.

```bash
brew install prowler
prowler --version  # 5.26.1 or later
```

> Prowler is invoked as a subprocess by the MCP Server — never directly.

### 5. Azure CLI (for Azure scans — skip for fixture mode)

```bash
brew install azure-cli
az login
az account set --subscription <your-subscription-id>
```

> The signed-in user needs **Reader** role on the target subscription.

### 6. AWS CLI (for AWS report scans — skip for fixture mode or AWS chat)

```bash
brew install awscli
aws configure
```

> AWS chat Q&A uses boto3 with your current credentials — no Prowler needed.

---

## Setup

```bash
git clone <repo-url>
cd Poc_MCP
uv sync
```

---

## Run

### Fixture mode (no cloud account needed)

Uses a pre-captured real scan of 197 Azure CIS findings.

```bash
FIXTURE_MODE=1 uv run python -m backend.app.chat
```

### Production mode

```bash
uv run python -m backend.app.chat
```

At startup, choose:
- `1` — Report wizard: generates a full CIS Markdown report via Prowler
- `2` — Security chat: ask questions about your AWS or Azure accounts

Example chat questions:
```
¿Tengo buckets S3 públicos?
¿Cuáles son mis instancias EC2 sin IMDSv2?
¿Hay usuarios IAM sin MFA?
¿Mis trails de CloudTrail tienen log validation habilitado?
```

Reports are saved to `backend/app/artifacts/reports/`.

---

## LLM

### Default — Claude via Anthropic API

Used for: report narrative (Doc Agent), report wizard intent, AWS chat Q&A (ReAct agent).

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

The model is `claude-sonnet-4-6`. No local GPU required.

### Alternative — Local via Ollama

For the report wizard and Azure chat scan, you can swap to Ollama in `backend/app/chat.py` and `backend/app/poc_graph.py`:

```python
# chat.py / poc_graph.py
llm = ChatOllama(model="qwen2.5-coder:14b", temperature=0)
```

> The ReAct agent for AWS chat always uses Claude — it requires reliable tool-calling.

---

## Tests

```bash
uv run pytest
# 249 passed
```

---

## Stack

| Layer | Technology |
|-------|-----------|
| Agent orchestration | LangGraph |
| LLM | Claude claude-sonnet-4-6 (Anthropic API) |
| AWS chat tools | boto3 — direct API calls per domain |
| MCP layer | FastMCP (`mcp>=1.27`) |
| Security scanner | Prowler CLI 5.26.1+ |
| Cloud auth | Azure CLI / AWS CLI / IAM role assume |
| Data contracts | Pydantic v2 |
| Reporting | Jinja2 + Markdown |
| Testing | pytest + moto (AWS mocks) |
| Package manager | uv |

---

## Project structure

```
backend/app/
    chat.py                    # terminal entrypoint — wizard + chat loop
    poc_contracts.py           # shared Pydantic models
    poc_graph.py               # LangGraph graph (report flow)
    agents/
        cis_agent.py           # interprets scan request, filters findings
        doc_agent.py           # generates report narrative
        _llm.py                # shared LLM retry-repair helper
        react_chat_agent.py    # ReAct agent for AWS chat Q&A
        security_tools.py      # 6 LangChain tools wrapping boto3 analyzers
    services/
        mcp_client.py          # calls MCP Server tools
        scan_service.py        # agent-facing scan facade
        report_storage.py      # saves reports to disk
    normalizers/
        prowler_normalizer.py  # Prowler OCSF → internal schema
    reporting/
        generator.py           # Jinja2 renderer
        templates/
            cis_report.md.j2
            multi_cloud_report.md.j2
    artifacts/                 # raw/, normalized/, selected/, reports/

MCP_SERVER/
    server_multicloud.py       # FastMCP server — 7 tools registered
    tools/
        azure/prowler.py       # Azure Prowler execution
        aws/prowler.py         # AWS Prowler execution
        aws/iam.py             # IAM boto3 analyzer
        aws/s3.py              # S3 boto3 analyzer
        aws/ebs.py             # EBS + Security Groups boto3 analyzer
        aws/cloudtrail.py      # CloudTrail boto3 analyzer
        aws/vpc.py             # VPC boto3 analyzer
        aws/ec2.py             # EC2 boto3 analyzer
    auth/
        azure_cli_auth.py
        aws_cli_auth.py
        assume_role.py

tests/
    fixtures/                  # real Prowler scan samples (Azure + AWS)
    aws/                       # 49 moto-mocked tests for boto3 tools
    test_*.py                  # report flow tests
```

---

## Fixture mode vs production

| | Fixture mode | Production |
|-|-------------|------------|
| Prowler runs | No | Yes (report wizard + Azure chat) |
| Cloud credentials | Not needed | Required |
| AWS chat (boto3) | Uses real credentials if set | Uses real credentials |
| LLM | Required (Claude API) | Required (Claude API) |
