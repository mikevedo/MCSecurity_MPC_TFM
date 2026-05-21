# MCP Security PoC

This project is a terminal-based Proof of Concept for a cloud security audit system with two distinct flows: a Prowler-based CIS report wizard and a boto3-based AWS chat Q&A with a ReAct agent.

---

# Goal

Allow a user to either:
1. Generate a full CIS compliance report (Azure or AWS) via Prowler CLI through an MCP Server
2. Ask free-form security questions about their AWS accounts answered by a ReAct agent with 6 boto3 domain tools

---

# Current Scope

- Terminal only. No frontend, no database.
- Two flows: report wizard (both providers) and security chat Q&A.
- Azure chat: Prowler via LangGraph (same path as report wizard).
- AWS chat: ReAct agent (Claude) with 6 direct boto3 security analyzers — no Prowler.
- CIS benchmark as the compliance reference.
- Prowler CLI is not executed directly by the user or agents — only through MCP Server tools.
- LangGraph is used for agent orchestration in the report flow.
- Claude claude-sonnet-4-6 (Anthropic API) is the main LLM for the report narrative, intent detection, and ReAct agent.
- Jinja2 is used for report generation.

---

# Two Flows

## Flow 1: Report Wizard

```
Terminal → Wizard (no LLM — direct param collection)
    → LangGraph
    → CIS Agent (interprets request, builds scan + report policy)
    → scan_service.py → mcp_client.py → MCP Server
    → Prowler CLI → Azure / AWS APIs
    → prowler_normalizer.py (OCSF → internal schema)
    → CIS Agent (filters findings)
    → Doc Agent (generates narrative via Claude)
    → Jinja2 → Markdown Report → artifacts/reports/
```

## Flow 2: Security Chat Q&A

```
Terminal → Chat loop
    → Intent detection (account vs. general question)

    AWS:   build_react_agent() → 6 LangChain boto3 tools
                → scan_iam / scan_s3 / scan_ebs / scan_cloudtrail / scan_vpc / scan_ec2
                → Claude decides which tools to call
                → direct text answer

    Azure: LangGraph (same scan path as report wizard)
                → normalized findings → Claude → text answer

    General: Claude with conversation history (no scan)
```

---

# Architecture

```text
backend/app/
│
├── chat.py                    # terminal entrypoint — wizard + chat loop
├── poc_contracts.py           # shared Pydantic models
├── poc_graph.py               # LangGraph graph (report flow)
│
├── agents/
│   ├── cis_agent.py           # interprets scan request, filters findings
│   ├── doc_agent.py           # generates report narrative
│   ├── _llm.py                # shared LLM retry-repair helper
│   ├── react_chat_agent.py    # ReAct agent for AWS chat Q&A
│   └── security_tools.py      # 6 LangChain tools wrapping boto3 analyzers
│
├── services/
│   ├── mcp_client.py          # calls MCP Server tools via MCP protocol
│   ├── scan_service.py        # agent-facing scan facade
│   └── report_storage.py      # saves reports to disk
│
├── normalizers/
│   └── prowler_normalizer.py  # Prowler OCSF → NormalizedFindings
│
├── reporting/
│   ├── generator.py           # Jinja2 renderer
│   └── templates/
│       ├── cis_report.md.j2
│       └── multi_cloud_report.md.j2
│
└── artifacts/
    ├── raw/
    ├── normalized/
    ├── selected/
    └── reports/

MCP_SERVER/
│
├── server_multicloud.py       # FastMCP server — 7 tools registered
│
├── tools/
│   ├── azure/
│   │   └── prowler.py         # runs: prowler azure --compliance ...
│   └── aws/
│       ├── prowler.py         # runs: prowler aws --compliance ...
│       ├── iam.py             # boto3: users, MFA, access keys, root
│       ├── s3.py              # boto3: public buckets, encryption, versioning
│       ├── ebs.py             # boto3: volumes, security groups, snapshots
│       ├── cloudtrail.py      # boto3: trails, CW integration, metric filters
│       ├── vpc.py             # boto3: default VPC, flow logs, subnets
│       └── ec2.py             # boto3: IMDSv2, public IP, monitoring
│
└── auth/
    ├── azure_cli_auth.py
    ├── aws_cli_auth.py
    └── assume_role.py

tests/
├── fixtures/                  # real Prowler scan samples
├── aws/                       # 49 moto-mocked tests for boto3 tools
└── test_*.py                  # report flow tests (normalizer, agents, graph, MCP)
```

---

# Rules

- Prowler CLI must only be invoked through MCP Server tools (`MCP_SERVER/tools/`).
- The terminal chat must not execute Prowler CLI or boto3 directly.
- AWS chat Q&A must go through `react_chat_agent.py` → `security_tools.py` → boto3 tools.
- Azure chat Q&A must go through LangGraph → `scan_service.py` → `mcp_client.py` → MCP Server.
- The report wizard must go through LangGraph → CIS Agent → `scan_service.py`.
- Agents must not invent findings. Reports must be generated only from normalized data.
- The normalizer (`prowler_normalizer.py`) is the only place that transforms Prowler output.
- boto3 tools (`MCP_SERVER/tools/aws/*.py`) return raw dicts; normalizers in `chat.py` convert them to `NormalizedFindings` when needed.
- Prefer small, testable modules. No frontend, database, Docker, or production deployment.

---

# Internal Normalized Schema

```json
{
  "security_findings": [],
  "compliance_checks": [],
  "summary": {}
}
```

---

# Tech Stack

## Core Language
- Python 3.13

## Environment & Dependency Management
- uv

## Agent Orchestration
- LangGraph (report flow)
- LangGraph ReAct (AWS chat Q&A)

## LLM
- Claude claude-sonnet-4-6 via Anthropic API (primary)
- qwen2.5-coder:14b via Ollama (optional alternative for report flow)

## MCP Layer
- MCP (Model Context Protocol)
- FastMCP (MCP Server implementation)

## Security Scanning Engine
- Prowler CLI (report wizard + Azure chat)
- boto3 (AWS chat Q&A)

## Cloud Authentication
- Azure CLI
- AWS CLI / IAM role assumption (assume_role.py)

## Data Validation & Contracts
- Pydantic v2

## Reporting Engine
- Jinja2 + Markdown

## Testing
- pytest
- moto (AWS service mocks for boto3 tools)

---

# AI Stack

```text
Anthropic API
↓
Claude claude-sonnet-4-6
↓
LangChain + LangGraph
↓
ReAct Agent (chat) / CIS + Doc Agents (report)
```
