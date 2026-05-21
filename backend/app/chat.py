"""
chat.py — Terminal entrypoint for the MCP Security Audit PoC.

Usage:
    uv run python -m backend.app.chat

Fixture mode (no real cloud account needed):
    FIXTURE_MODE=1 uv run python -m backend.app.chat

Two modes available at startup:
  1. Report wizard  — step-by-step collection of scan params, no LLM involved
  2. Security chat  — free-form Q&A with conversation history and lazy account context

Chat behavior:
  - Conversation history is kept across turns (LLM remembers the session)
  - Account context is asked lazily — only when the first account question arrives
  - Once set, the account is reused for all account questions in the session
  - Intent is auto-detected: 'account' vs 'general'

Rules:
- MUST NOT call Prowler CLI or import subprocess directly
- Wizard builds ScanRequest + ReportPolicy directly (no LLM for config)
- LLM only used in chat mode and for report narrative generation
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_anthropic import ChatAnthropic
from backend.app.agents.react_chat_agent import ask_react_agent, build_react_agent

from backend.app.poc_contracts import (
    Benchmark,
    ComplianceCheck,
    FilterCriteria,
    FindingStatus,
    NormalizedFindings,
    Provider,
    ReportPolicy,
    ScanRequest,
    ScanSummary,
    SecurityFinding,
    Severity,
)
from backend.app.poc_graph import build_graph
from backend.app.reporting.generator import render_multicloud
from backend.app.services.report_storage import ReportStorage

# ---------------------------------------------------------------------------
# Domain → Prowler services mapping
# ---------------------------------------------------------------------------

_AWS_DOMAINS: dict[str, tuple[str, list[str]]] = {
    "1": ("Identity & Access Management", ["iam"]),
    "2": ("Storage",                       ["s3"]),
    "3": ("Logging",                        ["cloudtrail"]),
    "4": ("Monitoring",                     ["cloudwatch", "guardduty"]),
    "5": ("Networking",                     ["vpc", "ec2"]),
}

_AZURE_DOMAINS: dict[str, tuple[str, list[str]]] = {
    "1": ("Identity & Access Management", ["iam"]),
    "2": ("Microsoft Defender",           ["defender"]),
    "3": ("Storage Accounts",             ["storage"]),
    "4": ("Database Services",            ["sql", "postgresql", "mysql"]),
    "5": ("Logging & Monitoring",         ["monitor"]),
    "6": ("Networking",                   ["network"]),
    "7": ("Virtual Machines",             ["vm"]),
    "8": ("Key Vault",                    ["keyvault"]),
    "9": ("App Service",                  ["appservice"]),
}

_AWS_BENCHMARKS: dict[str, tuple[str, Benchmark]] = {
    "1": ("CIS AWS v3.0",     Benchmark.CIS_3_0_AWS),
    "2": ("CIS AWS v4.0",     Benchmark.CIS_4_0_AWS),
    "3": ("CIS AWS v5.0",     Benchmark.CIS_5_0_AWS),
    "4": ("CIS AWS v6.0",     Benchmark.CIS_6_0_AWS),
    "5": ("PCI DSS v4.0",     Benchmark.PCI_4_0_AWS),
    "6": ("SOC 2",            Benchmark.SOC2_AWS),
    "7": ("HIPAA",            Benchmark.HIPAA_AWS),
    "8": ("ISO 27001:2022",   Benchmark.ISO27001_2022_AWS),
    "9": ("NIST 800-53 Rev5", Benchmark.NIST_800_53_R5_AWS),
}

_AZURE_BENCHMARKS: dict[str, tuple[str, Benchmark]] = {
    "1": ("CIS Azure v2.0",   Benchmark.CIS_2_0_AZURE),
    "2": ("CIS Azure v2.1",   Benchmark.CIS_2_1_AZURE),
    "3": ("CIS Azure v3.0",   Benchmark.CIS_3_0_AZURE),
    "4": ("CIS Azure v4.0",   Benchmark.CIS_4_0_AZURE),
    "5": ("CIS Azure v5.0",   Benchmark.CIS_5_0_AZURE),
    "6": ("PCI DSS v4.0",     Benchmark.PCI_4_0_AZURE),
    "7": ("SOC 2",            Benchmark.SOC2_AZURE),
    "8": ("HIPAA",            Benchmark.HIPAA_AZURE),
    "9": ("ISO 27001:2022",   Benchmark.ISO27001_2022_AZURE),
    "a": ("NIS2",             Benchmark.NIS2_AZURE),
    "b": ("MITRE ATT&CK",     Benchmark.MITRE_ATTACK_AZURE),
}

# Framework detection map — used by LLM in chat to auto-select compliance benchmark
_AZURE_FRAMEWORK_MAP: dict[str, Benchmark] = {
    "pci_4.0_azure":        Benchmark.PCI_4_0_AZURE,
    "soc2_azure":           Benchmark.SOC2_AZURE,
    "hipaa_azure":          Benchmark.HIPAA_AZURE,
    "iso27001_2022_azure":  Benchmark.ISO27001_2022_AZURE,
    "nis2_azure":           Benchmark.NIS2_AZURE,
    "mitre_attack_azure":   Benchmark.MITRE_ATTACK_AZURE,
    "cis_2.0_azure":        Benchmark.CIS_2_0_AZURE,
    "cis_2.1_azure":        Benchmark.CIS_2_1_AZURE,
    "cis_3.0_azure":        Benchmark.CIS_3_0_AZURE,
    "cis_4.0_azure":        Benchmark.CIS_4_0_AZURE,
    "cis_5.0_azure":        Benchmark.CIS_5_0_AZURE,
}

_AWS_FRAMEWORK_MAP: dict[str, Benchmark] = {
    "pci_4.0_aws":                  Benchmark.PCI_4_0_AWS,
    "soc2_aws":                     Benchmark.SOC2_AWS,
    "hipaa_aws":                    Benchmark.HIPAA_AWS,
    "iso27001_2022_aws":            Benchmark.ISO27001_2022_AWS,
    "nis2_aws":                     Benchmark.NIS2_AWS,
    "nist_800_53_revision_5_aws":   Benchmark.NIST_800_53_R5_AWS,
    "cis_3.0_aws":                  Benchmark.CIS_3_0_AWS,
    "cis_4.0_aws":                  Benchmark.CIS_4_0_AWS,
    "cis_5.0_aws":                  Benchmark.CIS_5_0_AWS,
    "cis_6.0_aws":                  Benchmark.CIS_6_0_AWS,
}

_AWS_ALL_SERVICES = ["iam", "s3", "cloudtrail", "cloudwatch", "guardduty", "vpc", "ec2"]
_AZURE_ALL_SERVICES = ["iam", "storage", "monitor", "network", "vm", "keyvault", "appservice", "defender", "sql"]

# Closed set of boto3-backed AWS domain keys for direct dispatch (no Prowler)
_AWS_DOMAIN_KEYS = ["iam", "s3", "ebs", "cloudtrail", "vpc", "ec2"]

_SEVERITY_OPTIONS: dict[str, tuple[str, list[str]]] = {
    "1": ("Solo críticos",          ["critical"]),
    "2": ("Críticos y altos",       ["critical", "high"]),
    "3": ("Críticos, altos y medios", ["critical", "high", "medium"]),
    "4": ("Todos los niveles",      []),
}

_BANNER = """
╔══════════════════════════════════════════════════════════╗
║        Cloud Security Audit — MCP Security PoC          ║
║  Powered by Prowler + MCP + LangGraph + qwen2.5-coder   ║
╚══════════════════════════════════════════════════════════╝"""

_FIXTURE_NOTICE = "[FIXTURE MODE ACTIVE] Using local fixture — no real cloud calls."

_SECURITY_SYSTEM_PROMPT = (
    "You are a cloud security expert specializing in CIS benchmarks, AWS, and Azure. "
    "Answer questions clearly and concisely. Focus on practical security guidance. "
    "When explaining findings or controls, include the risk and remediation steps."
)

_HISTORY_LIMIT = 20  # max messages kept in history (10 exchanges)


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def _prompt(msg: str) -> str:
    try:
        return input(f"\n{msg}").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nGoodbye.")
        sys.exit(0)


def _pick(options: dict[str, tuple], label: str) -> str:
    print(f"\n{label}")
    for key, value in options.items():
        name = value[0] if isinstance(value, tuple) else value
        print(f"  {key}. {name}")
    while True:
        choice = _prompt("> ")
        if choice in options:
            return choice
        print(f"  Opción inválida. Elegí entre: {', '.join(options.keys())}")


def _pick_multi(options: dict[str, tuple], label: str, all_key: str = "0") -> list[str]:
    print(f"\n{label}")
    for key, value in options.items():
        name = value[0] if isinstance(value, tuple) else value
        print(f"  {key}. {name}")
    print(f"  {all_key}. Todos")
    while True:
        raw = _prompt("> ")
        if raw == all_key:
            return list(options.keys())
        parts = [p.strip() for p in raw.replace(",", " ").split()]
        if parts and all(p in options for p in parts):
            return parts
        print("  Ingresá números válidos separados por coma, ej: 1, 3")


# ---------------------------------------------------------------------------
# LLM helpers
# ---------------------------------------------------------------------------

def _classify_question(llm_json: Any, question: str) -> str:
    """Classify question as 'account' or 'general'. Returns 'general' on failure."""
    prompt = (
        f"Classify this security question. Return ONLY valid JSON.\n\n"
        f"Question: {question!r}\n\n"
        f"If the question is about the user's specific cloud account, resources, "
        f"findings, or compliance status → {{\"type\": \"account\"}}\n"
        f"If it's general security knowledge → {{\"type\": \"general\"}}\n\n"
        f"Examples:\n"
        f"  '¿qué es el MFA?' → {{\"type\": \"general\"}}\n"
        f"  '¿cómo está mi IAM?' → {{\"type\": \"account\"}}\n"
        f"  '¿tengo buckets S3 públicos?' → {{\"type\": \"account\"}}\n"
        f"  '¿por qué rotar las claves?' → {{\"type\": \"general\"}}\n"
    )
    try:
        response = llm_json.invoke([HumanMessage(content=prompt)])
        return json.loads(response.content).get("type", "general")
    except Exception:  # noqa: BLE001
        return "general"


def _extract_checks(llm_json: Any, question: str, provider: Provider) -> list[str]:
    """
    Map a question to specific Prowler check IDs.
    Returns check IDs if confident, empty list if uncertain.
    Using specific checks makes scans run in seconds instead of minutes.
    """
    prompt = (
        f"Map this security question to specific Prowler check IDs. Return ONLY valid JSON.\n\n"
        f"Question: {question!r}\n"
        f"Provider: {provider.value}\n\n"
        f"Return specific Prowler check IDs that directly answer this question.\n"
        f"Only return checks you are highly confident about. If unsure, return [].\n\n"
        f"Examples (aws):\n"
        f"  '¿MFA en root?' → {{\"checks\": [\"iam_root_hardware_mfa_enabled\", \"iam_root_mfa_enabled\"]}}\n"
        f"  '¿access keys sin rotar?' → {{\"checks\": [\"iam_user_accesskey_unused\", \"iam_user_accesskey_age_over_90_days\"]}}\n"
        f"  '¿S3 público?' → {{\"checks\": [\"s3_bucket_public_access\", \"s3_bucket_policy_public_write_access\"]}}\n"
        f"  '¿cloudtrail habilitado?' → {{\"checks\": [\"cloudtrail_multi_region_enabled\"]}}\n"
        f"  'algo genérico o amplio' → {{\"checks\": []}}\n\n"
        f"Return: {{\"checks\": [...]}}\n"
    )
    try:
        response = llm_json.invoke([HumanMessage(content=prompt)])
        return json.loads(response.content).get("checks", [])
    except Exception:  # noqa: BLE001
        return []


def _extract_services(llm_json: Any, question: str, provider: Provider) -> list[str]:
    """Extract relevant Prowler services from a question. Returns [] if unclear."""
    options = ", ".join(
        _AWS_ALL_SERVICES if provider == Provider.AWS else _AZURE_ALL_SERVICES
    )
    prompt = (
        f"Extract the cloud security domain from this question. Return ONLY valid JSON.\n\n"
        f"Question: {question!r}\n"
        f"Provider: {provider.value}\n\n"
        f"Choose from: {options}\n"
        f"Return: {{\"services\": [\"iam\"]}}\n"
        f"If unclear, return: {{\"services\": []}}\n"
    )
    try:
        response = llm_json.invoke([HumanMessage(content=prompt)])
        return json.loads(response.content).get("services", [])
    except Exception:  # noqa: BLE001
        return []


def _extract_azure_scope(
    llm_json: Any,
    question: str,
) -> tuple[Optional[str], Optional[str]]:
    """
    Detect Azure resource group and/or region from a question.
    Returns (resource_group, azure_region) — either can be None.
    """
    prompt = (
        f"Extract Azure resource group and region from this question. Return ONLY valid JSON.\n\n"
        f"Question: {question!r}\n\n"
        f"If the question mentions a resource group name → extract it.\n"
        f"If the question mentions an Azure region (e.g. westeurope, eastus, northeurope) → extract it.\n"
        f"If nothing is mentioned → return null for both.\n\n"
        f"Examples:\n"
        f"  '¿cómo están los recursos del grupo prod?' → {{\"resource_group\": \"prod\", \"region\": null}}\n"
        f"  '¿qué falla en westeurope?' → {{\"resource_group\": null, \"region\": \"westeurope\"}}\n"
        f"  '¿cómo está mi IAM?' → {{\"resource_group\": null, \"region\": null}}\n\n"
        f"Return: {{\"resource_group\": \"<name>\" | null, \"region\": \"<region>\" | null}}\n"
    )
    try:
        response = llm_json.invoke([HumanMessage(content=prompt)])
        data = json.loads(response.content)
        return data.get("resource_group"), data.get("region")
    except Exception:  # noqa: BLE001
        return None, None


def _extract_aws_region(llm_json: Any, question: str) -> Optional[str]:
    """Detect an AWS region mentioned in the question. Returns region string or None."""
    prompt = (
        f"Extract an AWS region from this question. Return ONLY valid JSON.\n\n"
        f"Question: {question!r}\n\n"
        f"If a region is mentioned (e.g. us-east-1, eu-west-1, ap-southeast-2) → extract it.\n"
        f"If no region is mentioned → return null.\n\n"
        f"Return: {{\"region\": \"<region>\" | null}}\n"
    )
    try:
        response = llm_json.invoke([HumanMessage(content=prompt)])
        return json.loads(response.content).get("region")
    except Exception:  # noqa: BLE001
        return None


def _extract_excluded_checks(
    llm_json: Any, question: str, provider: Provider
) -> list[str]:
    """Detect check IDs to exclude from a question. Returns list or []."""
    prompt = (
        f"Extract Prowler check IDs to EXCLUDE from this question. Return ONLY valid JSON.\n\n"
        f"Question: {question!r}\n"
        f"Provider: {provider.value}\n\n"
        f"Only extract exclusions if the user explicitly says to skip, ignore, or exclude something.\n"
        f"Return check IDs to exclude, or [] if none.\n\n"
        f"Examples:\n"
        f"  'todo menos cloudtrail' → {{\"excluded\": [\"cloudtrail_multi_region_enabled\"]}}\n"
        f"  '¿cómo está mi IAM?' → {{\"excluded\": []}}\n\n"
        f"Return: {{\"excluded\": [...]}}\n"
    )
    try:
        response = llm_json.invoke([HumanMessage(content=prompt)])
        return json.loads(response.content).get("excluded", [])
    except Exception:  # noqa: BLE001
        return []


def _extract_severity(llm_json: Any, question: str) -> list[str]:
    """Detect severity filter from a question. Returns list or default ['critical', 'high']."""
    prompt = (
        f"Detect the severity level requested in this security question. Return ONLY valid JSON.\n\n"
        f"Question: {question!r}\n\n"
        f"Severity levels: critical, high, medium, low, informational\n\n"
        f"Rules:\n"
        f"- If the user mentions a specific severity → return that level AND all higher ones\n"
        f"- 'medium' → ['critical', 'high', 'medium']\n"
        f"- 'low' → ['critical', 'high', 'medium', 'low']\n"
        f"- 'critical only' → ['critical']\n"
        f"- If no severity mentioned → return []\n\n"
        f"Examples:\n"
        f"  '¿tengo problemas medios?' → {{\"severity\": [\"critical\", \"high\", \"medium\"]}}\n"
        f"  '¿algo crítico en IAM?' → {{\"severity\": [\"critical\"]}}\n"
        f"  '¿cómo está mi S3?' → {{\"severity\": []}}\n\n"
        f"Return: {{\"severity\": [...]}}\n"
    )
    try:
        response = llm_json.invoke([HumanMessage(content=prompt)])
        result = json.loads(response.content).get("severity", [])
        return result if result else ["critical", "high"]
    except Exception:  # noqa: BLE001
        return ["critical", "high"]


def _extract_category(llm_json: Any, question: str, provider: Provider) -> list[str]:
    """Detect Prowler check categories from a question. Returns list or []."""
    prompt = (
        f"Map this security question to Prowler check categories. Return ONLY valid JSON.\n\n"
        f"Question: {question!r}\n"
        f"Provider: {provider.value}\n\n"
        f"Common Prowler categories: software_and_configuration_checks, encryption, "
        f"infrastructure_security, logging, runtime_behavior_analysis.\n"
        f"Return matching categories or [] if generic.\n\n"
        f"Return: {{\"categories\": [...]}}\n"
    )
    try:
        response = llm_json.invoke([HumanMessage(content=prompt)])
        return json.loads(response.content).get("categories", [])
    except Exception:  # noqa: BLE001
        return []


def _extract_aws_domain(llm_json: Any, question: str) -> Optional[str]:
    """
    Map an AWS chat question to ONE domain key from _AWS_DOMAIN_KEYS, or None.

    Single-domain dispatch: chat answers one domain at a time. If the user asks
    about two domains in one breath, return None and let the caller fall through.

    Returns a string from _AWS_DOMAIN_KEYS or None. Never raises.
    """
    prompt = (
        f"Map this cloud security question to one AWS domain. Return ONLY valid JSON.\n\n"
        f"Question: {question!r}\n\n"
        f"Domains:\n"
        f"- \"iam\"        → users, MFA, access keys, roles, root account, permissions\n"
        f"- \"s3\"         → buckets, objects, storage, files, public access\n"
        f"- \"ebs\"        → volumes, snapshots, disks, security groups, firewall rules, ports\n"
        f"- \"cloudtrail\" → audit logs, API calls, trail, logging, metric filters, alarms\n"
        f"- \"vpc\"        → network, VPC, subnets, flow logs, default VPC, routing\n"
        f"- \"ec2\"        → instances, servers, virtual machines, IMDSv2, compute, monitoring\n\n"
        f"If the question clearly maps to one domain → return that domain.\n"
        f"If ambiguous or general → return null.\n\n"
        f"Return: {{\"domain\": \"<domain>\" | null}}\n"
    )
    try:
        response = llm_json.invoke([HumanMessage(content=prompt)])
        value = json.loads(response.content).get("domain")
        if value in _AWS_DOMAIN_KEYS:
            return value
        return None
    except Exception:  # noqa: BLE001
        return None


def _detect_framework(
    llm_json: Any,
    question: str,
    provider: Provider,
) -> Optional[Benchmark]:
    """
    Detect if the question mentions a specific compliance framework.
    Returns the matching Benchmark enum value, or None if CIS/unknown.
    """
    framework_map = _AWS_FRAMEWORK_MAP if provider == Provider.AWS else _AZURE_FRAMEWORK_MAP
    options = ", ".join(framework_map.keys())
    prompt = (
        f"Detect if this question references a specific compliance framework. Return ONLY valid JSON.\n\n"
        f"Question: {question!r}\n"
        f"Provider: {provider.value}\n\n"
        f"Available compliance IDs: {options}\n\n"
        f"If the question mentions PCI, SOC2, HIPAA, ISO 27001, NIS2, MITRE, NIST, or a specific CIS version → "
        f"return the matching compliance ID.\n"
        f"If the question is generic or only says 'CIS' without a version → return null.\n\n"
        f"Examples:\n"
        f"  '¿cómo estoy en PCI?' → {{\"framework\": \"pci_4.0_{provider.value}\"}}\n"
        f"  '¿cumplimos HIPAA?' → {{\"framework\": \"hipaa_{provider.value}\"}}\n"
        f"  '¿cómo está mi IAM?' → {{\"framework\": null}}\n"
        f"  '¿CIS v5?' → {{\"framework\": \"cis_5.0_{provider.value}\"}}\n\n"
        f"Return: {{\"framework\": \"<id>\" | null}}\n"
    )
    try:
        response = llm_json.invoke([HumanMessage(content=prompt)])
        raw = json.loads(response.content).get("framework")
        if raw and raw in framework_map:
            return framework_map[raw]
    except Exception:  # noqa: BLE001
        pass
    return None


def _findings_to_context(normalized: NormalizedFindings) -> str:
    """Convert NormalizedFindings to a concise LLM-readable context string."""
    s = normalized.summary
    lines = [
        f"Account: {s.cloud_account_id}",
        f"Provider: {s.provider.value.upper()}",
        f"Benchmark: {s.benchmark.value}",
        f"Scan results: {s.total} total — {s.failed} failed, {s.passed} passed",
        "",
        "Failed findings:",
    ]
    failed = [f for f in normalized.security_findings if f.status.value == "FAIL"]
    for f in failed[:40]:
        lines.append(
            f"  [{f.severity.value}] {f.check_id}: {f.title} | Resource: {f.resource_id}"
        )
    if len(failed) > 40:
        lines.append(f"  ... and {len(failed) - 40} more failed findings.")
    return "\n".join(lines)


def _invoke_with_history(
    llm: Any,
    system: SystemMessage,
    history: list[BaseMessage],
    question: str,
) -> str:
    """Call LLM with full conversation history. Returns response text."""
    messages = [system] + history[-_HISTORY_LIMIT:] + [HumanMessage(content=question)]
    response = llm.invoke(messages)
    return response.content


# ---------------------------------------------------------------------------
# Mutelist management
# ---------------------------------------------------------------------------

_MUTELIST_DIR = Path("backend/app/artifacts/mutelist")


def _detect_aws_account_id() -> str:
    """Auto-detect AWS account ID via STS. Returns empty string on failure."""
    import subprocess
    try:
        result = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        account_id = result.stdout.strip()
        return account_id if account_id and result.returncode == 0 else ""
    except Exception:  # noqa: BLE001
        return ""


def _detect_azure_subscription_id() -> str:
    """Auto-detect active Azure subscription ID via CLI. Returns empty string on failure."""
    import subprocess
    try:
        result = subprocess.run(
            ["az", "account", "show", "--query", "id", "--output", "tsv"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        sub_id = result.stdout.strip()
        return sub_id if sub_id and result.returncode == 0 else ""
    except Exception:  # noqa: BLE001
        return ""


def _mutelist_path(account_id: str) -> Path:
    return _MUTELIST_DIR / f"{account_id}.yaml"


def _load_mutelist(path: Path) -> dict:
    if path.exists():
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {"Mutelist": {"Accounts": {"*": {"Checks": {}}}}}
    return {"Mutelist": {"Accounts": {"*": {"Checks": {}}}}}


def _append_to_mutelist(path: Path, check_ids: list[str], justification: str) -> None:
    data = _load_mutelist(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    checks = data.setdefault("Mutelist", {}).setdefault("Accounts", {}).setdefault("*", {}).setdefault("Checks", {})
    for check_id in check_ids:
        checks[check_id] = {"Regions": ["*"], "Resources": ["*"]}
    with open(path, "w", encoding="utf-8") as fh:
        yaml.dump(data, fh, default_flow_style=False, allow_unicode=True)


def _post_report_mute_prompt(normalized: Optional[NormalizedFindings], account_id: str) -> None:
    """After report generation, offer to suppress findings via mutelist."""
    if normalized is None:
        return

    failed = [f for f in normalized.security_findings if f.status.value == "FAIL"]
    if not failed:
        return

    answer = _prompt("¿Querés suprimir algún finding del próximo scan? (s/n)\n> ").lower()
    if answer not in ("s", "si", "sí", "y", "yes"):
        return

    print("\n  Findings fallidos:")
    for i, f in enumerate(failed[:50], 1):
        print(f"    {i:2}. [{f.severity.value}] {f.check_id} — {f.title}")
    if len(failed) > 50:
        print(f"    ... y {len(failed) - 50} más.")

    raw = _prompt("Ingresá los números a suprimir (separados por coma)\n> ")
    selected_indices = []
    for part in raw.replace(",", " ").split():
        if part.isdigit() and 1 <= int(part) <= len(failed[:50]):
            selected_indices.append(int(part) - 1)

    if not selected_indices:
        print("  Ningún finding seleccionado.")
        return

    check_ids = [failed[i].check_id for i in selected_indices]
    print(f"\n  Checks a suprimir: {', '.join(check_ids)}")
    justification = _prompt("¿Justificación? (ej: no aplica, ya mitigado)\n> ")
    if not justification:
        justification = "Suprimido manualmente"

    path = _mutelist_path(account_id)
    _append_to_mutelist(path, check_ids, justification)
    print(f"  Mutelist actualizado: {path}")
    print("  Se aplicará automáticamente en el próximo scan de esta cuenta.")


# ---------------------------------------------------------------------------
# Account context helpers
# ---------------------------------------------------------------------------

def _ask_account_context() -> dict:
    """Ask the user for provider + account ID + scan preferences. Returns a context dict."""
    print("\n  Necesito saber sobre qué cuenta querés preguntar.")
    provider_key = _pick({"1": ("Azure",), "2": ("AWS",)}, "¿Provider?")
    provider = Provider.AZURE if provider_key == "1" else Provider.AWS

    account_id = _prompt(
        "¿Subscription ID?\n> " if provider == Provider.AZURE else "¿Account ID?\n> "
    )
    if not account_id:
        account_id = "unknown-account"

    if provider == Provider.AZURE:
        tenant_id = _prompt("¿Tenant ID? (Enter para usar el del CLI)\n> ")
        role_arn = ""
    else:
        tenant_id = ""
        raw_role = _prompt("¿Role ARN a asumir? (Enter para usar credenciales del entorno)\n> ")
        role_arn = raw_role if raw_role else ""

    print(f"\n  Contexto fijado: {provider.value.upper()} — {account_id}")
    return {
        "provider": provider,
        "account_id": account_id,
        "tenant_id": tenant_id,
        "role_arn": role_arn,
    }


def _account_matches(normalized: Optional[NormalizedFindings], account_id: str) -> bool:
    """Check if the last normalized findings are for the given account."""
    if normalized is None:
        return False
    return normalized.summary.cloud_account_id == account_id


# ---------------------------------------------------------------------------
# Wizard — multi-cloud
# ---------------------------------------------------------------------------

def _run_multicloud_wizard(fixture_mode: bool, graph) -> None:
    """Collect N account configs, run scans sequentially, generate unified report."""
    print("\n  Modo multi-cloud. Vas a configurar cada cuenta a escanear.\n")

    configs: list[dict] = []

    while True:
        print(f"\n  --- Cuenta #{len(configs) + 1} ---")
        config = _collect_account_config(fixture_mode)
        if config:
            configs.append(config)
            print(f"  Cuenta agregada: {config['provider'].value.upper()} — {config['account_id']}")

        add_more = _prompt("¿Agregar otra cuenta? (s/n)\n> ").lower()
        if add_more not in ("s", "si", "sí", "y", "yes"):
            break

    if not configs:
        print("  Cancelado — no se configuraron cuentas.")
        return

    print(f"\n  Resumen: {len(configs)} cuenta(s) a escanear")
    for i, c in enumerate(configs, 1):
        print(f"    {i}. {c['provider'].value.upper()} — {c['account_id']} — {', '.join(c['domain_names'])}")

    confirm = _prompt("\n¿Confirmás? (s/n)\n> ").lower()
    if confirm not in ("s", "si", "sí", "y", "yes"):
        print("  Cancelado.")
        return

    findings_list: list[NormalizedFindings] = []
    policies_list: list[ReportPolicy] = []

    for config in configs:
        print(f"\n  Escaneando {config['provider'].value.upper()} — {config['account_id']}...")
        try:
            result = asyncio.run(graph.ainvoke({
                "scan_request": config["scan_request"],
                "report_policy": config["report_policy"],
            }))
        except Exception as exc:  # noqa: BLE001
            print(f"  Error: {exc} — saltando esta cuenta.")
            continue

        if result.get("error"):
            print(f"  Scan fallido: {result['error']} — saltando esta cuenta.")
            continue

        nf = result.get("filtered_findings") or result.get("filtered")
        if nf:
            findings_list.append(nf)
            policies_list.append(config["report_policy"])
            print(f"  OK — {nf.summary.total} findings ({nf.summary.failed} fallidos)")

    if not findings_list:
        print("\n  No se obtuvieron findings de ninguna cuenta.")
        return

    print("\n  Generando reporte unificado...")
    try:
        content = render_multicloud(findings_list, policies_list)
        scan_id = str(uuid.uuid4())[:8]
        storage = ReportStorage()
        report_path = storage.save_report(f"multicloud_{scan_id}", content)
        print(f"\n  Reporte multi-cloud generado: {report_path}")
    except Exception as exc:  # noqa: BLE001
        print(f"  Error al generar el reporte: {exc}")


# ---------------------------------------------------------------------------
# IAM direct tool (boto3, no Prowler)
# ---------------------------------------------------------------------------

def _call_iam_tool_direct(role_arn: Optional[str] = None) -> dict:
    """Invoke scan_iam_security_aws via MCPClient. Returns raw tool dict."""
    from backend.app.services.mcp_client import MCPClient
    args: dict = {}
    if role_arn:
        args["role_arn"] = role_arn
    return asyncio.run(MCPClient().call_tool("scan_iam_security_aws", args))


def _iam_result_to_normalized(
    result: dict,
    account_id: str,
    provider: Provider,
    benchmark: Benchmark,
) -> Optional[NormalizedFindings]:
    """Convert scan_iam_security_aws output to NormalizedFindings."""
    if not result.get("success"):
        return None

    now_iso = datetime.now(tz=timezone.utc).isoformat()
    findings: list[SecurityFinding] = []

    for item in result.get("users_without_mfa", []):
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="iam_user_mfa_disabled",
            title="IAM user without MFA",
            severity=Severity.HIGH,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:iam::{account_id}:user/{item['user_name']}",
            resource_type="AWS::IAM::User",
            region="global",
            cloud_account_id=account_id,
            description="IAM user does not have MFA enabled.",
            risk="Compromised credentials provide full account access without MFA.",
            remediation=item.get("recommendation", "Enable MFA for this user."),
            compliance={"CIS": ["1.10"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    for item in result.get("old_access_keys", []):
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="iam_user_accesskey_age_over_90_days",
            title="IAM access key not rotated",
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:iam::{account_id}:user/{item['user_name']}",
            resource_type="AWS::IAM::AccessKey",
            region="global",
            cloud_account_id=account_id,
            description=f"Access key {item['access_key_id']} is {item['age_days']} days old.",
            risk="Old access keys increase the risk of credential compromise.",
            remediation=item.get("recommendation", "Rotate this access key."),
            compliance={"CIS": ["1.14"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    for item in result.get("root_account_issues", []):
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="iam_root_mfa_enabled" if "MFA" in item["issue"] else "iam_root_access_key_exists",
            title=item["issue"],
            severity=Severity.CRITICAL,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:iam::{account_id}:root",
            resource_type="AWS::IAM::Root",
            region="global",
            cloud_account_id=account_id,
            description=item["issue"],
            risk="Root account issues represent the highest security risk.",
            remediation=item.get("recommendation", "Fix root account security."),
            compliance={"CIS": ["1.5"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    for item in result.get("inactive_users", []):
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="iam_user_console_access_unused",
            title="IAM user console access unused",
            severity=Severity.LOW,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:iam::{account_id}:user/{item['user_name']}",
            resource_type="AWS::IAM::User",
            region="global",
            cloud_account_id=account_id,
            description=f"User has not used console for {item['days_inactive']} days.",
            risk="Inactive users with console access are an unnecessary attack surface.",
            remediation=item.get("recommendation", "Disable or remove this user."),
            compliance={"CIS": ["1.12"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    total = len(findings)
    severity_breakdown = {}
    for f in findings:
        severity_breakdown[f.severity.value] = severity_breakdown.get(f.severity.value, 0) + 1

    summary = ScanSummary(
        provider=provider,
        benchmark=benchmark,
        cloud_account_id=account_id,
        started_at=now_iso,
        finished_at=now_iso,
        total=total,
        passed=0,
        failed=total,
        manual=0,
        severity_breakdown=severity_breakdown,
        fixture_mode=False,
    )
    return NormalizedFindings(
        security_findings=findings,
        compliance_checks=[],
        summary=summary,
    )


# ---------------------------------------------------------------------------
# S3 direct tool normalizer (boto3, no Prowler)
# ---------------------------------------------------------------------------

def _s3_result_to_normalized(
    result: dict,
    account_id: str,
    provider: Provider,
    benchmark: Benchmark,
) -> Optional[NormalizedFindings]:
    """Convert scan_s3_security_aws output to NormalizedFindings."""
    if not result.get("success"):
        return None

    now_iso = datetime.now(tz=timezone.utc).isoformat()
    findings: list[SecurityFinding] = []

    for item in result.get("public_buckets", []):
        bucket_name = item["bucket_name"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="s3_bucket_public_access",
            title="S3 bucket allows public access",
            severity=Severity.HIGH,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:s3:::{bucket_name}",
            resource_type="AWS::S3::Bucket",
            region="global",
            cloud_account_id=account_id,
            description=f"Bucket {bucket_name} is publicly accessible.",
            risk="Publicly accessible buckets can leak sensitive data.",
            remediation=item.get("recommendation", "Enable S3 Block Public Access for this bucket."),
            compliance={"CIS": ["2.1.5"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    for item in result.get("unencrypted_buckets", []):
        bucket_name = item["bucket_name"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="s3_bucket_default_encryption_disabled",
            title="S3 bucket without default encryption",
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:s3:::{bucket_name}",
            resource_type="AWS::S3::Bucket",
            region="global",
            cloud_account_id=account_id,
            description=f"Bucket {bucket_name} does not enforce SSE.",
            risk="Unencrypted objects at rest violate CIS encryption baseline.",
            remediation=item.get("recommendation", "Enable default SSE-S3 or SSE-KMS encryption."),
            compliance={"CIS": ["2.1.1"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    for item in result.get("buckets_without_versioning", []):
        bucket_name = item["bucket_name"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="s3_bucket_no_mfa_delete",
            title="S3 bucket without versioning/MFA delete",
            severity=Severity.LOW,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:s3:::{bucket_name}",
            resource_type="AWS::S3::Bucket",
            region="global",
            cloud_account_id=account_id,
            description=f"Bucket {bucket_name} has versioning disabled.",
            risk="Without versioning, accidental or malicious deletes are unrecoverable.",
            remediation=item.get("recommendation", "Enable versioning and MFA delete."),
            compliance={"CIS": ["2.1.3"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    for item in result.get("buckets_without_logging", []):
        bucket_name = item["bucket_name"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="s3_bucket_access_logging_disabled",
            title="S3 bucket without access logging",
            severity=Severity.LOW,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:s3:::{bucket_name}",
            resource_type="AWS::S3::Bucket",
            region="global",
            cloud_account_id=account_id,
            description=f"Bucket {bucket_name} has access logging disabled.",
            risk="Without access logs there is no audit trail of bucket reads/writes.",
            remediation=item.get("recommendation", "Enable S3 server access logging."),
            compliance={"CIS": ["2.1.2"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    total = len(findings)
    severity_breakdown: dict[str, int] = {}
    for f in findings:
        severity_breakdown[f.severity.value] = severity_breakdown.get(f.severity.value, 0) + 1

    summary = ScanSummary(
        provider=provider,
        benchmark=benchmark,
        cloud_account_id=account_id,
        started_at=now_iso,
        finished_at=now_iso,
        total=total,
        passed=0,
        failed=total,
        manual=0,
        severity_breakdown=severity_breakdown,
        fixture_mode=False,
    )
    return NormalizedFindings(
        security_findings=findings,
        compliance_checks=[],
        summary=summary,
    )


# ---------------------------------------------------------------------------
# EBS + Security Groups direct tool normalizer (boto3, no Prowler)
# ---------------------------------------------------------------------------

def _ebs_result_to_normalized(
    result: dict,
    account_id: str,
    provider: Provider,
    benchmark: Benchmark,
) -> Optional[NormalizedFindings]:
    """Convert scan_ebs_security_aws output to NormalizedFindings."""
    if not result.get("success"):
        return None

    now_iso = datetime.now(tz=timezone.utc).isoformat()
    region = result.get("region", "us-east-1")
    findings: list[SecurityFinding] = []

    for item in result.get("unencrypted_volumes", []):
        volume_id = item["volume_id"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="ec2_ebs_volume_encryption_enabled",
            title="EBS volume not encrypted",
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:ec2:{region}:{account_id}:volume/{volume_id}",
            resource_type="AWS::EC2::Volume",
            region=region,
            cloud_account_id=account_id,
            description=f"EBS volume {volume_id} is not encrypted.",
            risk="Unencrypted volumes expose data if the underlying storage is compromised.",
            remediation=item.get("recommendation", "Enable EBS encryption for this volume."),
            compliance={"CIS": ["2.2.1"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    for item in result.get("risky_security_groups", []):
        group_id = item["group_id"]
        description = ", ".join(item.get("issues", []))
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="ec2_securitygroup_allow_ingress_from_internet",
            title="Security group allows 0.0.0.0/0 ingress",
            severity=Severity.HIGH,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:ec2:{region}:{account_id}:security-group/{group_id}",
            resource_type="AWS::EC2::SecurityGroup",
            region=region,
            cloud_account_id=account_id,
            description=description or f"Security group {group_id} has risky ingress rules.",
            risk="Wide-open ingress from the public internet exposes the workload to attacks.",
            remediation=item.get("recommendation", "Restrict ingress rules to known CIDRs."),
            compliance={"CIS": ["5.2"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    for item in result.get("public_snapshots", []):
        snapshot_id = item["snapshot_id"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="ec2_ebs_snapshot_is_not_public",
            title="EBS snapshot is public",
            severity=Severity.CRITICAL,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:ec2:{region}:{account_id}:snapshot/{snapshot_id}",
            resource_type="AWS::EC2::Snapshot",
            region=region,
            cloud_account_id=account_id,
            description=f"EBS snapshot {snapshot_id} is publicly accessible.",
            risk="Public EBS snapshots leak full disk contents to any AWS account.",
            remediation=item.get("recommendation", "Remove public createVolumePermission from this snapshot."),
            compliance={"CIS": ["2.2.2"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    total = len(findings)
    severity_breakdown: dict[str, int] = {}
    for f in findings:
        severity_breakdown[f.severity.value] = severity_breakdown.get(f.severity.value, 0) + 1

    summary = ScanSummary(
        provider=provider,
        benchmark=benchmark,
        cloud_account_id=account_id,
        started_at=now_iso,
        finished_at=now_iso,
        total=total,
        passed=0,
        failed=total,
        manual=0,
        severity_breakdown=severity_breakdown,
        fixture_mode=False,
    )
    return NormalizedFindings(
        security_findings=findings,
        compliance_checks=[],
        summary=summary,
    )


# ---------------------------------------------------------------------------
# CloudTrail direct tool normalizer (boto3, no Prowler)
# ---------------------------------------------------------------------------

def _cloudtrail_result_to_normalized(
    result: dict,
    account_id: str,
    provider: Provider,
    benchmark: Benchmark,
) -> Optional[NormalizedFindings]:
    """Convert scan_cloudtrail_security_aws output to NormalizedFindings."""
    if not result.get("success"):
        return None

    now_iso = datetime.now(tz=timezone.utc).isoformat()
    region = result.get("region", "us-east-1")
    findings: list[SecurityFinding] = []

    for item in result.get("trail_issues", []):
        trail_arn = item.get("trail_arn", item.get("trail_name", "unknown"))
        issue = item.get("issue", "")

        if "multi-region" in issue.lower():
            check_id = "cloudtrail_multi_region_enabled"
            severity = Severity.HIGH
            compliance_cis = ["3.1"]
            title = "CloudTrail not multi-region"
            description = "Trail is not configured as multi-region, missing API activity from other regions."
            risk = "Single-region trails miss API activity in other regions, creating audit blind spots."
        elif "validation" in issue.lower():
            check_id = "cloudtrail_log_file_validation_enabled"
            severity = Severity.MEDIUM
            compliance_cis = ["3.2"]
            title = "CloudTrail log file validation disabled"
            description = "CloudTrail log file validation is not enabled for this trail."
            risk = "Without log file validation, tampered CloudTrail logs cannot be detected."
        elif "cloudwatch" in issue.lower():
            check_id = "cloudtrail_cloudwatch_logging_enabled"
            severity = Severity.MEDIUM
            compliance_cis = ["3.4"]
            title = "CloudTrail not integrated with CloudWatch Logs"
            description = "Trail is not delivering logs to CloudWatch Logs."
            risk = "Without CloudWatch integration, real-time alerting on suspicious API activity is impossible."
        else:
            check_id = "cloudtrail_misconfigured"
            severity = Severity.MEDIUM
            compliance_cis = ["3.1"]
            title = issue
            description = issue
            risk = "CloudTrail misconfiguration reduces audit coverage."

        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id=check_id,
            title=title,
            severity=severity,
            status=FindingStatus.FAIL,
            resource_id=trail_arn,
            resource_type="AWS::CloudTrail::Trail",
            region=region,
            cloud_account_id=account_id,
            description=description,
            risk=risk,
            remediation=item.get("recommendation", f"Fix CloudTrail configuration: {issue}"),
            compliance={"CIS": compliance_cis},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    for item in result.get("missing_metric_filters", []):
        filter_name = item.get("filter_name", "unknown")
        cis_control = item.get("cis_control", "3.3")
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id=f"cloudwatch_log_metric_filter_{filter_name}",
            title=f"Missing CloudWatch metric filter for {filter_name}",
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL,
            resource_id=filter_name,
            resource_type="AWS::CloudWatch::MetricFilter",
            region=region,
            cloud_account_id=account_id,
            description=item.get("description", f"Missing CloudWatch metric filter: {filter_name}"),
            risk="Missing CloudWatch metric filter — no alarm path for this security-relevant event.",
            remediation=item.get("recommendation", f"Create a CloudWatch metric filter for {filter_name}."),
            compliance={"CIS": [cis_control]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    total = len(findings)
    severity_breakdown: dict[str, int] = {}
    for f in findings:
        severity_breakdown[f.severity.value] = severity_breakdown.get(f.severity.value, 0) + 1

    summary = ScanSummary(
        provider=provider,
        benchmark=benchmark,
        cloud_account_id=account_id,
        started_at=now_iso,
        finished_at=now_iso,
        total=total,
        passed=0,
        failed=total,
        manual=0,
        severity_breakdown=severity_breakdown,
        fixture_mode=False,
    )
    return NormalizedFindings(
        security_findings=findings,
        compliance_checks=[],
        summary=summary,
    )


def _vpc_result_to_normalized(
    result: dict,
    account_id: str,
    provider: Provider,
    benchmark: Benchmark,
) -> Optional[NormalizedFindings]:
    """Convert scan_vpc_security_aws output to NormalizedFindings."""
    if not result.get("success"):
        return None

    now_iso = datetime.now(tz=timezone.utc).isoformat()
    region = result.get("region", "us-east-1")
    findings: list[SecurityFinding] = []

    # Default VPC present → CIS 5.4 / MEDIUM
    for item in result.get("default_vpcs", []):
        vpc_id = item["vpc_id"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="vpc_default_security_group_restricts_all_traffic",
            title="Default VPC present in region",
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}",
            resource_type="AWS::EC2::VPC",
            region=region,
            cloud_account_id=account_id,
            description=f"Default VPC {vpc_id} is present in region {region}.",
            risk="Default VPCs ship with permissive defaults that should be replaced with explicit, hardened VPCs.",
            remediation=item.get("recommendation", "Delete the default VPC or replace it with a hardened custom VPC."),
            compliance={"CIS": ["5.4"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    # VPCs without flow logs → CIS 5.1 / MEDIUM
    for item in result.get("vpcs_without_flow_logs", []):
        vpc_id = item["vpc_id"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="vpc_flow_logs_enabled",
            title="VPC without flow logs",
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}",
            resource_type="AWS::EC2::VPC",
            region=region,
            cloud_account_id=account_id,
            description=f"VPC {vpc_id} does not have active VPC flow logs configured.",
            risk="Without VPC flow logs, network-level forensics and intrusion detection are impossible.",
            remediation=item.get("recommendation", "Enable VPC Flow Logs for this VPC to capture network traffic metadata."),
            compliance={"CIS": ["5.1"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    # Subnets with auto-assign public IP → CIS 5.3 / LOW
    for item in result.get("subnets_with_public_ip", []):
        subnet_id = item["subnet_id"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="ec2_subnet_no_public_ip_auto_assign",
            title="Subnet auto-assigns public IPv4 addresses",
            severity=Severity.LOW,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:ec2:{region}:{account_id}:subnet/{subnet_id}",
            resource_type="AWS::EC2::Subnet",
            region=region,
            cloud_account_id=account_id,
            description=f"Subnet {subnet_id} in VPC {item.get('vpc_id', '')} has MapPublicIpOnLaunch enabled.",
            risk="Subnets that auto-assign public IPs accidentally expose new instances to the internet.",
            remediation=item.get("recommendation", "Disable auto-assign public IPv4 on this subnet and use explicit EIP/NAT instead."),
            compliance={"CIS": ["5.3"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    total = len(findings)
    severity_breakdown: dict[str, int] = {}
    for f in findings:
        severity_breakdown[f.severity.value] = severity_breakdown.get(f.severity.value, 0) + 1

    summary = ScanSummary(
        provider=provider,
        benchmark=benchmark,
        cloud_account_id=account_id,
        started_at=now_iso,
        finished_at=now_iso,
        total=total,
        passed=0,
        failed=total,
        manual=0,
        severity_breakdown=severity_breakdown,
        fixture_mode=False,
    )
    return NormalizedFindings(
        security_findings=findings,
        compliance_checks=[],
        summary=summary,
    )


# ---------------------------------------------------------------------------
# EC2 direct tool normalizer (boto3, no Prowler)
# ---------------------------------------------------------------------------

def _ec2_result_to_normalized(
    result: dict,
    account_id: str,
    provider: Provider,
    benchmark: Benchmark,
) -> Optional[NormalizedFindings]:
    """Convert scan_ec2_security_aws output to NormalizedFindings."""
    if not result.get("success"):
        return None

    now_iso = datetime.now(tz=timezone.utc).isoformat()
    region = result.get("region", "us-east-1")
    findings: list[SecurityFinding] = []

    # IMDSv2 not enforced → CIS 5.6 / HIGH
    for item in result.get("imdsv2_not_enforced", []):
        instance_id = item["instance_id"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="ec2_instance_imdsv2_enabled",
            title="EC2 instance does not enforce IMDSv2",
            severity=Severity.HIGH,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
            resource_type="AWS::EC2::Instance",
            region=region,
            cloud_account_id=account_id,
            description=f"Instance {instance_id} allows IMDSv1 (HttpTokens={item.get('http_tokens', 'optional')}).",
            risk="Without IMDSv2 enforcement, SSRF in the workload can steal instance role credentials.",
            remediation=item.get("recommendation", "Set HttpTokens=required in MetadataOptions for this instance."),
            compliance={"CIS": ["5.6"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    # Instance with public IP → CIS 5.5 / MEDIUM
    for item in result.get("public_ip_instances", []):
        instance_id = item["instance_id"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="ec2_instance_public_ip",
            title="EC2 instance has public IPv4",
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
            resource_type="AWS::EC2::Instance",
            region=region,
            cloud_account_id=account_id,
            description=f"Instance {instance_id} has a public IPv4 address ({item.get('public_ip', '')}).",
            risk="Public IPs on instances expand the attack surface; prefer NAT/ALB for ingress.",
            remediation=item.get("recommendation", "Remove the public IP and route traffic through a NAT gateway or ALB."),
            compliance={"CIS": ["5.5"]},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    # Monitoring disabled → LOW / no CIS code
    for item in result.get("monitoring_disabled", []):
        instance_id = item["instance_id"]
        findings.append(SecurityFinding(
            finding_id=str(uuid.uuid4()),
            check_id="ec2_instance_detailed_monitoring_enabled",
            title="EC2 instance without detailed monitoring",
            severity=Severity.LOW,
            status=FindingStatus.FAIL,
            resource_id=f"arn:aws:ec2:{region}:{account_id}:instance/{instance_id}",
            resource_type="AWS::EC2::Instance",
            region=region,
            cloud_account_id=account_id,
            description=f"Instance {instance_id} does not have detailed monitoring enabled.",
            risk="Without detailed monitoring, 1-minute metrics are unavailable for incident triage.",
            remediation=item.get("recommendation", "Enable detailed monitoring on this EC2 instance."),
            compliance={"CIS": []},
            categories=["software_and_configuration_checks"],
            finding_uid=str(uuid.uuid4()),
            scan_time=now_iso,
        ))

    total = len(findings)
    severity_breakdown: dict[str, int] = {}
    for f in findings:
        severity_breakdown[f.severity.value] = severity_breakdown.get(f.severity.value, 0) + 1

    summary = ScanSummary(
        provider=provider,
        benchmark=benchmark,
        cloud_account_id=account_id,
        started_at=now_iso,
        finished_at=now_iso,
        total=total,
        passed=0,
        failed=total,
        manual=0,
        severity_breakdown=severity_breakdown,
        fixture_mode=False,
    )
    return NormalizedFindings(
        security_findings=findings,
        compliance_checks=[],
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Chat scan (targeted scan using cached account context)
# ---------------------------------------------------------------------------

def _chat_scan_boto3(
    question: str,
    llm_json: Any,
    chat_account: dict,
) -> tuple[Optional[NormalizedFindings], dict]:
    """
    Route an AWS security question to the appropriate boto3 MCP tool.

    Returns (NormalizedFindings, meta) or (None, {}) if domain is unclear.
    No Prowler. No LangGraph. Direct MCP tool dispatch.

    The caller decides whether to fall back to the Prowler path when (None, {}) is returned.
    """
    account_id: str = chat_account["account_id"]
    role_arn: str = chat_account.get("role_arn", "")
    aws_region: str = chat_account.get("aws_region", "us-east-1") or "us-east-1"
    provider: Provider = chat_account.get("provider", Provider.AWS)

    # Detect which domain this question is about
    domain = _extract_aws_domain(llm_json, question)
    if domain is None:
        print("  No se pudo detectar el dominio — pregunta demasiado amplia.")
        return None, {}

    print(f"  Dominio detectado: {domain}")

    # Detect benchmark (for normalizer)
    detected = _detect_framework(llm_json, question, provider)
    benchmark = detected or Benchmark.CIS_6_0_AWS

    # Tool dispatch table: domain → (tool_name, args, normalizer_fn)
    # IAM uses no region param (global service)
    _DISPATCH: dict[str, tuple[str, dict, Any]] = {
        "iam":        ("scan_iam_security_aws",        {"role_arn": role_arn},                        _iam_result_to_normalized),
        "s3":         ("scan_s3_security_aws",         {"role_arn": role_arn, "region": aws_region},  _s3_result_to_normalized),
        "ebs":        ("scan_ebs_security_aws",        {"role_arn": role_arn, "region": aws_region},  _ebs_result_to_normalized),
        "cloudtrail": ("scan_cloudtrail_security_aws", {"role_arn": role_arn, "region": aws_region},  _cloudtrail_result_to_normalized),
        "vpc":        ("scan_vpc_security_aws",        {"role_arn": role_arn, "region": aws_region},  _vpc_result_to_normalized),
        "ec2":        ("scan_ec2_security_aws",        {"role_arn": role_arn, "region": aws_region},  _ec2_result_to_normalized),
    }

    if domain not in _DISPATCH:
        print(f"  Dominio '{domain}' no registrado en el dispatch.")
        return None, {}

    tool_name, args, normalizer = _DISPATCH[domain]

    print(f"  Llamando tool {tool_name}...")
    try:
        from backend.app.services.mcp_client import MCPClient
        result = asyncio.run(MCPClient().call_tool(tool_name, args))
    except Exception as exc:  # noqa: BLE001
        print(f"  Error al llamar {tool_name}: {exc}")
        return None, {}

    if not result.get("success"):
        print(f"  Tool falló: {result.get('error', 'unknown error')}")
        return None, {}

    normalized = normalizer(result, account_id, provider, benchmark)
    if normalized is None:
        print("  No se pudieron normalizar los findings.")
        return None, {}

    print(f"  {domain.upper()} scan completado — {normalized.summary.total} findings.")
    return normalized, {"checks": [], "services": [domain]}


def _scan_covered(last_meta: Optional[dict], checks: list[str], services: list[str]) -> bool:
    """Return True if last scan already covers what the new question needs."""
    if last_meta is None:
        return False
    last_checks = set(last_meta.get("checks", []))
    last_services = set(last_meta.get("services", []))
    if checks:
        return set(checks).issubset(last_checks)
    if services:
        return set(services).issubset(last_services)
    # broad scan — only covered if previous was also broad
    return not last_checks and not last_services


def _chat_scan(
    graph,
    question: str,
    llm_json: Any,
    chat_account: dict,
    fixture_mode: bool,
    last_normalized: Optional[NormalizedFindings] = None,
    last_meta: Optional[dict] = None,
) -> tuple[Optional[NormalizedFindings], dict]:
    """Run a targeted scan for the cached account context and return (findings, scan_meta)."""
    provider: Provider = chat_account["provider"]
    account_id: str = chat_account["account_id"]
    role_arn: str = chat_account.get("role_arn", "")

    print("  Analizando tu pregunta para optimizar el scan...")
    detected = _detect_framework(llm_json, question, provider)
    if detected:
        benchmark = detected
        print(f"  Framework detectado: {benchmark.value}")
    else:
        benchmark = Benchmark.CIS_5_0_AZURE if provider == Provider.AZURE else Benchmark.CIS_6_0_AWS
        print(f"  Usando benchmark por defecto: {benchmark.value}")

    resource_group: Optional[str] = None
    azure_region: Optional[str] = None
    aws_region: Optional[str] = None
    if provider == Provider.AZURE:
        resource_group, azure_region = _extract_azure_scope(llm_json, question)
        if resource_group:
            print(f"  Resource group detectado: {resource_group}")
        if azure_region:
            print(f"  Región detectada: {azure_region}")
    else:
        aws_region = _extract_aws_region(llm_json, question)
        if aws_region:
            print(f"  Región detectada: {aws_region}")

    excluded_checks = _extract_excluded_checks(llm_json, question, provider)
    if excluded_checks:
        print(f"  Checks excluidos: {', '.join(excluded_checks)}")

    categories = _extract_category(llm_json, question, provider)
    if categories:
        print(f"  Categoría detectada: {', '.join(categories)}")

    checks = _extract_checks(llm_json, question, provider)
    services: list[str] = []

    if checks:
        print(f"  Checks detectados: {', '.join(checks)} (scan rápido)")
    else:
        services = _extract_services(llm_json, question, provider)
        if services:
            print(f"  Dominio detectado: {', '.join(services)}")
        else:
            services = _AWS_ALL_SERVICES if provider == Provider.AWS else _AZURE_ALL_SERVICES
            print("  No se detectó dominio específico — escaneando todo.")

    # Reuse previous findings if they already cover what this question needs
    if last_normalized is not None and _scan_covered(last_meta, checks, services):
        print("  Usando findings del scan anterior (ya cubiertos).")
        return last_normalized, last_meta or {}

    # AWS: use direct boto3 domain tools (no Prowler, no LangGraph)
    if provider == Provider.AWS:
        boto3_account = {
            "account_id": account_id,
            "role_arn": role_arn,
            "provider": provider,
            "aws_region": aws_region or "us-east-1",
        }
        findings, meta = _chat_scan_boto3(question, llm_json, boto3_account)
        if findings is not None:
            return findings, meta
        print("  No se pudo resolver dominio AWS — usando Prowler como fallback.")

    severity_filter = _extract_severity(llm_json, question)
    print(f"  Severidad: {', '.join(severity_filter)}")
    fixture_path = os.environ.get("FIXTURE_PATH", "tests/fixtures/prowler_azure_sample.json")
    scan_request = ScanRequest(
        provider=provider,
        benchmark=benchmark,
        cloud_account_id=account_id,
        checks=checks,
        services=services,
        severity_filter=severity_filter,
        only_failed=True,
        resource_group=resource_group,
        azure_region=azure_region,
        aws_region=aws_region,
        role_arn=role_arn or None,
        excluded_checks=excluded_checks,
        categories=categories,
        fixture_mode=fixture_mode,
        fixture_path=fixture_path if fixture_mode else None,
    )
    report_policy = ReportPolicy(
        title=f"Chat scan — {account_id}",
        audience="Security Team",
        benchmark=benchmark,
        filter=FilterCriteria(only_failed=True, services=services),
        include_remediation=True,
        include_compliance_overview=False,
        created_at=datetime.now(tz=timezone.utc).isoformat(),
    )

    print("  Escaneando... (puede tardar varios minutos)")
    try:
        result = asyncio.run(graph.ainvoke({
            "scan_request": scan_request,
            "report_policy": report_policy,
            "skip_render": True,
        }))
    except Exception as exc:  # noqa: BLE001
        print(f"  Error durante el scan: {exc}")
        return None, {}

    if result.get("error"):
        # If checks were invalid, retry without them (fall back to compliance + service filter)
        if checks and "Invalid check" in result.get("error", ""):
            # IAM fast path: all invalid checks are iam_* → use direct boto3 tool
            if provider == Provider.AWS and all(c.startswith("iam_") for c in checks):
                print("  Checks IAM inválidos — usando análisis IAM directo (boto3)...")
                try:
                    iam_result = _call_iam_tool_direct(role_arn or None)
                    normalized = _iam_result_to_normalized(iam_result, account_id, provider, benchmark)
                    if normalized is not None:
                        print(f"  IAM scan completado — {normalized.summary.total} findings.")
                        return normalized, {"checks": [], "services": ["iam"]}
                    print("  IAM tool falló, usando Prowler como fallback.")
                except Exception as exc:  # noqa: BLE001
                    print(f"  IAM tool error: {exc} — usando Prowler como fallback.")

            print("  Checks inválidos detectados — reintentando con scan por servicio...")
            checks = []
            services = services or (_AWS_ALL_SERVICES if provider == Provider.AWS else _AZURE_ALL_SERVICES)
            scan_request = scan_request.model_copy(update={"checks": [], "categories": []})
            report_policy = report_policy.model_copy(
                update={"filter": FilterCriteria(only_failed=True, services=services)}
            )
            try:
                result = asyncio.run(graph.ainvoke({
                    "scan_request": scan_request,
                    "report_policy": report_policy,
                    "skip_render": True,
                }))
            except Exception as exc:  # noqa: BLE001
                print(f"  Error durante el scan: {exc}")
                return None, {}
            if result.get("error"):
                print(f"  Scan fallido: {result['error']}")
                return None, {}
        else:
            print(f"  Scan fallido: {result['error']}")
            return None, {}

    findings = result.get("filtered_findings") or result.get("filtered")
    meta = {"checks": checks, "services": services}
    return findings, meta


# ---------------------------------------------------------------------------
# Shared account config collector (used by both wizards)
# ---------------------------------------------------------------------------

def _collect_account_config(fixture_mode: bool) -> dict | None:
    """
    Collect a single account scan config interactively.
    Returns a dict with scan_request + report_policy, or None if cancelled.
    """
    provider_key = _pick({"1": ("Azure",), "2": ("AWS",)}, "¿Provider?")
    provider = Provider.AZURE if provider_key == "1" else Provider.AWS

    if provider == Provider.AZURE:
        account_id = _detect_azure_subscription_id()
        if account_id:
            print(f"  Subscription ID detectado: {account_id}")
        else:
            account_id = "unknown-account"
            print("  No se pudo detectar el Subscription ID (se usará 'unknown-account').")
    else:
        account_id = _detect_aws_account_id()
        if account_id:
            print(f"  Account ID detectado: {account_id}")
        else:
            account_id = "unknown-account"
            print("  No se pudo detectar el Account ID (se usará 'unknown-account').")

    benchmarks = _AZURE_BENCHMARKS if provider == Provider.AZURE else _AWS_BENCHMARKS
    bmark_key = _pick(benchmarks, "¿Framework de compliance?")
    benchmark = benchmarks[bmark_key][1]

    domains_map = _AZURE_DOMAINS if provider == Provider.AZURE else _AWS_DOMAINS
    chosen_keys = _pick_multi(domains_map, "¿Qué dominios querés auditar?")
    services: list[str] = []
    domain_names: list[str] = []
    for key in chosen_keys:
        name, svcs = domains_map[key]
        domain_names.append(name)
        services.extend(svcs)

    only_failed_key = _pick(
        {"1": ("Solo findings fallidos",), "2": ("Todos (PASS + FAIL)",)},
        "¿Qué findings incluir?",
    )
    only_failed = only_failed_key == "1"

    sev_key = _pick(
        {k: (v[0],) for k, v in _SEVERITY_OPTIONS.items()},
        "¿Severidad mínima?",
    )
    severity_filter = _SEVERITY_OPTIONS[sev_key][1]

    aws_region: Optional[str] = None
    role_arn: Optional[str] = None
    if provider == Provider.AWS:
        raw_region = _prompt("¿Región AWS específica? (Enter para todas)\n> ")
        aws_region = raw_region if raw_region else None
        raw_role = _prompt("¿Role ARN a asumir? (Enter para usar credenciales del entorno)\n> ")
        role_arn = raw_role if raw_role else None

    detected_mutelist = _mutelist_path(account_id)
    mutelist_file: Optional[str] = str(detected_mutelist) if detected_mutelist.exists() else None

    fixture_path = os.environ.get("FIXTURE_PATH", "tests/fixtures/prowler_azure_sample.json")
    scan_request = ScanRequest(
        provider=provider,
        benchmark=benchmark,
        cloud_account_id=account_id,
        severity_filter=severity_filter,
        only_failed=only_failed,
        aws_region=aws_region,
        role_arn=role_arn,
        mutelist_file=mutelist_file,
        fixture_mode=fixture_mode,
        fixture_path=fixture_path if fixture_mode else None,
    )
    report_policy = ReportPolicy(
        title=f"CIS {provider.value.upper()} — {account_id}",
        audience="Security Team",
        benchmark=benchmark,
        filter=FilterCriteria(only_failed=only_failed, services=services),
        include_remediation=True,
        include_compliance_overview=True,
        created_at=datetime.now(tz=timezone.utc).isoformat(),
    )
    return {
        "provider": provider,
        "account_id": account_id,
        "domain_names": domain_names,
        "scan_request": scan_request,
        "report_policy": report_policy,
    }


# ---------------------------------------------------------------------------
# Wizard — single cloud
# ---------------------------------------------------------------------------

def _run_wizard(fixture_mode: bool) -> dict:
    """Collect scan parameters step by step and return initial graph state."""
    provider_key = _pick({"1": ("Azure",), "2": ("AWS",)}, "¿Para qué provider?")
    provider = Provider.AZURE if provider_key == "1" else Provider.AWS

    if provider == Provider.AZURE:
        account_id = _detect_azure_subscription_id()
        if account_id:
            print(f"  Subscription ID detectado: {account_id}")
        else:
            account_id = "unknown-account"
            print("  No se pudo detectar el Subscription ID (se usará 'unknown-account').")
    else:
        account_id = _detect_aws_account_id()
        if account_id:
            print(f"  Account ID detectado: {account_id}")
        else:
            account_id = "unknown-account"
            print("  No se pudo detectar el Account ID (se usará 'unknown-account').")

    benchmarks = _AZURE_BENCHMARKS if provider == Provider.AZURE else _AWS_BENCHMARKS
    bmark_key = _pick(benchmarks, "¿Framework de compliance?")
    benchmark = benchmarks[bmark_key][1]

    domains_map = _AZURE_DOMAINS if provider == Provider.AZURE else _AWS_DOMAINS
    chosen_keys = _pick_multi(domains_map, "¿Qué dominios querés auditar?")
    services: list[str] = []
    domain_names: list[str] = []
    for key in chosen_keys:
        name, svcs = domains_map[key]
        domain_names.append(name)
        services.extend(svcs)

    only_failed_key = _pick(
        {"1": ("Solo findings fallidos",), "2": ("Todos (PASS + FAIL)",)},
        "¿Qué findings incluir?",
    )
    only_failed = only_failed_key == "1"

    sev_key = _pick(
        {k: (v[0],) for k, v in _SEVERITY_OPTIONS.items()},
        "¿Severidad mínima?",
    )
    severity_filter = _SEVERITY_OPTIONS[sev_key][1]
    sev_label = _SEVERITY_OPTIONS[sev_key][0]

    aws_region: Optional[str] = None
    role_arn: Optional[str] = None
    if provider == Provider.AWS:
        raw_region = _prompt("¿Región AWS específica? (Enter para todas)\n> ")
        aws_region = raw_region if raw_region else None
        raw_role = _prompt("¿Role ARN a asumir? (Enter para usar credenciales del entorno)\n> ")
        role_arn = raw_role if raw_role else None

    detected_mutelist = _mutelist_path(account_id)
    mutelist_file: Optional[str] = str(detected_mutelist) if detected_mutelist.exists() else None

    print(f"""
  Resumen:
    Provider   : {provider.value.upper()}
    Cuenta     : {account_id}
    Benchmark  : {benchmark.value}
    Dominios   : {', '.join(domain_names)}
    Filtro     : {'Solo fallidos' if only_failed else 'Todos'}
    Severidad  : {sev_label}
    Región     : {aws_region or 'todas'}
    Role ARN   : {role_arn or 'credenciales del entorno'}
    Mutelist   : {mutelist_file or 'ninguno'}
""")
    confirm = _prompt("¿Confirmás? (s/n)\n> ").lower()
    if confirm not in ("s", "si", "sí", "y", "yes"):
        print("  Cancelado.")
        return {}

    fixture_path = os.environ.get("FIXTURE_PATH", "tests/fixtures/prowler_azure_sample.json")
    scan_request = ScanRequest(
        provider=provider,
        benchmark=benchmark,
        cloud_account_id=account_id,
        severity_filter=severity_filter,
        only_failed=only_failed,
        aws_region=aws_region,
        role_arn=role_arn,
        mutelist_file=mutelist_file,
        fixture_mode=fixture_mode,
        fixture_path=fixture_path if fixture_mode else None,
    )
    report_policy = ReportPolicy(
        title=f"CIS {provider.value.upper()} Security Report — {account_id}",
        audience="Security Team",
        benchmark=benchmark,
        filter=FilterCriteria(only_failed=only_failed, services=services),
        include_remediation=True,
        include_compliance_overview=True,
        created_at=datetime.now(tz=timezone.utc).isoformat(),
    )
    return {"scan_request": scan_request, "report_policy": report_policy}


# ---------------------------------------------------------------------------
# Security chat mode
# ---------------------------------------------------------------------------

def _run_chat(
    llm: Any,
    llm_json: Any,
    graph,
    last_normalized: Optional[NormalizedFindings],
    fixture_mode: bool,
) -> Optional[NormalizedFindings]:
    """
    Free-form security Q&A loop with conversation history and lazy account context.

    - History is kept across turns so the LLM remembers the session.
    - Account context is asked only when the first account question arrives.
    - Once set, the account is reused for all account questions.
    """
    print("\n  Modo chat de seguridad. Escribí 'salir' para volver al menú.\n")

    history: list[BaseMessage] = []
    chat_account: Optional[dict] = None
    last_scan_meta: Optional[dict] = None
    react_agent: Optional[Any] = None
    system_general = SystemMessage(content=_SECURITY_SYSTEM_PROMPT)

    while True:
        question = _prompt("> ")
        if question.lower() in ("salir", "exit", "quit", "q", "volver"):
            break
        if not question:
            continue

        intent = _classify_question(llm_json, question)

        if intent == "account":
            # Lazily ask for account context on first account question
            if chat_account is None:
                chat_account = _ask_account_context()

            provider: Provider = chat_account.get("provider", Provider.AWS)

            # AWS path: ReAct agent calls the 6 boto3 domain tools directly
            if provider == Provider.AWS:
                if react_agent is None:
                    react_agent = build_react_agent(
                        role_arn=chat_account.get("role_arn", ""),
                        region=chat_account.get("region", "us-east-1"),
                        account_id=chat_account.get("account_id", ""),
                    )
                try:
                    answer = asyncio.run(ask_react_agent(react_agent, question))
                    print(f"\n{answer}\n")
                    history.append(HumanMessage(content=question))
                    history.append(AIMessage(content=answer))
                except Exception as exc:  # noqa: BLE001
                    print(f"  Error al contactar el agente: {exc}")
                continue

            # Azure path: Prowler scan → normalize → LLM answer
            account_changed = not _account_matches(last_normalized, chat_account["account_id"])
            if account_changed:
                last_scan_meta = None
            last_normalized, last_scan_meta = _chat_scan(
                graph, question, llm_json, chat_account, fixture_mode,
                last_normalized, last_scan_meta,
            )

            if last_normalized is not None:
                context = _findings_to_context(last_normalized)
                system_ctx = SystemMessage(
                    content=(
                        f"{_SECURITY_SYSTEM_PROMPT}\n\n"
                        f"The user's cloud account scan results:\n\n{context}\n\n"
                        f"Answer based on these specific findings."
                    )
                )
                try:
                    answer = _invoke_with_history(llm, system_ctx, history, question)
                    print(f"\n{answer}\n")
                    history.append(HumanMessage(content=question))
                    history.append(AIMessage(content=answer))
                except Exception as exc:  # noqa: BLE001
                    print(f"  Error al contactar el LLM: {exc}")
                continue

            # Scan failed — fall through to general answer
            print("  No se pudo obtener datos de la cuenta. Respondiendo con conocimiento general.\n")

        # General question
        try:
            answer = _invoke_with_history(llm, system_general, history, question)
            print(f"\n{answer}\n")
            history.append(HumanMessage(content=question))
            history.append(AIMessage(content=answer))
        except Exception as exc:  # noqa: BLE001
            print(f"  Error al contactar el LLM: {exc}")

    return last_normalized


# ---------------------------------------------------------------------------
# Main REPL
# ---------------------------------------------------------------------------

def main() -> None:
    fixture_mode = bool(int(os.environ.get("FIXTURE_MODE", "0")))

    if fixture_mode:
        # Propagate fixture mode to the MCP server subprocess
        os.environ["PROWLER_FIXTURE_MODE"] = "true"
        default_fixture = "tests/fixtures/prowler_azure_sample.json"
        if "PROWLER_FIXTURE_PATH" not in os.environ:
            os.environ["PROWLER_FIXTURE_PATH"] = os.environ.get("FIXTURE_PATH", default_fixture)

    print(_BANNER)
    if fixture_mode:
        print(f"\n  {_FIXTURE_NOTICE}")

    try:
        graph = build_graph()
        llm_chat = ChatAnthropic(model="claude-sonnet-4-6", temperature=0)
        llm_json = ChatAnthropic(model="claude-sonnet-4-6", temperature=0)
    except Exception as exc:  # noqa: BLE001
        print(f"Error al inicializar: {exc}", file=sys.stderr)
        sys.exit(1)

    last_normalized: Optional[NormalizedFindings] = None

    while True:
        choice = _pick(
            {
                "1": ("Generar un reporte de seguridad",),
                "2": ("Hacer una pregunta de seguridad",),
            },
            "¿Qué querés hacer?",
        )

        if choice == "1":
            report_type = _pick(
                {"1": ("Single cloud — un provider, una cuenta",), "2": ("Multi-cloud — varios providers y cuentas",)},
                "¿Qué tipo de reporte?",
            )

            if report_type == "1":
                initial_state = _run_wizard(fixture_mode)
                if not initial_state:
                    continue

                print("\n  Escaneando... (esto puede tardar varios minutos)")
                try:
                    result = asyncio.run(graph.ainvoke(initial_state))
                except Exception as exc:  # noqa: BLE001
                    print(f"  Error: {exc}")
                    continue

                if result.get("error"):
                    print(f"  Scan fallido: {result['error']}")
                elif result.get("report_path"):
                    print(f"\n  Reporte generado: {result['report_path']}")
                    last_normalized = result.get("filtered_findings") or result.get("filtered")
                    account_id = initial_state["scan_request"].cloud_account_id
                    _post_report_mute_prompt(last_normalized, account_id)
                else:
                    print("  Scan completado pero no se generó el reporte.")

            elif report_type == "2":
                _run_multicloud_wizard(fixture_mode, graph)

        elif choice == "2":
            last_normalized = _run_chat(
                llm_chat, llm_json, graph, last_normalized, fixture_mode
            )

        again = _prompt("¿Querés hacer algo más? (s/n)\n> ").lower()
        if again not in ("s", "si", "sí", "y", "yes"):
            print("\n  Goodbye.")
            break


if __name__ == "__main__":
    main()
