"""
cis_agent.py — CIS Agent node functions for the LangGraph graph.

This module provides three LangGraph node functions:
- interpret_request: Parse user_input → ScanRequest using LLM
- build_policy:      Generate ReportPolicy from scan_request using LLM
- apply_filter:      Pure deterministic filtering of NormalizedFindings by ReportPolicy

Rules (spec CIS-1):
- MUST NOT import subprocess, mcp, mcp_client, or any Prowler module
- Policy building and interpret_request use retry-with-repair via _llm.py (CIS-2)
- Filtering is pure and deterministic — no LLM call (CIS-3)
- Filtering MUST NOT invent findings (CIS-4)

Design reference: sdd/poc-foundation/design Section 6 (Agents, cis_agent)
Spec reference:   sdd/poc-foundation/spec  — cis-agent CIS-1 through CIS-4
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from backend.app.agents._llm import call_llm_validated
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
    Severity,
)

# ---------------------------------------------------------------------------
# Severity ordering for min_severity comparisons (higher index = more severe)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Node: interpret_request
# ---------------------------------------------------------------------------


async def interpret_request(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node: parse user_input → ScanRequest using the LLM.

    The LLM is expected in state["llm"]. On validation failure the helper
    retries up to 3 times with a repair hint.  If all retries fail, the node
    sets state["error"] and returns without crashing.

    Args:
        state: GraphState dict. Must contain "user_input" and "llm".

    Returns:
        Updated state with "scan_request" set (ScanRequest) or "error" set.
    """
    llm = state.get("llm")
    user_input: str = state.get("user_input", "")

    fixture_mode = bool(int(os.environ.get("FIXTURE_MODE", "0")))
    fixture_path = os.environ.get(
        "FIXTURE_PATH", "tests/fixtures/prowler_azure_sample.json"
    )

    prompt = (
        f"Extract a cloud security scan request from the following user input.\n"
        f"User input: {user_input!r}\n\n"
        f"Return ONLY a JSON object with these fields:\n"
        f"  provider: string, one of ['azure', 'aws'] (default: 'azure')\n"
        f"  benchmark: string, one of "
        f"['cis_azure_foundations_benchmark_v2.0', "
        f"'cis_azure_foundations_benchmark_v2.1', "
        f"'cis_aws_foundations_benchmark_v1.5', "
        f"'cis_aws_foundations_benchmark_v2.0', "
        f"'cis_aws_foundations_benchmark_v3.0'] "
        f"(default: 'cis_azure_foundations_benchmark_v2.0')\n"
        f"  cloud_account_id: string (extract from input or use 'unknown-account')\n"
        f"  fixture_mode: boolean (default: {str(fixture_mode).lower()})\n"
        f"  fixture_path: string or null\n"
        f"Example: {{\"provider\": \"azure\", \"benchmark\": "
        f"\"cis_azure_foundations_benchmark_v2.0\", "
        f"\"cloud_account_id\": \"abc-123\", \"fixture_mode\": false, \"fixture_path\": null}}"
    )

    # If the wizard already built a ScanRequest, respect it — skip LLM
    if state.get("scan_request") is not None:
        scan_request = state["scan_request"]
        if fixture_mode and not scan_request.fixture_mode:
            scan_request = scan_request.model_copy(
                update={"fixture_mode": True, "fixture_path": fixture_path}
            )
        return {**state, "scan_request": scan_request}

    try:
        scan_request = await call_llm_validated(
            llm, prompt, ScanRequest, max_retries=3
        )
        if fixture_mode and not scan_request.fixture_mode:
            scan_request = scan_request.model_copy(
                update={"fixture_mode": True, "fixture_path": fixture_path}
            )
        return {**state, "scan_request": scan_request}
    except Exception as exc:  # noqa: BLE001
        return {**state, "error": f"interpret_request failed: {exc}"}


# ---------------------------------------------------------------------------
# Node: build_policy
# ---------------------------------------------------------------------------


async def build_policy(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node: create a ReportPolicy from the scan_request using the LLM.

    Args:
        state: GraphState dict. Must contain "scan_request" and "llm".

    Returns:
        Updated state with "report_policy" set (ReportPolicy) or "error" set.
    """
    llm = state.get("llm")
    scan_request: ScanRequest | None = state.get("scan_request")

    if scan_request is None:
        return {**state, "error": "build_policy: scan_request is not set"}

    # If the wizard already built a ReportPolicy, respect it — skip LLM
    if state.get("report_policy") is not None:
        return state

    prompt = (
        f"Create a security report policy for the following scan request.\n"
        f"Provider: {scan_request.provider.value}\n"
        f"Benchmark: {scan_request.benchmark.value}\n"
        f"Cloud Account: {scan_request.cloud_account_id}\n\n"
        f"Return ONLY a JSON object with these fields:\n"
        f"  title: string (descriptive report title)\n"
        f"  audience: string (e.g. 'Security Team', 'Management')\n"
        f"  benchmark: string (same as above: {scan_request.benchmark.value!r})\n"
        f"  filter: object with optional keys: min_severity, only_failed, "
        f"include_controls, exclude_controls, resource_types\n"
        f"  include_remediation: boolean (default: true)\n"
        f"  include_compliance_overview: boolean (default: true)\n"
        f"Example: {{\"title\": \"CIS Azure L1 Report\", \"audience\": "
        f"\"Security Team\", \"benchmark\": "
        f"\"{scan_request.benchmark.value}\", \"filter\": {{\"only_failed\": true}}, "
        f"\"include_remediation\": true, \"include_compliance_overview\": true}}"
    )

    try:
        report_policy: ReportPolicy = await call_llm_validated(
            llm, prompt, ReportPolicy, max_retries=3
        )
        return {**state, "report_policy": report_policy}
    except Exception as exc:  # noqa: BLE001
        # Deterministic fallback: create a default policy
        fallback_policy = ReportPolicy(
            title=f"CIS Azure Security Report — {scan_request.cloud_account_id}",
            audience="Security Team",
            benchmark=scan_request.benchmark,
            filter=FilterCriteria(only_failed=True),
            include_remediation=True,
            include_compliance_overview=True,
            created_at=datetime.now(tz=timezone.utc).isoformat(),
        )
        return {**state, "report_policy": fallback_policy}


# ---------------------------------------------------------------------------
# Pure function: apply_filter
# ---------------------------------------------------------------------------


def apply_filter(
    normalized: NormalizedFindings,
    criteria: FilterCriteria,
    max_findings: int | None = None,
) -> NormalizedFindings:
    """
    Pure deterministic filtering of NormalizedFindings.

    Applies the following filters in order:
    1. min_severity: keeps findings >= min_severity level
    2. only_failed: keeps only FAIL status findings
    3. include_controls: keeps findings whose compliance map contains at least one match
    4. exclude_controls: removes findings whose compliance map contains any excluded control
    5. resource_types: keeps findings matching any resource type in the filter list
    6. max_findings: truncates the result to at most max_findings items

    Args:
        normalized:   Input NormalizedFindings (not mutated).
        criteria:     FilterCriteria specifying what to include/exclude.
        max_findings: Optional hard cap on number of returned findings.

    Returns:
        A NEW NormalizedFindings instance with filtered findings and recomputed summary.
        NEVER returns findings not in the original input (CIS-4).
    """
    findings = list(normalized.security_findings)

    # --- 1. min_severity ---
    if criteria.min_severity is not None:
        min_level = _SEVERITY_ORDER[criteria.min_severity]
        findings = [
            f for f in findings if _SEVERITY_ORDER[f.severity] >= min_level
        ]

    # --- 2. only_failed ---
    if criteria.only_failed:
        findings = [f for f in findings if f.status == FindingStatus.FAIL]

    # --- 3. include_controls ---
    if criteria.include_controls:
        include_set = set(criteria.include_controls)
        findings = [
            f for f in findings
            if _has_any_control(f.compliance, include_set)
        ]

    # --- 4. exclude_controls ---
    if criteria.exclude_controls:
        exclude_set = set(criteria.exclude_controls)
        findings = [
            f for f in findings
            if not _has_any_control(f.compliance, exclude_set)
        ]

    # --- 5. resource_types ---
    if criteria.resource_types:
        resource_type_set = {rt.lower() for rt in criteria.resource_types}
        findings = [
            f for f in findings
            if f.resource_type.lower() in resource_type_set
        ]

    # --- 6. services (check_id prefix match) ---
    if criteria.services:
        prefixes = tuple(s.lower() + "_" for s in criteria.services)
        findings = [
            f for f in findings
            if f.check_id.lower().startswith(prefixes)
        ]

    # --- 7. max_findings truncation ---
    if max_findings is not None and len(findings) > max_findings:
        findings = findings[:max_findings]

    # --- Recompute summary counts ---
    total = len(findings)
    passed = sum(1 for f in findings if f.status == FindingStatus.PASS)
    failed = sum(1 for f in findings if f.status == FindingStatus.FAIL)
    manual = sum(1 for f in findings if f.status == FindingStatus.MANUAL)

    severity_breakdown: dict[str, int] = {}
    for f in findings:
        key = f.severity.value
        severity_breakdown[key] = severity_breakdown.get(key, 0) + 1

    updated_summary = normalized.summary.model_copy(
        update={
            "total": total,
            "passed": passed,
            "failed": failed,
            "manual": manual,
            "severity_breakdown": severity_breakdown,
        }
    )

    return NormalizedFindings(
        security_findings=findings,
        compliance_checks=normalized.compliance_checks,
        summary=updated_summary,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _has_any_control(
    compliance: dict[str, list[str]],
    control_set: set[str],
) -> bool:
    """Return True if any control in compliance map matches any ID in control_set."""
    for control_ids in compliance.values():
        for cid in control_ids:
            if cid in control_set:
                return True
    return False
