"""
doc_agent.py — Documentation Agent node function for the LangGraph graph.

Provides a single LangGraph node:
- generate_narrative: Produce executive summary + key risks + remediation priorities

Rules (spec DOC-1):
- MUST NOT import subprocess, mcp, or any Prowler module
- Narrative MUST be grounded in filtered findings (DOC-2)
- On LLM failure, MUST return a deterministic fallback string (DOC-3)

Design reference: sdd/poc-foundation/design Section 6 (Agents, doc_agent)
Spec reference:   sdd/poc-foundation/spec  — doc-agent DOC-1, DOC-2, DOC-3
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel

from backend.app.agents._llm import call_llm_validated
from backend.app.poc_contracts import FindingStatus, NormalizedFindings, ReportPolicy


# ---------------------------------------------------------------------------
# Internal Pydantic model for narrative output validation
# ---------------------------------------------------------------------------


class NarrativeSections(BaseModel):
    """Validated output structure for doc_agent narrative."""

    executive_summary: str
    key_risks: list[str]
    remediation_priorities: list[str]


# ---------------------------------------------------------------------------
# Fallback generator (deterministic, no LLM)
# ---------------------------------------------------------------------------


def _make_fallback_narrative(
    normalized: NormalizedFindings,
) -> dict[str, Any]:
    """
    Generate a deterministic fallback narrative from normalized findings.

    Called when the LLM is unavailable or returns invalid output after all
    retries.  This guarantees the pipeline always continues (DOC-3).
    """
    summary = normalized.summary
    failed_ids = [
        f.check_id
        for f in normalized.security_findings
        if f.status == FindingStatus.FAIL
    ][:5]

    exec_summary = (
        f"Scan completed for account {summary.cloud_account_id}. "
        f"Total findings: {summary.total} "
        f"({summary.failed} failed, {summary.passed} passed). "
        f"Narrative generation was unavailable — please review the findings table directly."
    )

    key_risks = [
        f"Check {cid} requires remediation." for cid in failed_ids
    ] or ["No high-priority risks identified in this scan."]

    remediation_priorities = [
        f"Remediate {cid} as soon as possible." for cid in failed_ids
    ] or ["No immediate remediation actions required."]

    return {
        "executive_summary": exec_summary,
        "key_risks": key_risks,
        "remediation_priorities": remediation_priorities,
    }


# ---------------------------------------------------------------------------
# Node: generate_narrative
# ---------------------------------------------------------------------------


async def generate_narrative(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node: generate an executive narrative from filtered findings.

    Uses the LLM to produce:
    - executive_summary: 2-3 paragraph overview
    - key_risks: top 5 risk statements (each referencing a finding)
    - remediation_priorities: top 5 prioritised actions

    If the LLM call fails or returns invalid output after all retries,
    a deterministic fallback narrative is returned instead (DOC-3).
    The node NEVER raises an unhandled exception.

    Args:
        state: GraphState dict.  Must contain "filtered_findings", "report_policy",
               and "llm".

    Returns:
        Updated state with "narrative" set (dict with executive_summary, key_risks,
        remediation_priorities).
    """
    llm = state.get("llm")
    filtered: NormalizedFindings | None = state.get("filtered_findings")
    policy: ReportPolicy | None = state.get("report_policy")

    # Guard: if no filtered findings are available, use fallback immediately
    if filtered is None:
        fallback = {
            "executive_summary": "No scan results available for narrative generation.",
            "key_risks": [],
            "remediation_priorities": [],
        }
        return {**state, "narrative": fallback}

    # Build grounded context for the LLM (DOC-2: only use input findings)
    findings_summary_lines = []
    for f in filtered.security_findings[:20]:  # cap context size
        findings_summary_lines.append(
            f"  - [{f.status.value}] {f.check_id}: {f.title} "
            f"(severity={f.severity.value}, resource={f.resource_type})"
        )
    findings_context = "\n".join(findings_summary_lines) or "  (no findings)"

    summary = filtered.summary
    audience = policy.audience if policy else "Security Team"
    benchmark = policy.benchmark.value if policy else "CIS Azure"

    prompt = (
        f"You are a cloud security analyst writing a {benchmark} compliance report "
        f"for {audience!r}.\n\n"
        f"Scan summary: {summary.total} total findings, "
        f"{summary.failed} FAIL, {summary.passed} PASS.\n"
        f"Top findings:\n{findings_context}\n\n"
        f"Return ONLY a JSON object with these exact fields:\n"
        f"  executive_summary: string (2-3 paragraphs summarising overall security posture)\n"
        f"  key_risks: array of strings (up to 5 risk statements, each referencing a "
        f"specific check_id from the findings above)\n"
        f"  remediation_priorities: array of strings (up to 5 prioritised actions)\n"
        f"IMPORTANT: Refer only to the findings listed above. Do not invent new findings."
    )

    try:
        narrative_obj: NarrativeSections = await call_llm_validated(
            llm, prompt, NarrativeSections, max_retries=3
        )
        return {
            **state,
            "narrative": {
                "executive_summary": narrative_obj.executive_summary,
                "key_risks": narrative_obj.key_risks,
                "remediation_priorities": narrative_obj.remediation_priorities,
            },
        }
    except Exception:  # noqa: BLE001
        # Deterministic fallback — pipeline must continue (DOC-3)
        return {**state, "narrative": _make_fallback_narrative(filtered)}
