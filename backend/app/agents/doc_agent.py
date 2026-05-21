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

from typing import Any

from backend.app.poc_contracts import FindingStatus, NormalizedFindings


# ---------------------------------------------------------------------------
# Narrative generator (deterministic, no LLM)
# ---------------------------------------------------------------------------


def _make_narrative(normalized: NormalizedFindings) -> dict[str, Any]:
    """Generate a deterministic narrative from normalized findings — no LLM."""
    summary = normalized.summary
    failed = [f for f in normalized.security_findings if f.status == FindingStatus.FAIL]

    # Severity breakdown of failures
    sev_counts: dict[str, int] = {}
    for f in failed:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    sev_line = ", ".join(
        f"{count} {sev}" for sev, count in sorted(
            sev_counts.items(),
            key=lambda x: ["Critical", "High", "Medium", "Low", "Informational"].index(x[0])
            if x[0] in ["Critical", "High", "Medium", "Low", "Informational"] else 99
        )
    ) or "none"

    exec_summary = (
        f"Security scan completed for account {summary.cloud_account_id} "
        f"using benchmark {summary.benchmark.value}. "
        f"A total of {summary.total} findings were evaluated: "
        f"{summary.failed} failed and {summary.passed} passed. "
        f"Failed findings by severity: {sev_line}."
    )

    # Top 5 risks — highest severity failures first
    _sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    top_failed = sorted(failed, key=lambda f: _sev_order.get(f.severity.value, 9))[:5]
    key_risks = [
        f"[{f.severity.value}] {f.check_id}: {f.title}" for f in top_failed
    ] or ["No failed findings in this scan."]

    remediation_priorities = [
        f"Remediate {f.check_id} ({f.severity.value}): {f.remediation[:120].rstrip()}..."
        if len(f.remediation) > 120 else f"Remediate {f.check_id} ({f.severity.value}): {f.remediation}"
        for f in top_failed
    ] or ["No remediation actions required."]

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
    LangGraph node: generate a deterministic narrative from filtered findings.

    Produces executive_summary, key_risks, and remediation_priorities
    directly from findings data — no LLM call, fully reproducible.
    """
    filtered: NormalizedFindings | None = state.get("filtered_findings")

    if filtered is None:
        return {**state, "narrative": {
            "executive_summary": "No scan results available.",
            "key_risks": [],
            "remediation_priorities": [],
        }}

    return {**state, "narrative": _make_narrative(filtered)}
