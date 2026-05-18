"""
Tests for backend/app/agents/doc_agent.py:
- generate_narrative produces narrative referencing a finding's check_id
- LLM exception yields fallback string without unhandled exception
- Boundary guard: no subprocess/mcp imports

Design reference: sdd/poc-foundation/design Section 6 (Agents, doc_agent)
Spec reference:   sdd/poc-foundation/spec  — doc-agent DOC-1, DOC-2, DOC-3

TDD: tests written before implementation (RED phase T-4-5).
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.app.poc_contracts import (
    Benchmark,
    FilterCriteria,
    FindingStatus,
    NormalizedFindings,
    Provider,
    ReportPolicy,
    ScanSummary,
    SecurityFinding,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(check_id: str = "iam_001") -> SecurityFinding:
    return SecurityFinding(
        finding_id="f-" + check_id,
        check_id=check_id,
        title=f"Check {check_id}",
        severity=Severity.HIGH,
        status=FindingStatus.FAIL,
        resource_id="res-uid",
        resource_type="microsoft.iam/users",
        region="global",
        cloud_account_id="sub-001",
        description="Description",
        risk="Risk",
        remediation="Remediation",
        references=[],
        compliance={},
        categories=[],
        finding_uid="uid-" + check_id,
        scan_time="2025-01-01T00:00:00+00:00",
    )


def _make_normalized(findings: list[SecurityFinding]) -> NormalizedFindings:
    total = len(findings)
    passed = sum(1 for f in findings if f.status == FindingStatus.PASS)
    failed = sum(1 for f in findings if f.status == FindingStatus.FAIL)
    summary = ScanSummary(
        provider=Provider.AZURE,
        benchmark=Benchmark.CIS_2_0_AZURE,
        cloud_account_id="sub-001",
        started_at="2025-01-01T00:00:00+00:00",
        finished_at="2025-01-01T01:00:00+00:00",
        total=total,
        passed=passed,
        failed=failed,
        fixture_mode=True,
    )
    return NormalizedFindings(
        security_findings=findings,
        compliance_checks=[],
        summary=summary,
    )


def _make_policy() -> ReportPolicy:
    return ReportPolicy(
        title="CIS Azure Report",
        audience="Security Team",
        benchmark=Benchmark.CIS_2_0_AZURE,
        filter=FilterCriteria(),
        include_remediation=True,
        include_compliance_overview=True,
    )


# ---------------------------------------------------------------------------
# Tests: generate_narrative node
# ---------------------------------------------------------------------------

class TestGenerateNarrative:
    """Tests for doc_agent.generate_narrative LangGraph node."""

    def test_import_succeeds(self):
        """doc_agent must be importable."""
        from backend.app.agents.doc_agent import generate_narrative
        assert callable(generate_narrative)

    def test_narrative_has_required_keys(self):
        """generate_narrative must produce a dict with executive_summary, key_risks, remediation_priorities."""
        from backend.app.agents.doc_agent import generate_narrative

        findings = [_make_finding("iam_001"), _make_finding("iam_002")]
        normalized = _make_normalized(findings)
        policy = _make_policy()

        narrative_payload = {
            "executive_summary": "There are 2 failed IAM checks requiring attention.",
            "key_risks": ["iam_001: risk one", "iam_002: risk two"],
            "remediation_priorities": ["Fix iam_001 first", "Then iam_002"],
        }

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            return_value=MagicMock(content=json.dumps(narrative_payload))
        )

        state = {
            "filtered_findings": normalized,
            "report_policy": policy,
            "llm": mock_llm,
        }

        result = asyncio.run(generate_narrative(state))

        assert "narrative" in result
        narrative = result["narrative"]
        assert "executive_summary" in narrative
        assert "key_risks" in narrative
        assert "remediation_priorities" in narrative

    def test_narrative_references_finding(self):
        """Narrative content should reference at least one finding check_id."""
        from backend.app.agents.doc_agent import generate_narrative

        findings = [_make_finding("iam_critical_check")]
        normalized = _make_normalized(findings)
        policy = _make_policy()

        narrative_payload = {
            "executive_summary": "Check iam_critical_check requires immediate attention.",
            "key_risks": ["iam_critical_check poses risk of unauthorized access"],
            "remediation_priorities": ["Remediate iam_critical_check"],
        }

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            return_value=MagicMock(content=json.dumps(narrative_payload))
        )

        state = {
            "filtered_findings": normalized,
            "report_policy": policy,
            "llm": mock_llm,
        }

        result = asyncio.run(generate_narrative(state))
        narrative = result["narrative"]

        # At least one field in narrative must reference the check_id
        all_text = str(narrative)
        assert "iam_critical_check" in all_text, (
            "Narrative must reference at least one finding check_id — DOC-2"
        )

    def test_llm_exception_yields_fallback(self):
        """When LLM raises an exception, a fallback narrative string is returned."""
        from backend.app.agents.doc_agent import generate_narrative

        findings = [_make_finding("iam_001")]
        normalized = _make_normalized(findings)
        policy = _make_policy()

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(side_effect=RuntimeError("Ollama not reachable"))

        state = {
            "filtered_findings": normalized,
            "report_policy": policy,
            "llm": mock_llm,
        }

        # Must NOT raise an exception
        result = asyncio.run(generate_narrative(state))

        assert "narrative" in result
        narrative = result["narrative"]
        # Fallback must still have the required keys
        assert "executive_summary" in narrative
        assert isinstance(narrative["executive_summary"], str)
        assert len(narrative["executive_summary"]) > 0

    def test_llm_invalid_json_uses_fallback(self):
        """All retries returning invalid JSON must produce a fallback, not an exception."""
        from backend.app.agents.doc_agent import generate_narrative

        findings = [_make_finding("iam_001")]
        normalized = _make_normalized(findings)
        policy = _make_policy()

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            return_value=MagicMock(content="not json at all {{")
        )

        state = {
            "filtered_findings": normalized,
            "report_policy": policy,
            "llm": mock_llm,
        }

        result = asyncio.run(generate_narrative(state))

        assert "narrative" in result
        assert "executive_summary" in result["narrative"]

    def test_empty_findings_returns_narrative(self):
        """generate_narrative with empty findings must still return a valid narrative dict."""
        from backend.app.agents.doc_agent import generate_narrative

        normalized = _make_normalized([])
        policy = _make_policy()

        narrative_payload = {
            "executive_summary": "No findings were identified in this scan.",
            "key_risks": [],
            "remediation_priorities": [],
        }

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            return_value=MagicMock(content=json.dumps(narrative_payload))
        )

        state = {
            "filtered_findings": normalized,
            "report_policy": policy,
            "llm": mock_llm,
        }

        result = asyncio.run(generate_narrative(state))
        assert "narrative" in result
        assert isinstance(result["narrative"]["executive_summary"], str)


# ---------------------------------------------------------------------------
# Boundary guard: no subprocess/mcp in doc_agent.py (DOC-1)
# ---------------------------------------------------------------------------

class TestDocAgentBoundary:
    """DOC-1: doc_agent.py MUST NOT import subprocess, mcp, or Prowler modules."""

    FORBIDDEN = ["subprocess", "mcp", "mcp_client", "MCP_SERVER", "prowler"]

    def test_no_forbidden_imports(self):
        source = Path("backend/app/agents/doc_agent.py").read_text()
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = (
                    [alias.name or "" for alias in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                )
                for name in names:
                    for forbidden in self.FORBIDDEN:
                        assert forbidden not in name, (
                            f"doc_agent.py must NOT import {forbidden!r} — found: {name!r}"
                        )
