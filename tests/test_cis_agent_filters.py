"""
Tests for backend/app/agents/ layer (CIS agent and LLM helper):
- _llm.py: call_llm_validated retry logic
- cis_agent.py: interpret_request (mocked LLM), build_policy (mocked LLM), apply_filter (pure logic)
- Boundary guard: no subprocess/mcp imports in agent modules

Design reference: sdd/poc-foundation/design Section 6 (Agents)
Spec reference:   sdd/poc-foundation/spec  — cis-agent CIS-1 through CIS-4

TDD: tests written before implementation (RED phase T-4-3).
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from backend.app.poc_contracts import (
    Benchmark,
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


# ---------------------------------------------------------------------------
# Helpers / shared fixtures
# ---------------------------------------------------------------------------

def _make_finding(
    check_id: str = "iam_001",
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.FAIL,
    resource_type: str = "microsoft.iam/users",
) -> SecurityFinding:
    return SecurityFinding(
        finding_id="f-" + check_id,
        check_id=check_id,
        title=f"Check {check_id}",
        severity=severity,
        status=status,
        resource_id="resource-uid",
        resource_type=resource_type,
        region="global",
        cloud_account_id="sub-001",
        description="Test description",
        risk="Test risk",
        remediation="Test remediation",
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
    manual = sum(1 for f in findings if f.status == FindingStatus.MANUAL)
    summary = ScanSummary(
        provider=Provider.AZURE,
        benchmark=Benchmark.CIS_2_0_AZURE,
        cloud_account_id="sub-001",
        started_at="2025-01-01T00:00:00+00:00",
        finished_at="2025-01-01T01:00:00+00:00",
        total=total,
        passed=passed,
        failed=failed,
        manual=manual,
        severity_breakdown={},
        fixture_mode=True,
    )
    return NormalizedFindings(
        security_findings=findings,
        compliance_checks=[],
        summary=summary,
    )


def _make_scan_request() -> ScanRequest:
    return ScanRequest(
        provider=Provider.AZURE,
        benchmark=Benchmark.CIS_2_0_AZURE,
        cloud_account_id="sub-001",
        fixture_mode=True,
        fixture_path="tests/fixtures/prowler_azure_sample.json",
    )


# ---------------------------------------------------------------------------
# T-4-1: _llm.py — call_llm_validated retry tests
# ---------------------------------------------------------------------------

class TestCallLlmValidated:
    """Tests for the shared LLM retry helper in agents/_llm.py."""

    def test_import_succeeds(self):
        """_llm.py must be importable."""
        from backend.app.agents._llm import call_llm_validated
        assert callable(call_llm_validated)

    def test_valid_llm_response_returns_model(self):
        """When LLM returns valid JSON, call_llm_validated returns validated model."""
        from backend.app.agents._llm import call_llm_validated

        valid_payload = {
            "title": "CIS Azure Report",
            "audience": "Security Team",
            "benchmark": Benchmark.CIS_2_0_AZURE.value,
            "filter": {},
            "include_remediation": True,
            "include_compliance_overview": True,
        }

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            return_value=MagicMock(content=json.dumps(valid_payload))
        )

        result = asyncio.run(
            call_llm_validated(mock_llm, "Build a report policy", ReportPolicy)
        )
        assert isinstance(result, ReportPolicy)
        assert result.title == "CIS Azure Report"

    def test_invalid_then_valid_retries_succeed(self):
        """On first call invalid JSON, second call valid JSON → succeeds on retry."""
        from backend.app.agents._llm import call_llm_validated

        valid_payload = {
            "title": "Retry Report",
            "audience": "Ops",
            "benchmark": Benchmark.CIS_2_0_AZURE.value,
            "filter": {},
            "include_remediation": True,
            "include_compliance_overview": True,
        }

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            side_effect=[
                MagicMock(content="this is not json {{"),  # attempt 1 fails
                MagicMock(content=json.dumps(valid_payload)),  # attempt 2 succeeds
            ]
        )

        result = asyncio.run(
            call_llm_validated(mock_llm, "Build a report policy", ReportPolicy)
        )
        assert isinstance(result, ReportPolicy)
        assert mock_llm.ainvoke.call_count == 2

    def test_all_retries_fail_raises(self):
        """When all 3 retries return invalid JSON, raises an exception."""
        from backend.app.agents._llm import call_llm_validated

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            return_value=MagicMock(content="not valid json")
        )

        with pytest.raises(Exception):
            asyncio.run(
                call_llm_validated(mock_llm, "Build a report policy", ReportPolicy, max_retries=3)
            )

        assert mock_llm.ainvoke.call_count == 3

    def test_validation_error_triggers_retry(self):
        """On Pydantic ValidationError (valid JSON but wrong schema), retry is attempted."""
        from backend.app.agents._llm import call_llm_validated

        # Missing required fields for ReportPolicy
        bad_payload = {"title": "Only Title"}  # missing audience, benchmark
        good_payload = {
            "title": "Good Report",
            "audience": "Ops",
            "benchmark": Benchmark.CIS_2_0_AZURE.value,
            "filter": {},
            "include_remediation": True,
            "include_compliance_overview": True,
        }

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            side_effect=[
                MagicMock(content=json.dumps(bad_payload)),
                MagicMock(content=json.dumps(good_payload)),
            ]
        )

        result = asyncio.run(
            call_llm_validated(mock_llm, "Make policy", ReportPolicy)
        )
        assert isinstance(result, ReportPolicy)
        assert mock_llm.ainvoke.call_count == 2


# ---------------------------------------------------------------------------
# T-4-2: cis_agent.py — interpret_request (mocked LLM)
# ---------------------------------------------------------------------------

class TestInterpretRequest:
    """Tests for cis_agent.interpret_request node."""

    def test_valid_llm_response_sets_scan_request(self):
        """interpret_request with mocked LLM sets state['scan_request'] correctly."""
        from backend.app.agents.cis_agent import interpret_request

        valid_scan_request_dict = {
            "provider": "azure",
            "benchmark": "cis_2.0_azure",
            "cloud_account_id": "sub-abc",
            "fixture_mode": True,
            "fixture_path": "tests/fixtures/prowler_azure_sample.json",
        }

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            return_value=MagicMock(content=json.dumps(valid_scan_request_dict))
        )

        state = {
            "user_input": "Run CIS audit on subscription sub-abc",
            "llm": mock_llm,
        }

        result = asyncio.run(interpret_request(state))
        assert "scan_request" in result
        assert isinstance(result["scan_request"], ScanRequest)
        assert result["scan_request"].cloud_account_id == "sub-abc"

    def test_retry_on_bad_json_then_valid(self):
        """interpret_request retries when LLM returns invalid JSON first."""
        from backend.app.agents.cis_agent import interpret_request

        valid_dict = {
            "provider": "azure",
            "benchmark": "cis_2.0_azure",
            "cloud_account_id": "sub-retry",
            "fixture_mode": False,
            "fixture_path": None,
        }

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            side_effect=[
                MagicMock(content="not json"),
                MagicMock(content=json.dumps(valid_dict)),
            ]
        )

        state = {
            "user_input": "Scan subscription sub-retry",
            "llm": mock_llm,
        }

        result = asyncio.run(interpret_request(state))
        assert result.get("scan_request") is not None
        assert result["scan_request"].cloud_account_id == "sub-retry"


# ---------------------------------------------------------------------------
# T-4-2: cis_agent.py — build_policy (mocked LLM)
# ---------------------------------------------------------------------------

class TestBuildPolicy:
    """Tests for cis_agent.build_policy node."""

    def test_valid_llm_response_sets_report_policy(self):
        """build_policy with mocked LLM sets state['report_policy']."""
        from backend.app.agents.cis_agent import build_policy

        valid_policy_dict = {
            "title": "CIS Azure L1",
            "audience": "Security Team",
            "benchmark": "cis_2.0_azure",
            "filter": {"only_failed": True},
            "include_remediation": True,
            "include_compliance_overview": True,
        }

        mock_llm = AsyncMock()
        mock_llm.ainvoke = AsyncMock(
            return_value=MagicMock(content=json.dumps(valid_policy_dict))
        )

        state = {
            "scan_request": _make_scan_request(),
            "llm": mock_llm,
        }

        result = asyncio.run(build_policy(state))
        assert "report_policy" in result
        assert isinstance(result["report_policy"], ReportPolicy)
        assert result["report_policy"].title == "CIS Azure L1"


# ---------------------------------------------------------------------------
# T-4-3 (spec CIS-3): apply_filter — pure deterministic logic tests
# ---------------------------------------------------------------------------

class TestApplyFilter:
    """
    Tests for cis_agent.apply_filter — pure logic, no LLM.
    Spec CIS-3: filtering MUST be deterministic given same input.
    Spec CIS-4: MUST NOT invent findings.
    """

    def test_severity_filter_removes_low_severity(self):
        """Only findings at or above min_severity should remain."""
        from backend.app.agents.cis_agent import apply_filter

        findings = [
            _make_finding("high_check", severity=Severity.HIGH, status=FindingStatus.FAIL),
            _make_finding("low_check", severity=Severity.LOW, status=FindingStatus.FAIL),
            _make_finding("medium_check", severity=Severity.MEDIUM, status=FindingStatus.FAIL),
        ]
        normalized = _make_normalized(findings)
        criteria = FilterCriteria(min_severity=Severity.HIGH)

        result = apply_filter(normalized, criteria)

        check_ids = [f.check_id for f in result.security_findings]
        assert "high_check" in check_ids
        assert "low_check" not in check_ids
        assert "medium_check" not in check_ids

    def test_only_failed_filter(self):
        """only_failed=True must exclude PASS and MANUAL findings."""
        from backend.app.agents.cis_agent import apply_filter

        findings = [
            _make_finding("fail_1", status=FindingStatus.FAIL),
            _make_finding("pass_1", status=FindingStatus.PASS),
            _make_finding("manual_1", status=FindingStatus.MANUAL),
        ]
        normalized = _make_normalized(findings)
        criteria = FilterCriteria(only_failed=True)

        result = apply_filter(normalized, criteria)

        assert all(f.status == FindingStatus.FAIL for f in result.security_findings)
        assert len(result.security_findings) == 1

    def test_max_findings_truncation(self):
        """When filter has max_findings, result must not exceed that count."""
        from backend.app.agents.cis_agent import apply_filter

        findings = [_make_finding(f"check_{i}") for i in range(20)]
        normalized = _make_normalized(findings)
        criteria = FilterCriteria()  # no filters
        # max_findings is passed as a kwarg in this design
        result = apply_filter(normalized, criteria, max_findings=5)

        assert len(result.security_findings) <= 5

    def test_no_findings_returns_empty(self):
        """Filter with no matches returns empty findings list, not an error."""
        from backend.app.agents.cis_agent import apply_filter

        findings = [
            _make_finding("low_check", severity=Severity.LOW, status=FindingStatus.PASS),
        ]
        normalized = _make_normalized(findings)
        # Filter for CRITICAL only → no matches
        criteria = FilterCriteria(min_severity=Severity.CRITICAL, only_failed=True)

        result = apply_filter(normalized, criteria)

        assert isinstance(result, NormalizedFindings)
        assert result.security_findings == []
        assert result.summary.total == 0

    def test_does_not_invent_findings(self):
        """apply_filter must never return findings not in the original normalized input."""
        from backend.app.agents.cis_agent import apply_filter

        findings = [_make_finding(f"real_{i}") for i in range(3)]
        normalized = _make_normalized(findings)
        criteria = FilterCriteria()

        result = apply_filter(normalized, criteria)

        original_ids = {f.finding_id for f in findings}
        result_ids = {f.finding_id for f in result.security_findings}
        assert result_ids.issubset(original_ids), (
            "apply_filter returned findings not in original input — CIS-4 violation"
        )

    def test_include_controls_filter(self):
        """include_controls filters to only specified control IDs."""
        from backend.app.agents.cis_agent import apply_filter

        findings = [
            _make_finding("included_check"),
            _make_finding("excluded_check"),
        ]
        # Set compliance so include_controls can filter
        findings[0] = findings[0].model_copy(update={"check_id": "iam_001", "compliance": {"CIS-2.0": ["1.1"]}})
        findings[1] = findings[1].model_copy(update={"check_id": "net_001", "compliance": {"CIS-2.0": ["6.1"]}})
        normalized = _make_normalized(findings)
        criteria = FilterCriteria(include_controls=["1.1"])

        result = apply_filter(normalized, criteria)

        check_ids = [f.check_id for f in result.security_findings]
        assert "iam_001" in check_ids
        assert "net_001" not in check_ids

    def test_exclude_controls_filter(self):
        """exclude_controls removes findings matching those control IDs."""
        from backend.app.agents.cis_agent import apply_filter

        findings = [
            _make_finding("keep_check"),
            _make_finding("drop_check"),
        ]
        findings[0] = findings[0].model_copy(update={"check_id": "iam_001", "compliance": {"CIS-2.0": ["1.1"]}})
        findings[1] = findings[1].model_copy(update={"check_id": "net_001", "compliance": {"CIS-2.0": ["6.1"]}})
        normalized = _make_normalized(findings)
        criteria = FilterCriteria(exclude_controls=["6.1"])

        result = apply_filter(normalized, criteria)

        check_ids = [f.check_id for f in result.security_findings]
        assert "iam_001" in check_ids
        assert "net_001" not in check_ids


# ---------------------------------------------------------------------------
# Boundary guard: no subprocess/mcp imports in agent files (CIS-1)
# ---------------------------------------------------------------------------

class TestAgentBoundaryGuards:
    """
    Spec CIS-1: cis_agent.py MUST NOT import subprocess, mcp, mcp_client,
    or any Prowler module.
    """

    FORBIDDEN_MODULES = ["subprocess", "mcp", "mcp_client", "MCP_SERVER", "prowler"]

    def _check_no_forbidden_imports(self, filepath: str) -> None:
        source = Path(filepath).read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    names = [alias.name or "" for alias in node.names]
                else:
                    names = [node.module or ""]
                for name in names:
                    for forbidden in self.FORBIDDEN_MODULES:
                        assert forbidden not in name, (
                            f"{filepath} must NOT import {forbidden!r} — found: {name!r}"
                        )

    def test_cis_agent_no_subprocess(self):
        self._check_no_forbidden_imports("backend/app/agents/cis_agent.py")

    def test_doc_agent_no_subprocess(self):
        self._check_no_forbidden_imports("backend/app/agents/doc_agent.py")

    def test_llm_helper_no_subprocess(self):
        self._check_no_forbidden_imports("backend/app/agents/_llm.py")


# ---------------------------------------------------------------------------
# PR 2: AWS prompts in cis_agent (RENAME-2 spec)
# ---------------------------------------------------------------------------

class TestCISAgentAWSPrompts:
    """
    Spec RENAME-2: cis_agent.interpret_request and build_policy prompts must
    include 'aws' as a provider option and at least one AWS CIS benchmark string.
    """

    def test_interpret_request_prompt_includes_aws_provider(self):
        """The interpret_request prompt must list 'aws' as a valid provider."""
        import inspect
        from backend.app.agents import cis_agent
        source = inspect.getsource(cis_agent.interpret_request)
        assert "'aws'" in source or '"aws"' in source, (
            "interpret_request prompt must include 'aws' as a valid provider option"
        )

    def test_interpret_request_prompt_includes_aws_benchmark(self):
        """The interpret_request prompt must list at least one AWS CIS benchmark."""
        import inspect
        from backend.app.agents import cis_agent
        source = inspect.getsource(cis_agent.interpret_request)
        assert "cis_aws_foundations_benchmark" in source, (
            "interpret_request prompt must include at least one AWS CIS benchmark string"
        )

    def test_build_policy_prompt_references_aws_aware_benchmark(self):
        """build_policy prompt uses scan_request.benchmark.value — which can now be AWS."""
        import inspect
        from backend.app.agents import cis_agent
        # build_policy uses scan_request.benchmark.value dynamically — it's inherently
        # AWS-aware. Assert the function source does NOT hard-code azure-only benchmarks.
        source = inspect.getsource(cis_agent.build_policy)
        # The fallback policy title now mentions a generic "Security Report" not hard-coded Azure
        assert "cis_azure_foundations_benchmark_v2.0" not in source, (
            "build_policy must not hard-code the Azure benchmark — it should use scan_request.benchmark.value"
        )
