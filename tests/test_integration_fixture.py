"""
test_integration_fixture.py — End-to-end integration tests in fixture mode.

Full pipeline: user input → report file.
Mocks: LLM (no Ollama needed), MCP transport (scan_service.run_scan bypassed).
Real: normalizer, filter, graph wiring, Jinja2 render, ReportStorage.

FIXTURE_MODE=1 is set so no real Azure credentials or live Prowler invocations occur.
The real fixture file is used for normalization (tests/fixtures/prowler_azure_sample.json).

Spec reference: sdd/poc-foundation/spec — terminal-chat CHAT-3, CHAT-5
                Integration Happy Path scenario
Design reference: sdd/poc-foundation/design — Section 3 (LangGraph Graph)
Tasks: T-7-2
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.app.poc_contracts import (
    Benchmark,
    FindingStatus,
    Provider,
    ScanRequest,
    ScanResult,
)

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

FIXTURE_PATH = str(Path(__file__).parent / "fixtures" / "prowler_azure_sample.json")
AWS_FIXTURE_PATH = str(Path(__file__).parent / "fixtures" / "prowler_aws_sample.json")
SUBSCRIPTION_ID = "1e11569b-de29-4e51-ad5e-8f7facd3d07f"
AWS_ACCOUNT_ID = "123456789012"


# ---------------------------------------------------------------------------
# Fixture: activate fixture mode for all integration tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def fixture_mode_env(monkeypatch):
    """Set FIXTURE_MODE and PROWLER_FIXTURE_MODE env vars for all tests."""
    monkeypatch.setenv("FIXTURE_MODE", "1")
    monkeypatch.setenv("PROWLER_FIXTURE_MODE", "true")
    monkeypatch.setenv("PROWLER_FIXTURE_PATH", FIXTURE_PATH)
    monkeypatch.setenv("FIXTURE_PATH", FIXTURE_PATH)


# ---------------------------------------------------------------------------
# Helper: build mock LLM returning correct JSON for each pipeline step
# ---------------------------------------------------------------------------


def _build_mock_llm() -> Any:
    """
    Build a mock LLM that returns valid JSON responses for each agent call.

    Pipeline call order:
    1. interpret_request  → ScanRequest JSON
    2. build_policy       → ReportPolicy JSON
    3. generate_narrative → NarrativeSections JSON
    """
    scan_request_json = json.dumps({
        "provider": "azure",
        "benchmark": "cis_2.0_azure",
        "cloud_account_id": SUBSCRIPTION_ID,
        "fixture_mode": True,
        "fixture_path": FIXTURE_PATH,
    })
    report_policy_json = json.dumps({
        "title": "CIS Azure Security Audit",
        "audience": "Security Team",
        "benchmark": "cis_2.0_azure",
        "filter": {
            "only_failed": True,
            "min_severity": None,
            "include_controls": [],
            "exclude_controls": [],
            "resource_types": [],
        },
        "include_remediation": True,
        "include_compliance_overview": True,
    })
    narrative_json = json.dumps({
        "executive_summary": "Integration test summary.",
        "key_risks": ["Risk 1 — iam check failing."],
        "remediation_priorities": ["Enable MFA for all users."],
    })

    responses = [scan_request_json, report_policy_json, narrative_json]
    call_count = 0

    async def mock_ainvoke(prompt: str) -> MagicMock:
        nonlocal call_count
        response = responses[call_count % len(responses)]
        call_count += 1
        m = MagicMock()
        m.content = response
        return m

    mock_llm = AsyncMock()
    mock_llm.ainvoke = mock_ainvoke
    return mock_llm


# ---------------------------------------------------------------------------
# Helper: build mock ScanService.run_scan that reads the fixture directly
# ---------------------------------------------------------------------------


def _make_fixture_scan_result() -> ScanResult:
    """
    Build a ScanResult from the real Azure fixture file.
    Simulates what MCPClient+ScanService would return in fixture mode
    without requiring the MCP transport to be running.
    """
    raw_data = json.loads(Path(FIXTURE_PATH).read_text(encoding="utf-8"))
    return ScanResult(
        raw_payload=raw_data,
        returncode=0,
        fixture_mode=True,
        started_at="2026-05-14T10:00:00+00:00",
        finished_at="2026-05-14T10:05:00+00:00",
    )


def _make_aws_fixture_scan_result() -> ScanResult:
    """
    Build a ScanResult from the AWS fixture file.
    Simulates what MCPClient+ScanService would return for AWS in fixture mode.
    """
    raw_data = json.loads(Path(AWS_FIXTURE_PATH).read_text(encoding="utf-8"))
    return ScanResult(
        raw_payload=raw_data,
        returncode=0,
        fixture_mode=True,
        started_at="2026-05-14T10:00:00+00:00",
        finished_at="2026-05-14T10:05:00+00:00",
    )


def _build_aws_mock_llm() -> Any:
    """
    Build a mock LLM that returns valid JSON for an AWS CIS scan pipeline.
    """
    scan_request_json = json.dumps({
        "provider": "aws",
        "benchmark": "cis_3.0_aws",
        "cloud_account_id": AWS_ACCOUNT_ID,
        "fixture_mode": True,
        "fixture_path": AWS_FIXTURE_PATH,
    })
    report_policy_json = json.dumps({
        "title": "CIS AWS Security Audit",
        "audience": "Security Team",
        "benchmark": "cis_3.0_aws",
        "filter": {
            "only_failed": True,
            "min_severity": None,
            "include_controls": [],
            "exclude_controls": [],
            "resource_types": [],
        },
        "include_remediation": True,
        "include_compliance_overview": True,
    })
    narrative_json = json.dumps({
        "executive_summary": "AWS integration test summary.",
        "key_risks": ["Risk 1 — IAM root hardware MFA not enabled."],
        "remediation_priorities": ["Enable hardware MFA for root account."],
    })

    responses = [scan_request_json, report_policy_json, narrative_json]
    call_count = 0

    async def mock_ainvoke(prompt: str) -> Any:
        nonlocal call_count
        response = responses[call_count % len(responses)]
        call_count += 1
        m = MagicMock()
        m.content = response
        return m

    mock_llm = AsyncMock()
    mock_llm.ainvoke = mock_ainvoke
    return mock_llm


# ---------------------------------------------------------------------------
# T-7-2: End-to-end fixture mode integration test
# ---------------------------------------------------------------------------


class TestFullPipelineFixtureMode:
    """
    Full pipeline tests with fixture mode.

    The MCP transport (ScanService.run_scan) is mocked to return the real
    fixture file content, avoiding the need for a running MCP server.
    All other layers are real: normalizer, filter, graph routing, Jinja2, storage.
    """

    def test_full_graph_produces_report_file(self):
        """
        Full pipeline: user input → report file exists and has valid content.

        Mocks: LLM responses, ScanService.run_scan (returns fixture data directly).
        Real: normalizer, filter, narrative fallback wiring, Jinja2 render, ReportStorage.
        """
        from backend.app.poc_graph import build_graph

        mock_llm = _build_mock_llm()
        scan_result = _make_fixture_scan_result()

        # Patch ScanService.run_scan to bypass the MCP transport layer
        with patch(
            "backend.app.poc_graph.ScanService.run_scan",
            new=AsyncMock(return_value=scan_result),
        ):
            graph = build_graph(llm=mock_llm)
            result = asyncio.run(graph.ainvoke({
                "user_input": f"Run CIS audit on subscription {SUBSCRIPTION_ID}"
            }))

        # No pipeline error
        assert result.get("error") is None, (
            f"Pipeline error: {result.get('error')}"
        )
        # Report path set
        assert result.get("report_path") is not None, (
            "report_path must be set after render_report node"
        )
        # File exists on disk
        report_path = Path(result["report_path"])
        assert report_path.exists(), f"Report file not found: {report_path}"
        # File has meaningful content
        content = report_path.read_text(encoding="utf-8")
        assert "# CIS Security Audit Report" in content, (
            "Report file does not start with expected Markdown heading"
        )
        assert len(content) > 100, "Report content is too short to be valid"

    def test_full_graph_report_under_artifacts_reports(self):
        """Report file must be stored under artifacts/reports/ directory."""
        from backend.app.poc_graph import build_graph

        mock_llm = _build_mock_llm()
        scan_result = _make_fixture_scan_result()

        with patch(
            "backend.app.poc_graph.ScanService.run_scan",
            new=AsyncMock(return_value=scan_result),
        ):
            graph = build_graph(llm=mock_llm)
            result = asyncio.run(graph.ainvoke({
                "user_input": f"Run CIS audit on subscription {SUBSCRIPTION_ID}"
            }))

        assert result.get("error") is None, f"Pipeline error: {result.get('error')}"
        report_path = Path(result["report_path"])
        assert "reports" in str(report_path), (
            f"Report path {report_path} is not under artifacts/reports/"
        )
        assert report_path.suffix == ".md", (
            f"Expected .md file, got: {report_path.suffix}"
        )

    def test_full_graph_report_contains_summary_table(self):
        """Report Markdown must contain the Scan Overview table."""
        from backend.app.poc_graph import build_graph

        mock_llm = _build_mock_llm()
        scan_result = _make_fixture_scan_result()

        with patch(
            "backend.app.poc_graph.ScanService.run_scan",
            new=AsyncMock(return_value=scan_result),
        ):
            graph = build_graph(llm=mock_llm)
            result = asyncio.run(graph.ainvoke({
                "user_input": f"CIS security report for subscription {SUBSCRIPTION_ID}"
            }))

        assert result.get("error") is None, f"Pipeline error: {result.get('error')}"
        report_path = Path(result["report_path"])
        content = report_path.read_text(encoding="utf-8")
        assert "Total Checks" in content, (
            "Report does not contain 'Total Checks' in summary table"
        )

    def test_full_graph_normalized_findings_populated(self):
        """normalized findings must be set in state after normalization node."""
        from backend.app.poc_graph import build_graph

        mock_llm = _build_mock_llm()
        scan_result = _make_fixture_scan_result()

        with patch(
            "backend.app.poc_graph.ScanService.run_scan",
            new=AsyncMock(return_value=scan_result),
        ):
            graph = build_graph(llm=mock_llm)
            result = asyncio.run(graph.ainvoke({
                "user_input": f"CIS Azure report for subscription {SUBSCRIPTION_ID}"
            }))

        assert result.get("error") is None, f"Pipeline error: {result.get('error')}"
        assert result.get("normalized") is not None, (
            "normalized must be set after normalize_findings node"
        )

    def test_full_graph_with_llm_failure_uses_fallback(self):
        """
        When the LLM returns invalid JSON, the pipeline must use fallback defaults
        and still produce a report (or route to error_handler gracefully).
        """
        from backend.app.poc_graph import build_graph

        # Mock LLM always returns invalid JSON
        mock_llm = AsyncMock()
        invalid_response = MagicMock()
        invalid_response.content = "this is not json at all"
        mock_llm.ainvoke = AsyncMock(return_value=invalid_response)

        scan_result = _make_fixture_scan_result()

        with patch(
            "backend.app.poc_graph.ScanService.run_scan",
            new=AsyncMock(return_value=scan_result),
        ):
            graph = build_graph(llm=mock_llm)
            result = asyncio.run(graph.ainvoke({
                "user_input": f"Run audit on {SUBSCRIPTION_ID}"
            }))

        # Pipeline must NOT raise — either recovers or gracefully errors
        assert result is not None, "Graph must return a state dict"
        if result.get("error"):
            assert isinstance(result["error"], str)


# ---------------------------------------------------------------------------
# T-7-2 (PR 2): AWS provider integration test
# ---------------------------------------------------------------------------


class TestAWSFullPipelineFixtureMode:
    """
    Full pipeline tests for the AWS provider in fixture mode.

    Uses the AWS fixture (prowler_aws_sample.json) with a mock LLM returning
    AWS-flavored ScanRequest JSON. Verifies the normalizer, filter, graph routing,
    Jinja2 render, and ReportStorage are all provider-blind.
    """

    def test_aws_full_graph_produces_report_file(self):
        """
        AWS provider pipeline: user input → report file exists and has valid content.

        Mocks: LLM responses (AWS JSON), ScanService.run_scan (returns AWS fixture data).
        Real: normalizer, filter, narrative fallback, Jinja2 render, ReportStorage.
        """
        from backend.app.poc_graph import build_graph

        mock_llm = _build_aws_mock_llm()
        scan_result = _make_aws_fixture_scan_result()

        with patch(
            "backend.app.poc_graph.ScanService.run_scan",
            new=AsyncMock(return_value=scan_result),
        ):
            graph = build_graph(llm=mock_llm)
            result = asyncio.run(graph.ainvoke({
                "user_input": f"Run CIS AWS audit on account {AWS_ACCOUNT_ID}"
            }))

        assert result.get("error") is None, (
            f"AWS pipeline error: {result.get('error')}"
        )
        assert result.get("report_path") is not None
        report_path = Path(result["report_path"])
        assert report_path.exists(), f"Report file not found: {report_path}"
        content = report_path.read_text(encoding="utf-8")
        assert "# CIS Security Audit Report" in content
        assert len(content) > 100

    def test_aws_full_graph_report_under_artifacts_reports(self):
        """AWS report file must be stored under artifacts/reports/ directory."""
        from backend.app.poc_graph import build_graph

        mock_llm = _build_aws_mock_llm()
        scan_result = _make_aws_fixture_scan_result()

        with patch(
            "backend.app.poc_graph.ScanService.run_scan",
            new=AsyncMock(return_value=scan_result),
        ):
            graph = build_graph(llm=mock_llm)
            result = asyncio.run(graph.ainvoke({
                "user_input": f"CIS AWS report for account {AWS_ACCOUNT_ID}"
            }))

        assert result.get("error") is None, f"AWS pipeline error: {result.get('error')}"
        report_path = Path(result["report_path"])
        assert "reports" in str(report_path)
        assert report_path.suffix == ".md"

    def test_aws_full_graph_normalized_findings_populated(self):
        """AWS normalized findings must be set in state after normalization node."""
        from backend.app.poc_graph import build_graph

        mock_llm = _build_aws_mock_llm()
        scan_result = _make_aws_fixture_scan_result()

        with patch(
            "backend.app.poc_graph.ScanService.run_scan",
            new=AsyncMock(return_value=scan_result),
        ):
            graph = build_graph(llm=mock_llm)
            result = asyncio.run(graph.ainvoke({
                "user_input": f"AWS security audit for account {AWS_ACCOUNT_ID}"
            }))

        assert result.get("error") is None, f"AWS pipeline error: {result.get('error')}"
        assert result.get("normalized") is not None


# ---------------------------------------------------------------------------
# T-7-2 (extended): Prowler CLI availability check
# ---------------------------------------------------------------------------


class TestProwlerCLIAvailability:
    """Prowler CLI must be on PATH — no Azure credentials needed."""

    def test_prowler_cli_available(self):
        """Verify Prowler CLI is on PATH."""
        prowler_path = shutil.which("prowler")
        assert prowler_path is not None, (
            "prowler not found on PATH. Install with: pip install prowler"
        )

    def test_prowler_cli_version_output(self):
        """
        Prowler --version must produce output mentioning 'prowler'.
        Verifies the binary is functional without needing Azure credentials.
        """
        result = subprocess.run(
            ["prowler", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        combined_output = result.stdout.lower() + result.stderr.lower()
        assert "prowler" in combined_output, (
            f"prowler --version output did not contain 'prowler'. "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}"
        )
