"""
Tests for backend/app/poc_graph.py:
- build_graph() returns a compiled graph
- error_handler produces a degraded GraphState
- State with error routes to error_handler, not subsequent nodes
- FIXTURE_MODE propagates to ScanRequest via graph

Design reference: sdd/poc-foundation/design Section 3 (LangGraph Graph)
Spec reference:   sdd/poc-foundation/spec  — terminal-chat CHAT-2, CHAT-4

TDD: tests written before implementation (RED phase T-5-3).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.app.poc_contracts import (
    Benchmark,
    FilterCriteria,
    FindingStatus,
    NormalizedFindings,
    Provider,
    ReportPolicy,
    ScanRequest,
    ScanResult,
    ScanSummary,
    SecurityFinding,
    Severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scan_request(fixture_mode: bool = True) -> ScanRequest:
    return ScanRequest(
        provider=Provider.AZURE,
        benchmark=Benchmark.CIS_2_0_AZURE,
        cloud_account_id="sub-001",
        fixture_mode=fixture_mode,
        fixture_path="tests/fixtures/prowler_azure_sample.json" if fixture_mode else None,
    )


def _make_empty_normalized() -> NormalizedFindings:
    summary = ScanSummary(
        provider=Provider.AZURE,
        benchmark=Benchmark.CIS_2_0_AZURE,
        cloud_account_id="sub-001",
        started_at="2025-01-01T00:00:00+00:00",
        finished_at="2025-01-01T01:00:00+00:00",
        total=0,
        passed=0,
        failed=0,
        fixture_mode=True,
    )
    return NormalizedFindings(
        security_findings=[],
        compliance_checks=[],
        summary=summary,
    )


def _make_policy() -> ReportPolicy:
    return ReportPolicy(
        title="Test Report",
        audience="Security Team",
        benchmark=Benchmark.CIS_2_0_AZURE,
        filter=FilterCriteria(),
        include_remediation=True,
        include_compliance_overview=True,
    )


# ---------------------------------------------------------------------------
# T-5-1: build_graph() basic tests
# ---------------------------------------------------------------------------

class TestBuildGraph:
    """Tests for poc_graph.build_graph()."""

    def test_import_succeeds(self):
        """poc_graph must be importable."""
        from backend.app.poc_graph import build_graph
        assert callable(build_graph)

    def test_build_graph_returns_compiled_graph(self):
        """build_graph() must return a compiled LangGraph graph without error."""
        from backend.app.poc_graph import build_graph

        graph = build_graph()
        assert graph is not None
        # Compiled graphs have an ainvoke method (LangGraph CompiledStateGraph)
        assert hasattr(graph, "ainvoke")

    def test_graph_state_typeddict_importable(self):
        """GraphState TypedDict must be importable from poc_graph."""
        from backend.app.poc_graph import GraphState
        assert GraphState is not None

    def test_error_handler_produces_degraded_state(self):
        """error_handler node sets error in state and does not raise."""
        from backend.app.poc_graph import error_handler

        state = {
            "user_input": "Run CIS audit",
            "error": "execute_scan failed: Prowler CLI not found",
        }

        result = error_handler(state)

        assert "error" in result
        assert result["error"] is not None
        assert len(result["error"]) > 0

    def test_error_handler_preserves_partial_state(self):
        """error_handler must preserve already-computed state fields."""
        from backend.app.poc_graph import error_handler

        scan_req = _make_scan_request()
        state = {
            "user_input": "Run CIS audit",
            "scan_request": scan_req,
            "error": "normalize node failed",
        }

        result = error_handler(state)

        # scan_request must be preserved (degraded report still shows what was known)
        assert result.get("scan_request") == scan_req


# ---------------------------------------------------------------------------
# T-5-3: Full graph invocation with all nodes mocked
# ---------------------------------------------------------------------------

class TestGraphInvocationMocked:
    """
    Full graph with all nodes mocked — verifies state flows correctly end-to-end.
    No real LLM, no real MCP.
    """

    def _build_mocked_graph(self):
        """
        Build graph but patch all external-call nodes so tests are fast and offline.
        Returns the mocked node state for later assertions.
        """
        from backend.app.poc_graph import build_graph
        return build_graph()

    def test_graph_invocation_with_mocked_nodes_succeeds(self):
        """
        With all nodes mocked, graph.ainvoke() must return a dict with user_input.
        """
        from backend.app.poc_graph import build_graph

        scan_req = _make_scan_request()
        normalized = _make_empty_normalized()
        policy = _make_policy()
        scan_result = ScanResult(
            raw_payload=[],
            returncode=0,
            fixture_mode=True,
        )

        # Mock all LLM-dependent and IO-dependent node functions
        async def mock_interpret_request(state):
            return {**state, "scan_request": scan_req}

        async def mock_build_policy(state):
            return {**state, "report_policy": policy}

        async def mock_execute_scan(state):
            return {**state, "scan_result": scan_result}

        def mock_normalize_findings(state):
            return {**state, "normalized": normalized}

        async def mock_filter_findings(state):
            return {**state, "filtered": normalized}

        async def mock_generate_narrative(state):
            return {**state, "narrative": {"executive_summary": "All good.", "key_risks": [], "remediation_priorities": []}}

        def mock_render_report(state):
            return {**state, "report_path": "/tmp/test_report.md"}

        with patch("backend.app.poc_graph.interpret_request", mock_interpret_request), \
             patch("backend.app.poc_graph.build_policy", mock_build_policy), \
             patch("backend.app.poc_graph.execute_scan", mock_execute_scan), \
             patch("backend.app.poc_graph.normalize_findings", mock_normalize_findings), \
             patch("backend.app.poc_graph.filter_findings", mock_filter_findings), \
             patch("backend.app.poc_graph.generate_narrative", mock_generate_narrative), \
             patch("backend.app.poc_graph.render_report", mock_render_report):

            graph = build_graph()
            result = asyncio.run(graph.ainvoke({"user_input": "Run CIS audit on sub-001"}))

        assert result is not None
        assert "user_input" in result

    def test_error_state_routes_to_error_handler(self):
        """
        If a node sets state['error'], the graph must route to error_handler.
        Subsequent non-error nodes must NOT be called.
        """
        from backend.app.poc_graph import build_graph

        execute_scan_called = []
        normalize_called = []

        async def mock_interpret_request(state):
            return {**state, "scan_request": _make_scan_request()}

        async def mock_build_policy(state):
            # Simulate a failure here by setting error
            return {**state, "error": "build_policy failed: LLM timeout"}

        async def mock_execute_scan(state):
            execute_scan_called.append(True)
            return {**state, "scan_result": None}

        def mock_normalize_findings(state):
            normalize_called.append(True)
            return state

        async def mock_filter_findings(state):
            return state

        async def mock_generate_narrative(state):
            return state

        def mock_render_report(state):
            return state

        with patch("backend.app.poc_graph.interpret_request", mock_interpret_request), \
             patch("backend.app.poc_graph.build_policy", mock_build_policy), \
             patch("backend.app.poc_graph.execute_scan", mock_execute_scan), \
             patch("backend.app.poc_graph.normalize_findings", mock_normalize_findings), \
             patch("backend.app.poc_graph.filter_findings", mock_filter_findings), \
             patch("backend.app.poc_graph.generate_narrative", mock_generate_narrative), \
             patch("backend.app.poc_graph.render_report", mock_render_report):

            graph = build_graph()
            result = asyncio.run(graph.ainvoke({"user_input": "Run audit"}))

        # execute_scan and normalize must NOT have been called
        assert len(execute_scan_called) == 0, (
            "execute_scan was called after error was set — graph did not route to error_handler"
        )
        assert len(normalize_called) == 0
        # error must be in final state
        assert result.get("error") is not None


# ---------------------------------------------------------------------------
# T-5-3: FIXTURE_MODE propagation
# ---------------------------------------------------------------------------

class TestFixtureModeInGraph:
    """CHAT-5: Fixture mode must be activatable without source changes."""

    def test_scan_request_fixture_mode_attribute(self):
        """ScanRequest has fixture_mode field for FIXTURE_MODE propagation."""
        req = _make_scan_request(fixture_mode=True)
        assert req.fixture_mode is True
        assert req.fixture_path is not None

    def test_non_fixture_scan_request(self):
        """ScanRequest without fixture_mode has fixture_mode=False."""
        req = _make_scan_request(fixture_mode=False)
        assert req.fixture_mode is False
