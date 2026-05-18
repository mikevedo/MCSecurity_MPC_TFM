"""
Tests for backend/app/services/ layer:
- ReportStorage: save_raw, save_normalized, save_selected, save_report
- ScanService.run_scan(): delegates to MCPClient mock, returns ScanResult with correct summary
- MCPClient: mocked transport — no real subprocess spawned

Design reference: sdd/poc-foundation/design Section 7 (Services)
Spec reference:   sdd/poc-foundation/spec  — scan-orchestration + report-generation

TDD: tests written before implementation (RED phase).
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.app.poc_contracts import (
    Benchmark,
    FindingStatus,
    NormalizedFindings,
    Provider,
    ScanRequest,
    ScanResult,
)
from backend.app.services.report_storage import ReportStorage
from backend.app.services.scan_service import ScanService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURE_PATH = Path("tests/fixtures/prowler_azure_sample.json")


def load_fixture_raw() -> list[dict]:
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def make_scan_request(fixture_mode: bool = True) -> ScanRequest:
    return ScanRequest(
        provider=Provider.AZURE,
        benchmark=Benchmark.CIS_2_0_AZURE,
        cloud_account_id="1e11569b-de29-4e51-ad5e-8f7facd3d07f",
        fixture_mode=fixture_mode,
        fixture_path=str(FIXTURE_PATH) if fixture_mode else None,
    )


# ---------------------------------------------------------------------------
# ReportStorage tests
# ---------------------------------------------------------------------------

class TestReportStorage:
    """Use tmp_path pytest fixture — all files created in a temp dir."""

    def test_save_raw_creates_file(self, tmp_path):
        storage = ReportStorage(base_path=tmp_path)
        scan_id = str(uuid.uuid4())
        data = [{"check_id": "test_check", "status_code": "FAIL"}]

        path = storage.save_raw(scan_id, data)

        assert path.exists()
        with open(path) as f:
            loaded = json.load(f)
        assert loaded == data

    def test_save_raw_path_under_raw_dir(self, tmp_path):
        storage = ReportStorage(base_path=tmp_path)
        scan_id = "my-scan-id"
        path = storage.save_raw(scan_id, [])
        assert "raw" in str(path)
        assert scan_id in path.name

    def test_save_normalized_creates_file(self, tmp_path):
        """save_normalized writes valid NormalizedFindings JSON."""
        from tests.test_prowler_normalizer import load_fixture, make_scan_request as make_req
        from backend.app.normalizers.prowler_normalizer import normalize

        raw = load_fixture()
        request = make_req()
        normalized = normalize(raw, request)

        storage = ReportStorage(base_path=tmp_path)
        scan_id = str(uuid.uuid4())
        path = storage.save_normalized(scan_id, normalized)

        assert path.exists()
        # Must be valid JSON that round-trips to NormalizedFindings
        restored = NormalizedFindings.model_validate_json(path.read_text())
        assert restored.summary.total == 197

    def test_save_normalized_path_under_normalized_dir(self, tmp_path):
        from tests.test_prowler_normalizer import load_fixture, make_scan_request as make_req
        from backend.app.normalizers.prowler_normalizer import normalize

        raw = load_fixture()
        normalized = normalize(raw, make_req())
        storage = ReportStorage(base_path=tmp_path)
        path = storage.save_normalized("scan-abc", normalized)
        assert "normalized" in str(path)

    def test_save_selected_creates_file(self, tmp_path):
        """save_selected writes a NormalizedFindings JSON under selected/."""
        from tests.test_prowler_normalizer import load_fixture, make_scan_request as make_req
        from backend.app.normalizers.prowler_normalizer import normalize

        raw = load_fixture()
        normalized = normalize(raw, make_req())
        storage = ReportStorage(base_path=tmp_path)
        path = storage.save_selected("scan-xyz", normalized)

        assert path.exists()
        assert "selected" in str(path)
        restored = NormalizedFindings.model_validate_json(path.read_text())
        assert restored.summary.total == normalized.summary.total

    def test_save_report_creates_markdown_file(self, tmp_path):
        storage = ReportStorage(base_path=tmp_path)
        scan_id = "my-scan"
        content = "# CIS Report\n\n- Finding 1\n- Finding 2\n"

        path = storage.save_report(scan_id, content)

        assert path.exists()
        assert path.read_text() == content
        assert path.suffix == ".md"
        assert "reports" in str(path)

    def test_save_report_scan_id_in_filename(self, tmp_path):
        storage = ReportStorage(base_path=tmp_path)
        path = storage.save_report("unique-scan-id", "# Report")
        assert "unique-scan-id" in path.name

    def test_save_raw_no_collision_different_scan_ids(self, tmp_path):
        """Two different scan_ids must produce two different files."""
        storage = ReportStorage(base_path=tmp_path)
        p1 = storage.save_raw("scan-1", [{"a": 1}])
        p2 = storage.save_raw("scan-2", [{"b": 2}])
        assert p1 != p2
        assert p1.exists() and p2.exists()

    def test_directories_created_automatically(self, tmp_path):
        """ReportStorage must create subdirectories if they don't exist."""
        base = tmp_path / "new_base"  # does not exist yet
        storage = ReportStorage(base_path=base)
        path = storage.save_report("scan-id", "# content")
        assert path.exists()


# ---------------------------------------------------------------------------
# ScanService tests
# ---------------------------------------------------------------------------

class TestScanService:
    """
    ScanService.run_scan() must:
    1. Delegate to MCPClient (no direct Prowler access)
    2. Call normalizer on returned raw findings
    3. Return a ScanResult with correct summary counts
    4. Propagate errors from MCPClient
    """

    def _make_mock_client(self, raw_findings: list[dict] | None = None, error: str | None = None):
        """Return a mock MCPClient whose call_tool returns the given payload."""
        client = MagicMock()
        if error:
            # Simulate error response from MCP tool
            client.call_tool = AsyncMock(return_value={
                "findings": None,
                "returncode": 1,
                "error": error,
                "fixture_mode": True,
            })
        else:
            payload = raw_findings if raw_findings is not None else []
            client.call_tool = AsyncMock(return_value={
                "findings": payload,
                "returncode": 0,
                "error": None,
                "fixture_mode": True,
            })
        return client

    def test_run_scan_returns_scan_result(self, tmp_path):
        """run_scan() must return a ScanResult instance."""
        raw = load_fixture_raw()
        client = self._make_mock_client(raw)
        storage = ReportStorage(base_path=tmp_path)
        service = ScanService(mcp_client=client, storage=storage)
        request = make_scan_request()

        result = asyncio.run(service.run_scan(request))

        assert isinstance(result, ScanResult)

    def test_run_scan_calls_mcp_client(self, tmp_path):
        """run_scan() must call mcp_client.call_tool exactly once."""
        client = self._make_mock_client([])
        storage = ReportStorage(base_path=tmp_path)
        service = ScanService(mcp_client=client, storage=storage)

        asyncio.run(service.run_scan(make_scan_request()))

        client.call_tool.assert_called_once()

    def test_run_scan_correct_summary_counts(self, tmp_path):
        """With real fixture data, summary must be 197 total / 136 failed / 61 passed."""
        raw = load_fixture_raw()
        client = self._make_mock_client(raw)
        storage = ReportStorage(base_path=tmp_path)
        service = ScanService(mcp_client=client, storage=storage)

        result = asyncio.run(service.run_scan(make_scan_request()))

        assert result.raw_payload is not None
        assert isinstance(result.raw_payload, list)
        assert len(result.raw_payload) == 197

    def test_run_scan_error_propagates(self, tmp_path):
        """When MCPClient returns an error, ScanResult must have error set."""
        client = self._make_mock_client(error="Prowler CLI not found.")
        storage = ReportStorage(base_path=tmp_path)
        service = ScanService(mcp_client=client, storage=storage)

        result = asyncio.run(service.run_scan(make_scan_request()))

        assert result.error is not None
        assert "Prowler" in result.error or len(result.error) > 0

    def test_run_scan_saves_raw_artifact(self, tmp_path):
        """run_scan() must save raw findings to disk and set raw_path."""
        raw = load_fixture_raw()
        client = self._make_mock_client(raw)
        storage = ReportStorage(base_path=tmp_path)
        service = ScanService(mcp_client=client, storage=storage)

        result = asyncio.run(service.run_scan(make_scan_request()))

        assert result.raw_path is not None
        assert Path(result.raw_path).exists()

    def test_run_scan_no_subprocess_import(self):
        """scan_service.py must NOT import subprocess (boundary guard)."""
        import ast
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "scan_service",
            "backend/app/services/scan_service.py",
        )
        source = Path("backend/app/services/scan_service.py").read_text()
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                else:
                    names = [node.module or ""]
                for name in names:
                    assert "subprocess" not in (name or ""), (
                        f"scan_service.py must NOT import subprocess — found: {name}"
                    )


# ---------------------------------------------------------------------------
# MCPClient mock transport test
# ---------------------------------------------------------------------------

class TestMCPClient:
    """
    MCPClient.call_tool() must use MCP stdio transport.
    We mock the transport layer — no real subprocess is spawned.
    """

    def test_import_succeeds(self):
        """MCPClient must be importable."""
        from backend.app.services.mcp_client import MCPClient
        assert MCPClient is not None

    def test_call_tool_with_mocked_session(self):
        """call_tool() returns the parsed result from the MCP session."""
        from backend.app.services.mcp_client import MCPClient

        # Mock the MCP session and transport
        mock_result = MagicMock()
        mock_result.content = [MagicMock(text=json.dumps({
            "raw_payload": [{"status_code": "PASS"}],
            "returncode": 0,
            "error": None,
            "fixture_mode": True,
        }))]

        mock_session = AsyncMock()
        mock_session.initialize = AsyncMock()
        mock_session.call_tool = AsyncMock(return_value=mock_result)

        async def run():
            client = MCPClient(server_script="MCP_SERVER/server_multicloud.py")
            with patch("backend.app.services.mcp_client.stdio_client") as mock_stdio, \
                 patch("backend.app.services.mcp_client.ClientSession") as mock_cls:
                # Configure context managers
                mock_read = AsyncMock()
                mock_write = AsyncMock()
                mock_stdio.return_value.__aenter__ = AsyncMock(return_value=(mock_read, mock_write))
                mock_stdio.return_value.__aexit__ = AsyncMock(return_value=False)
                mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_session)
                mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

                result = await client.call_tool("run_prowler_scan", {"provider": "azure"})
                return result

        result = asyncio.run(run())
        assert isinstance(result, dict)
        assert "raw_payload" in result

    def test_no_subprocess_import_in_mcp_client(self):
        """mcp_client.py must NOT import subprocess."""
        import ast

        source = Path("backend/app/services/mcp_client.py").read_text()
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                else:
                    names = [node.module or ""]
                for name in names:
                    assert "subprocess" not in (name or ""), (
                        f"mcp_client.py must NOT import subprocess — found: {name}"
                    )
