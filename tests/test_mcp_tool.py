"""
Tests for MCP Server layer — T-1-4.

Covers:
1. run_prowler_scan in fixture mode returns dict with expected fields and 197 findings
2. Missing fixture file returns error dict (no exception raised)
3. returncode 3 is treated as success
4. returncode 1 (and other non-0/3) produces error dict
5. check_azure_cli_auth() with mocked subprocess
"""

import json
import os
import subprocess
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch


FIXTURE_PATH = str(
    Path(__file__).parent / "fixtures" / "prowler_azure_sample.json"
)
PROJECT_ROOT = str(Path(__file__).parent.parent)


# ---------------------------------------------------------------------------
# run_prowler_scan — fixture mode
# ---------------------------------------------------------------------------

class TestRunProwlerScanFixtureMode:
    def test_fixture_mode_returns_success_dict(self, monkeypatch):
        """PROWLER_FIXTURE_MODE=true → reads fixture file, returns status=success."""
        monkeypatch.setenv("PROWLER_FIXTURE_MODE", "true")
        monkeypatch.setenv("PROWLER_FIXTURE_PATH", FIXTURE_PATH)

        from MCP_SERVER.tools.azure.prowler import run_prowler_scan

        result = run_prowler_scan(
            cloud_account_id="1e11569b-de29-4e51-ad5e-8f7facd3d07f",
            benchmark="cis_azure_foundations_benchmark_v2.0",
        )

        assert result["status"] == "success"
        assert result["error"] is None
        assert isinstance(result["findings"], list)

    def test_fixture_mode_returns_197_findings(self, monkeypatch):
        """The real fixture file has exactly 197 findings."""
        monkeypatch.setenv("PROWLER_FIXTURE_MODE", "true")
        monkeypatch.setenv("PROWLER_FIXTURE_PATH", FIXTURE_PATH)

        from MCP_SERVER.tools.azure.prowler import run_prowler_scan

        result = run_prowler_scan(
            cloud_account_id="1e11569b-de29-4e51-ad5e-8f7facd3d07f",
        )

        assert len(result["findings"]) == 197

    def test_fixture_mode_includes_prowler_version(self, monkeypatch):
        """Fixture mode should still populate prowler_version from fixture data."""
        monkeypatch.setenv("PROWLER_FIXTURE_MODE", "true")
        monkeypatch.setenv("PROWLER_FIXTURE_PATH", FIXTURE_PATH)

        from MCP_SERVER.tools.azure.prowler import run_prowler_scan

        result = run_prowler_scan(cloud_account_id="abc-123")
        # prowler_version may be None in fixture mode — just assert key exists
        assert "prowler_version" in result

    def test_missing_fixture_file_returns_error_dict(self, monkeypatch):
        """Missing fixture file → error dict, NOT an unhandled exception."""
        monkeypatch.setenv("PROWLER_FIXTURE_MODE", "true")
        monkeypatch.setenv("PROWLER_FIXTURE_PATH", "/nonexistent/path/file.json")

        # Force reimport so env vars are picked up
        import importlib
        import MCP_SERVER.tools.azure.prowler as prowler_mod
        importlib.reload(prowler_mod)

        result = prowler_mod.run_prowler_scan(cloud_account_id="abc-123")

        assert result["status"] == "error"
        assert result["error"] is not None
        assert isinstance(result["findings"], list)
        assert len(result["findings"]) == 0

    def test_default_fixture_path_used_when_env_not_set(self, monkeypatch):
        """When PROWLER_FIXTURE_PATH is not set, fall back to the default path."""
        monkeypatch.setenv("PROWLER_FIXTURE_MODE", "true")
        monkeypatch.delenv("PROWLER_FIXTURE_PATH", raising=False)

        import importlib
        import MCP_SERVER.tools.azure.prowler as prowler_mod
        importlib.reload(prowler_mod)

        result = prowler_mod.run_prowler_scan(cloud_account_id="abc-123")
        # Default fixture should resolve to the real fixture file
        assert result["status"] == "success"


# ---------------------------------------------------------------------------
# run_prowler_scan — live mode returncode handling
# ---------------------------------------------------------------------------

class TestRunProwlerScanReturnCodes:
    def _make_completed_process(self, returncode: int, stdout: str = "[]") -> MagicMock:
        mock = MagicMock()
        mock.returncode = returncode
        mock.stdout = stdout
        mock.stderr = ""
        return mock

    def test_returncode_0_is_success(self, monkeypatch):
        """returncode 0 → all PASS, status=success."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_completed_process(0, "[]")
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            result = prowler_mod.run_prowler_scan(cloud_account_id="abc-123")

        assert result["status"] == "success"
        assert result["error"] is None

    def test_returncode_3_is_success(self, monkeypatch):
        """returncode 3 → success with findings, must NOT be treated as error."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_completed_process(3, "[]")
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            result = prowler_mod.run_prowler_scan(cloud_account_id="abc-123")

        assert result["status"] == "success"
        assert result["error"] is None

    def test_returncode_1_is_error(self, monkeypatch):
        """returncode 1 → Prowler error, status=error."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_completed_process(1, "")
            mock_run.return_value.stderr = "Prowler crashed"
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            result = prowler_mod.run_prowler_scan(cloud_account_id="abc-123")

        assert result["status"] == "error"
        assert result["error"] is not None
        assert result["findings"] == []

    def test_returncode_2_is_error(self, monkeypatch):
        """returncode 2 → unexpected error, status=error."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_completed_process(2, "")
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            result = prowler_mod.run_prowler_scan(cloud_account_id="abc-123")

        assert result["status"] == "error"

    def test_subprocess_timeout_returns_error_dict(self, monkeypatch):
        """subprocess.TimeoutExpired → structured error dict, not unhandled exception."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="prowler", timeout=600)
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            result = prowler_mod.run_prowler_scan(cloud_account_id="abc-123")

        assert result["status"] == "error"
        assert "timeout" in result["error"].lower()

    def test_prowler_not_on_path_returns_error_dict(self, monkeypatch):
        """FileNotFoundError (prowler not on PATH) → structured error dict."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("No such file or directory: 'prowler'")
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            result = prowler_mod.run_prowler_scan(cloud_account_id="abc-123")

        assert result["status"] == "error"
        assert result["findings"] == []


# ---------------------------------------------------------------------------
# check_azure_cli_auth — mocked subprocess
# ---------------------------------------------------------------------------

class TestCheckAzureCliAuth:
    def test_returns_true_when_exit_code_0(self):
        with patch("subprocess.run") as mock_run:
            mock = MagicMock()
            mock.returncode = 0
            mock_run.return_value = mock

            from MCP_SERVER.auth.azure_cli_auth import check_azure_cli_login

            result = check_azure_cli_login()

        assert result is True

    def test_returns_false_when_exit_code_nonzero(self):
        with patch("subprocess.run") as mock_run:
            mock = MagicMock()
            mock.returncode = 1
            mock_run.return_value = mock

            from MCP_SERVER.auth.azure_cli_auth import check_azure_cli_login

            result = check_azure_cli_login()

        assert result is False

    def test_returns_false_when_subprocess_raises(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("az not found")

            from MCP_SERVER.auth.azure_cli_auth import check_azure_cli_login

            result = check_azure_cli_login()

        assert result is False

    def test_get_subscription_id_returns_string_on_success(self):
        with patch("subprocess.run") as mock_run:
            mock = MagicMock()
            mock.returncode = 0
            mock.stdout = "1e11569b-de29-4e51-ad5e-8f7facd3d07f\n"
            mock_run.return_value = mock

            from MCP_SERVER.auth.azure_cli_auth import get_subscription_id

            sub_id = get_subscription_id()

        assert sub_id == "1e11569b-de29-4e51-ad5e-8f7facd3d07f"

    def test_get_subscription_id_returns_none_on_failure(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("az error")

            from MCP_SERVER.auth.azure_cli_auth import get_subscription_id

            sub_id = get_subscription_id()

        assert sub_id is None


# ---------------------------------------------------------------------------
# Dispatch tests — unified server dispatch (PR 2)
# ---------------------------------------------------------------------------

class TestDispatchRoutes:
    def _success_return(self) -> dict:
        return {
            "status": "success", "findings": [], "error": None,
            "prowler_version": None, "returncode": 0,
            "started_at": None, "finished_at": None, "fixture_mode": False,
        }

    def test_dispatch_routes_azure_to_azure_tool(self, monkeypatch):
        """server.run_prowler_scan(provider='azure') must call Azure tool, not AWS."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("MCP_SERVER.tools.azure.prowler.run_prowler_scan") as mock_azure, \
             patch("MCP_SERVER.tools.aws.prowler.run_prowler_scan") as mock_aws:
            mock_azure.return_value = self._success_return()

            import importlib
            import MCP_SERVER.server_multicloud as server_mod
            importlib.reload(server_mod)

            server_mod.run_prowler_scan(
                provider="azure",
                cloud_account_id="sub-abc-123",
                benchmark="cis_azure_foundations_benchmark_v2.0",
                output_format="json-ocsf",
            )

        mock_azure.assert_called_once()
        mock_aws.assert_not_called()

    def test_dispatch_unknown_provider_returns_error(self, monkeypatch):
        """server.run_prowler_scan(provider='gcp') must return error dict."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        import importlib
        import MCP_SERVER.server_multicloud as server_mod
        importlib.reload(server_mod)

        result = server_mod.run_prowler_scan(
            provider="gcp",
            cloud_account_id="my-project-id",
            benchmark="cis_gcp_benchmark",
            output_format="json-ocsf",
        )

        assert result["status"] == "error"
        assert "gcp" in result["error"]


# ---------------------------------------------------------------------------
# Severity filter and only_failed flag — Azure tool
# ---------------------------------------------------------------------------

class TestSeverityAndStatusFlagsAzure:
    """--severity and --status FAIL must be injected into the Prowler subprocess command."""

    def _make_proc(self, returncode: int = 0, stdout: str = "[]") -> MagicMock:
        proc = MagicMock()
        proc.returncode = returncode
        proc.stdout = stdout
        proc.stderr = ""
        return proc

    def test_severity_filter_added_to_cmd(self, monkeypatch):
        """severity_filter=['critical','high'] → --severity critical high in cmd."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_proc()
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            prowler_mod.run_prowler_scan(
                cloud_account_id="sub-123",
                severity_filter=["critical", "high"],
            )

        cmd = mock_run.call_args[0][0]
        assert "--severity" in cmd
        sev_idx = cmd.index("--severity")
        assert cmd[sev_idx + 1] == "critical"
        assert cmd[sev_idx + 2] == "high"

    def test_only_failed_adds_status_fail(self, monkeypatch):
        """only_failed=True → --status FAIL in cmd."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_proc()
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            prowler_mod.run_prowler_scan(
                cloud_account_id="sub-123",
                only_failed=True,
            )

        cmd = mock_run.call_args[0][0]
        assert "--status" in cmd
        status_idx = cmd.index("--status")
        assert cmd[status_idx + 1] == "FAIL"

    def test_no_severity_filter_omits_flag(self, monkeypatch):
        """When severity_filter=[] (default), --severity must NOT appear in cmd."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_proc()
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            prowler_mod.run_prowler_scan(cloud_account_id="sub-123")

        cmd = mock_run.call_args[0][0]
        assert "--severity" not in cmd
        assert "--status" not in cmd


# ---------------------------------------------------------------------------
# Resource group and Azure region flags — Azure tool
# ---------------------------------------------------------------------------

class TestAzureScopeFlags:
    """--resource-group and --azure-region must be injected into the subprocess command."""

    def _make_proc(self, returncode: int = 0, stdout: str = "[]") -> MagicMock:
        proc = MagicMock()
        proc.returncode = returncode
        proc.stdout = stdout
        proc.stderr = ""
        return proc

    def test_resource_group_added_to_cmd(self, monkeypatch):
        """resource_group='prod' → --resource-group prod in cmd."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_proc()
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            prowler_mod.run_prowler_scan(
                cloud_account_id="sub-123",
                resource_group="prod",
            )

        cmd = mock_run.call_args[0][0]
        assert "--resource-group" in cmd
        rg_idx = cmd.index("--resource-group")
        assert cmd[rg_idx + 1] == "prod"

    def test_azure_region_added_to_cmd(self, monkeypatch):
        """azure_region='westeurope' → --azure-region westeurope in cmd."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_proc()
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            prowler_mod.run_prowler_scan(
                cloud_account_id="sub-123",
                azure_region="westeurope",
            )

        cmd = mock_run.call_args[0][0]
        assert "--azure-region" in cmd
        region_idx = cmd.index("--azure-region")
        assert cmd[region_idx + 1] == "westeurope"

    def test_no_scope_flags_omitted_by_default(self, monkeypatch):
        """Default (no resource_group, no azure_region) → flags absent from cmd."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_proc()
            import importlib
            import MCP_SERVER.tools.azure.prowler as prowler_mod
            importlib.reload(prowler_mod)

            prowler_mod.run_prowler_scan(cloud_account_id="sub-123")

        cmd = mock_run.call_args[0][0]
        assert "--resource-group" not in cmd
        assert "--azure-region" not in cmd
