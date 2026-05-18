"""
Tests for MCP Server AWS layer — PR 2.

Covers:
1. run_prowler_scan (AWS) in fixture mode — happy path, missing file, invalid JSON
2. run_prowler_scan (AWS) live mode — subprocess command construction, returncode handling
3. check_aws_cli_login / get_account_id auth helpers
4. Unified server dispatch routing
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch


AWS_FIXTURE_PATH = str(
    Path(__file__).parent / "fixtures" / "prowler_aws_sample.json"
)
PROJECT_ROOT = str(Path(__file__).parent.parent)


# ---------------------------------------------------------------------------
# TestRunProwlerScanFixtureMode
# ---------------------------------------------------------------------------

class TestRunProwlerScanFixtureMode:
    def test_fixture_mode_returns_success(self, monkeypatch):
        """PROWLER_FIXTURE_MODE=true → reads AWS fixture, returns status=success."""
        monkeypatch.setenv("PROWLER_FIXTURE_MODE", "true")
        monkeypatch.setenv("PROWLER_FIXTURE_PATH", AWS_FIXTURE_PATH)

        from MCP_SERVER.tools.aws.prowler import run_prowler_scan

        result = run_prowler_scan(
            cloud_account_id="123456789012",
            benchmark="cis_aws_foundations_benchmark_v3.0",
            output_format="json-ocsf",
        )

        assert result["status"] == "success"
        assert result["fixture_mode"] is True
        assert isinstance(result["findings"], list)

    def test_fixture_mode_missing_file_returns_error(self, monkeypatch):
        """Missing fixture file → error dict with fixture_mode=True."""
        monkeypatch.setenv("PROWLER_FIXTURE_MODE", "true")
        monkeypatch.setenv("PROWLER_FIXTURE_PATH", "/nonexistent/aws_fixtures.json")

        import importlib
        import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
        importlib.reload(aws_prowler_mod)

        result = aws_prowler_mod.run_prowler_scan(cloud_account_id="123456789012")

        assert result["status"] == "error"
        assert result["fixture_mode"] is True

    def test_fixture_mode_invalid_json_returns_error(self, monkeypatch):
        """Invalid JSON in fixture file → error dict with fixture_mode=True."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as fh:
            fh.write("this is not valid json {{{")
            tmp_path = fh.name

        monkeypatch.setenv("PROWLER_FIXTURE_MODE", "true")
        monkeypatch.setenv("PROWLER_FIXTURE_PATH", tmp_path)

        import importlib
        import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
        importlib.reload(aws_prowler_mod)

        result = aws_prowler_mod.run_prowler_scan(cloud_account_id="123456789012")

        assert result["status"] == "error"
        assert result["fixture_mode"] is True

        import os as _os
        _os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# TestRunProwlerScanReturnCodes
# ---------------------------------------------------------------------------

class TestRunProwlerScanReturnCodes:
    def _make_completed_process(self, returncode: int, stdout: str = "[]") -> MagicMock:
        mock = MagicMock()
        mock.returncode = returncode
        mock.stdout = stdout
        mock.stderr = ""
        return mock

    def test_live_mode_command_contains_required_flags(self, monkeypatch):
        """Live mode command must contain prowler, aws, --compliance, benchmark."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        captured_cmd = []

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return self._make_completed_process(0, "[]")

        with patch("subprocess.run", side_effect=fake_run):
            import importlib
            import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
            importlib.reload(aws_prowler_mod)

            aws_prowler_mod.run_prowler_scan(
                cloud_account_id="",
                benchmark="cis_aws_foundations_benchmark_v3.0",
                output_format="json-ocsf",
            )

        assert "prowler" in captured_cmd
        assert "aws" in captured_cmd
        assert "--compliance" in captured_cmd
        assert "cis_aws_foundations_benchmark_v3.0" in captured_cmd
        assert "--output-formats" in captured_cmd
        assert "json-ocsf" in captured_cmd

    def test_live_mode_includes_aws_account_id_when_provided(self, monkeypatch):
        """When cloud_account_id is non-empty, --aws-account-id must appear in cmd."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        captured_cmd = []

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return self._make_completed_process(0, "[]")

        with patch("subprocess.run", side_effect=fake_run):
            import importlib
            import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
            importlib.reload(aws_prowler_mod)

            aws_prowler_mod.run_prowler_scan(
                cloud_account_id="123456789012",
                benchmark="cis_aws_foundations_benchmark_v3.0",
            )

        assert "--aws-account-id" in captured_cmd
        assert "123456789012" in captured_cmd

    def test_live_mode_omits_aws_account_id_when_empty(self, monkeypatch):
        """When cloud_account_id is empty, --aws-account-id must NOT appear in cmd."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        captured_cmd = []

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return self._make_completed_process(0, "[]")

        with patch("subprocess.run", side_effect=fake_run):
            import importlib
            import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
            importlib.reload(aws_prowler_mod)

            aws_prowler_mod.run_prowler_scan(
                cloud_account_id="",
                benchmark="cis_aws_foundations_benchmark_v3.0",
            )

        assert "--aws-account-id" not in captured_cmd

    def test_live_mode_prowler_not_found_returns_error(self, monkeypatch):
        """FileNotFoundError → error dict with 'not found' in error message."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("No such file or directory: 'prowler'")
            import importlib
            import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
            importlib.reload(aws_prowler_mod)

            result = aws_prowler_mod.run_prowler_scan(cloud_account_id="123456789012")

        assert result["status"] == "error"
        assert "not found" in result["error"].lower() or "prowler" in result["error"].lower()

    def test_live_mode_timeout_returns_error(self, monkeypatch):
        """TimeoutExpired → error dict with 'timeout' in error message."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="prowler", timeout=600)
            import importlib
            import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
            importlib.reload(aws_prowler_mod)

            result = aws_prowler_mod.run_prowler_scan(cloud_account_id="123456789012")

        assert result["status"] == "error"
        assert "timeout" in result["error"].lower()

    def test_live_mode_nonzero_returncode_returns_error(self, monkeypatch):
        """returncode=1 (not in {0,3}) → error dict."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = self._make_completed_process(1, "")
            mock_run.return_value.stderr = "Prowler crashed"
            import importlib
            import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
            importlib.reload(aws_prowler_mod)

            result = aws_prowler_mod.run_prowler_scan(cloud_account_id="123456789012")

        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# TestCheckAwsCliAuth
# ---------------------------------------------------------------------------

class TestCheckAwsCliAuth:
    def test_check_aws_cli_login_returns_true_on_success(self):
        """aws sts get-caller-identity exit 0 → True."""
        with patch("subprocess.run") as mock_run:
            mock = MagicMock()
            mock.returncode = 0
            mock_run.return_value = mock

            from MCP_SERVER.auth.aws_cli_auth import check_aws_cli_login

            result = check_aws_cli_login()

        assert result is True

    def test_check_aws_cli_login_returns_false_on_nonzero(self):
        """aws sts get-caller-identity exit 1 → False."""
        with patch("subprocess.run") as mock_run:
            mock = MagicMock()
            mock.returncode = 1
            mock_run.return_value = mock

            from MCP_SERVER.auth.aws_cli_auth import check_aws_cli_login

            result = check_aws_cli_login()

        assert result is False

    def test_check_aws_cli_login_returns_false_when_not_found(self):
        """FileNotFoundError (aws CLI not on PATH) → False, no exception."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("aws not found")

            from MCP_SERVER.auth.aws_cli_auth import check_aws_cli_login

            result = check_aws_cli_login()

        assert result is False

    def test_get_account_id_returns_account_string(self):
        """Parses 'Account' from aws sts get-caller-identity JSON."""
        with patch("subprocess.run") as mock_run:
            mock = MagicMock()
            mock.returncode = 0
            mock.stdout = json.dumps({
                "Account": "123456789012",
                "UserId": "AIDAIOSFODNN7EXAMPLE",
                "Arn": "arn:aws:iam::123456789012:user/test",
            })
            mock_run.return_value = mock

            from MCP_SERVER.auth.aws_cli_auth import get_account_id

            result = get_account_id()

        assert result == "123456789012"


# ---------------------------------------------------------------------------
# Dispatch tests for AWS provider
# ---------------------------------------------------------------------------

class TestDispatchRoutesAws:
    def test_dispatch_routes_aws_to_aws_tool(self, monkeypatch):
        """server.run_prowler_scan(provider='aws') must call AWS tool, not Azure."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch("MCP_SERVER.tools.aws.prowler.run_prowler_scan") as mock_aws, \
             patch("MCP_SERVER.tools.azure.prowler.run_prowler_scan") as mock_azure:
            mock_aws.return_value = {
                "status": "success", "findings": [], "error": None,
                "prowler_version": None, "returncode": 0,
                "started_at": None, "finished_at": None, "fixture_mode": False,
            }

            import importlib
            import MCP_SERVER.server_multicloud as server_mod
            importlib.reload(server_mod)

            server_mod.run_prowler_scan(
                provider="aws",
                cloud_account_id="123456789012",
                benchmark="cis_aws_foundations_benchmark_v3.0",
                output_format="json-ocsf",
            )

        mock_aws.assert_called_once()
        mock_azure.assert_not_called()


# ---------------------------------------------------------------------------
# TestAssumeRole
# ---------------------------------------------------------------------------

class TestAssumeRole:
    _STS_RESPONSE = json.dumps({
        "Credentials": {
            "AccessKeyId": "ASIA_FAKE_KEY",
            "SecretAccessKey": "fake/secret/key",
            "SessionToken": "fake-session-token",
            "Expiration": "2026-01-01T00:00:00Z",
        }
    })

    def test_happy_path_returns_credentials_dict(self):
        """Valid STS response → returns env-var dict with three credential keys."""
        with patch("subprocess.run") as mock_run:
            mock = MagicMock()
            mock.returncode = 0
            mock.stdout = self._STS_RESPONSE
            mock_run.return_value = mock

            from MCP_SERVER.auth.assume_role import assume_role
            result = assume_role("arn:aws:iam::123456789012:role/ProwlerRole")

        assert result["AWS_ACCESS_KEY_ID"] == "ASIA_FAKE_KEY"
        assert result["AWS_SECRET_ACCESS_KEY"] == "fake/secret/key"
        assert result["AWS_SESSION_TOKEN"] == "fake-session-token"

    def test_sts_nonzero_raises_runtime_error(self):
        """returncode != 0 → RuntimeError with STS error message."""
        with patch("subprocess.run") as mock_run:
            mock = MagicMock()
            mock.returncode = 1
            mock.stdout = ""
            mock.stderr = "An error occurred (AccessDenied)"
            mock_run.return_value = mock

            from MCP_SERVER.auth.assume_role import assume_role
            with pytest.raises(RuntimeError, match="AssumeRole failed"):
                assume_role("arn:aws:iam::123456789012:role/ProwlerRole")

    def test_aws_cli_not_found_raises_runtime_error(self):
        """FileNotFoundError (aws not on PATH) → RuntimeError."""
        with patch("subprocess.run", side_effect=FileNotFoundError("aws not found")):
            from MCP_SERVER.auth.assume_role import assume_role
            with pytest.raises(RuntimeError, match="not found"):
                assume_role("arn:aws:iam::123456789012:role/ProwlerRole")

    def test_timeout_raises_runtime_error(self):
        """TimeoutExpired → RuntimeError."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("aws", 30)):
            from MCP_SERVER.auth.assume_role import assume_role
            with pytest.raises(RuntimeError, match="timed out"):
                assume_role("arn:aws:iam::123456789012:role/ProwlerRole")


# ---------------------------------------------------------------------------
# TestGetCredentialsForScan
# ---------------------------------------------------------------------------

class TestGetCredentialsForScan:
    def test_empty_role_arn_returns_empty_dict(self):
        """No role_arn → empty dict, no STS call."""
        from MCP_SERVER.auth.aws_cli_auth import get_credentials_for_scan
        result = get_credentials_for_scan("")
        assert result == {}

    def test_role_arn_calls_assume_role_and_returns_creds(self):
        """role_arn provided → delegates to assume_role, returns credentials."""
        fake_creds = {
            "AWS_ACCESS_KEY_ID": "ASIA_FAKE",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "AWS_SESSION_TOKEN": "token",
        }
        with patch("MCP_SERVER.auth.assume_role.assume_role", return_value=fake_creds) as mock_ar:
            from MCP_SERVER.auth import aws_cli_auth
            import importlib
            importlib.reload(aws_cli_auth)

            result = aws_cli_auth.get_credentials_for_scan(
                "arn:aws:iam::123456789012:role/ProwlerRole"
            )

        assert result == fake_creds


# ---------------------------------------------------------------------------
# TestAssumeRoleInjectedIntoSubprocess
# ---------------------------------------------------------------------------

class TestAssumeRoleInjectedIntoSubprocess:
    def test_role_arn_credentials_appear_in_subprocess_env(self, monkeypatch):
        """When role_arn is set, subprocess.run must receive env with temp credentials."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        fake_creds = {
            "AWS_ACCESS_KEY_ID": "ASIA_FAKE",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "AWS_SESSION_TOKEN": "token",
        }
        captured_env = {}

        def fake_run(cmd, **kwargs):
            captured_env.update(kwargs.get("env") or {})
            mock = MagicMock()
            mock.returncode = 0
            mock.stdout = "[]"
            mock.stderr = ""
            return mock

        with patch("MCP_SERVER.auth.aws_cli_auth.get_credentials_for_scan", return_value=fake_creds), \
             patch("subprocess.run", side_effect=fake_run):
            import importlib
            import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
            importlib.reload(aws_prowler_mod)

            aws_prowler_mod.run_prowler_scan(
                cloud_account_id="123456789012",
                role_arn="arn:aws:iam::123456789012:role/ProwlerRole",
            )

        assert captured_env.get("AWS_ACCESS_KEY_ID") == "ASIA_FAKE"
        assert captured_env.get("AWS_SESSION_TOKEN") == "token"

    def test_no_role_arn_subprocess_env_is_none(self, monkeypatch):
        """When role_arn is empty, subprocess.run must receive env=None (ambient)."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        captured_kwargs = {}

        def fake_run(cmd, **kwargs):
            captured_kwargs.update(kwargs)
            mock = MagicMock()
            mock.returncode = 0
            mock.stdout = "[]"
            mock.stderr = ""
            return mock

        with patch("MCP_SERVER.auth.aws_cli_auth.get_credentials_for_scan", return_value={}), \
             patch("subprocess.run", side_effect=fake_run):
            import importlib
            import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
            importlib.reload(aws_prowler_mod)

            aws_prowler_mod.run_prowler_scan(cloud_account_id="123456789012", role_arn="")

        assert captured_kwargs.get("env") is None

    def test_assume_role_failure_returns_error_dict(self, monkeypatch):
        """If get_credentials_for_scan raises RuntimeError → error dict, no subprocess."""
        monkeypatch.delenv("PROWLER_FIXTURE_MODE", raising=False)

        with patch(
            "MCP_SERVER.auth.aws_cli_auth.get_credentials_for_scan",
            side_effect=RuntimeError("sts:AssumeRole failed: AccessDenied"),
        ), patch("subprocess.run") as mock_run:
            import importlib
            import MCP_SERVER.tools.aws.prowler as aws_prowler_mod
            importlib.reload(aws_prowler_mod)

            result = aws_prowler_mod.run_prowler_scan(
                cloud_account_id="123456789012",
                role_arn="arn:aws:iam::123456789012:role/ProwlerRole",
            )

        assert result["status"] == "error"
        assert "AssumeRole" in result["error"]
        mock_run.assert_not_called()
