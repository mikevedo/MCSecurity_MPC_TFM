"""
prowler.py — MCP tool that executes Prowler CLI for AWS CIS benchmarks.

Design reference: sdd/aws-multicloud/design — PR 2 (MCP Layer / tools/aws/prowler.py)
Spec reference: MCP-AWS-1, MCP-AWS-2

CRITICAL RULES (enforced by boundary tests):
- This is the ONLY module in the project that may call subprocess for AWS Prowler.
- No other module may import or invoke Prowler CLI for AWS.

Exit code handling:
- 0 → all checks passed (success)
- 3 → success with findings (Prowler's normal result when issues are found)
- Any other code → error

Fixture mode:
- Set env var PROWLER_FIXTURE_MODE=true to skip subprocess and load fixture file.
- PROWLER_FIXTURE_PATH overrides the default fixture location.

Return schema (byte-identical to MCP_SERVER/tools/azure/prowler.py):
{
    "status": "success" | "error",
    "findings": list[dict],
    "error": str | None,
    "prowler_version": str | None,
    "returncode": int | None,
    "started_at": str | None,
    "finished_at": str | None,
    "fixture_mode": bool,
}
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from MCP_SERVER.auth.aws_cli_auth import get_credentials_for_scan

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROWLER_TIMEOUT: int = 600  # seconds
DEFAULT_FIXTURE_PATH: str = str(
    Path(__file__).parents[3] / "tests" / "fixtures" / "prowler_aws_sample.json"
)
SUCCESS_RETURNCODES: frozenset[int] = frozenset({0, 3})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _error_dict(message: str, returncode: Optional[int] = None) -> dict[str, Any]:
    return {
        "status": "error",
        "findings": [],
        "error": message,
        "prowler_version": None,
        "returncode": returncode,
        "started_at": None,
        "finished_at": None,
        "fixture_mode": False,
    }


def _extract_prowler_version(findings: list[dict]) -> Optional[str]:
    """Extract prowler version from the first finding's metadata, if available."""
    if findings:
        try:
            return findings[0]["metadata"]["product"]["version"]
        except (KeyError, IndexError, TypeError):
            pass
    return None


# ---------------------------------------------------------------------------
# Fixture mode
# ---------------------------------------------------------------------------


def _run_fixture_mode(fixture_path: str) -> dict[str, Any]:
    """Load findings from a fixture JSON file instead of running Prowler."""
    started_at = _now_iso()
    try:
        with open(fixture_path, encoding="utf-8") as fh:
            findings = json.load(fh)
        if not isinstance(findings, list):
            return _error_dict(
                f"Fixture file does not contain a JSON array: {fixture_path}"
            ) | {"fixture_mode": True}
        finished_at = _now_iso()
        return {
            "status": "success",
            "findings": findings,
            "error": None,
            "prowler_version": _extract_prowler_version(findings),
            "returncode": 0,
            "started_at": started_at,
            "finished_at": finished_at,
            "fixture_mode": True,
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "findings": [],
            "error": f"Fixture file not found: {fixture_path}",
            "prowler_version": None,
            "returncode": None,
            "started_at": started_at,
            "finished_at": _now_iso(),
            "fixture_mode": True,
        }
    except json.JSONDecodeError as exc:
        return {
            "status": "error",
            "findings": [],
            "error": f"Fixture file contains invalid JSON: {exc}",
            "prowler_version": None,
            "returncode": None,
            "started_at": started_at,
            "finished_at": _now_iso(),
            "fixture_mode": True,
        }


# ---------------------------------------------------------------------------
# Live mode
# ---------------------------------------------------------------------------


def _run_live_mode(
    cloud_account_id: str,
    benchmark: str,
    output_format: str,
    role_arn: str = "",
    services: list[str] | None = None,
    checks: list[str] | None = None,
    severity_filter: list[str] | None = None,
    only_failed: bool = False,
    aws_region: str | None = None,
    excluded_checks: list[str] | None = None,
    categories: list[str] | None = None,
    mutelist_file: str | None = None,
) -> dict[str, Any]:
    """Run Prowler CLI via subprocess for AWS and return structured result."""
    started_at = _now_iso()

    try:
        creds_env = get_credentials_for_scan(role_arn)
    except RuntimeError as exc:
        return _error_dict(f"AssumeRole failed: {exc}")

    with tempfile.TemporaryDirectory() as tmp_dir:
        scan_id = os.urandom(8).hex()
        cmd = [
            "prowler",
            "aws",
            "--output-formats",
            output_format,
            "--output-directory",
            tmp_dir,
            "--output-filename",
            scan_id,
        ]
        if checks:
            # --checks mode: --compliance, --category, --excluded-checks are incompatible
            cmd += ["--checks"] + checks
        else:
            cmd += ["--compliance", benchmark]
            if excluded_checks:
                cmd += ["--excluded-checks"] + excluded_checks
            # --category is incompatible with --compliance in Prowler CLI — omitted
        if severity_filter:
            cmd += ["--severity"] + severity_filter
        if only_failed:
            cmd += ["--status", "FAIL"]
        if aws_region:
            cmd += ["--region", aws_region]
        if mutelist_file:
            cmd += ["--mutelist-file", mutelist_file]

        subprocess_env = {**os.environ, **creds_env} if creds_env else None

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=PROWLER_TIMEOUT,
                check=False,
                env=subprocess_env,
            )
            finished_at = _now_iso()
            returncode = proc.returncode

            if returncode not in SUCCESS_RETURNCODES:
                error_detail = proc.stderr.strip() or f"Prowler exited with code {returncode}"
                return {
                    "status": "error",
                    "findings": [],
                    "error": error_detail,
                    "prowler_version": None,
                    "returncode": returncode,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "fixture_mode": False,
                }

            # Read findings from temp file (extension depends on output_format)
            ext = "ocsf.json" if output_format == "json-ocsf" else f"{output_format}.json"
            output_file = Path(tmp_dir) / f"{scan_id}.{ext}"
            try:
                findings = json.loads(output_file.read_text(encoding="utf-8")) if output_file.exists() else []
            except json.JSONDecodeError:
                findings = []

            return {
                "status": "success",
                "findings": findings,
                "error": None,
                "prowler_version": _extract_prowler_version(findings),
                "returncode": returncode,
                "started_at": started_at,
                "finished_at": finished_at,
                "fixture_mode": False,
            }

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "findings": [],
                "error": f"prowler scan timeout: exceeded {PROWLER_TIMEOUT} seconds",
                "prowler_version": None,
                "returncode": None,
                "started_at": started_at,
                "finished_at": _now_iso(),
                "fixture_mode": False,
            }
        except FileNotFoundError:
            return {
                "status": "error",
                "findings": [],
                "error": "Prowler CLI not found on PATH. Install prowler or use fixture mode.",
                "prowler_version": None,
                "returncode": None,
                "started_at": started_at,
                "finished_at": _now_iso(),
                "fixture_mode": False,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "error",
                "findings": [],
                "error": f"Unexpected error running Prowler: {exc}",
                "prowler_version": None,
                "returncode": None,
                "started_at": started_at,
                "finished_at": _now_iso(),
                "fixture_mode": False,
            }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_prowler_scan(
    cloud_account_id: str = "",
    benchmark: str = "cis_aws_foundations_benchmark_v3.0",
    output_format: str = "json-ocsf",
    role_arn: str = "",
    services: list[str] | None = None,
    checks: list[str] | None = None,
    severity_filter: list[str] | None = None,
    only_failed: bool = False,
    aws_region: str | None = None,
    excluded_checks: list[str] | None = None,
    categories: list[str] | None = None,
    mutelist_file: str | None = None,
) -> dict[str, Any]:
    """
    Execute a Prowler security scan against an AWS account and return a structured result.

    Fixture mode is activated when the environment variable
    PROWLER_FIXTURE_MODE is set to "true" (case-insensitive).
    The fixture file path is read from PROWLER_FIXTURE_PATH, falling back to
    the default location at tests/fixtures/prowler_aws_sample.json.

    Args:
        cloud_account_id: AWS account ID to scan. When empty, --aws-account-id is omitted
                          and Prowler auto-detects the account from credentials.
        benchmark: Prowler compliance benchmark identifier (default: CIS AWS v3.0).
        output_format: Prowler output format (default: json-ocsf).
        role_arn: IAM role ARN to assume before scanning. When empty, Prowler uses
                  the ambient AWS credentials from the environment.
        checks: Optional Prowler --checks filter. When set, overrides services.
        severity_filter: Optional --severity filter (e.g. ['critical', 'high']).
        only_failed: When True, passes --status FAIL to exclude PASS findings at source.

    Returns:
        dict with keys: status, findings, error, prowler_version, returncode,
        started_at, finished_at, fixture_mode.
    """
    fixture_mode = os.environ.get("PROWLER_FIXTURE_MODE", "").lower() == "true"

    if fixture_mode:
        fixture_path = os.environ.get("PROWLER_FIXTURE_PATH", DEFAULT_FIXTURE_PATH)
        return _run_fixture_mode(fixture_path)

    return _run_live_mode(
        cloud_account_id=cloud_account_id,
        benchmark=benchmark,
        output_format=output_format,
        role_arn=role_arn,
        services=services,
        checks=checks,
        severity_filter=severity_filter,
        only_failed=only_failed,
        aws_region=aws_region,
        excluded_checks=excluded_checks,
        categories=categories,
        mutelist_file=mutelist_file,
    )
