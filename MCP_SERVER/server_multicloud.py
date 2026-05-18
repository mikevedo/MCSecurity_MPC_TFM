"""
server_multicloud.py — FastMCP server exposing cloud security scan tools.

Design reference: sdd/aws-multicloud/design — PR 2 (MCP Layer / server_multicloud.py)
Spec reference: MCP-DISPATCH-1

Exposes one tool:
    run_prowler_scan(provider, cloud_account_id, benchmark, output_format, role_arn)
        → dispatches to the appropriate provider tool:
            - "azure" → MCP_SERVER/tools/azure/prowler.py
            - "aws"   → MCP_SERVER/tools/aws/prowler.py
            - other   → error dict (status="error", error="unknown provider: {x}")

Server name: "cloud-security-mcp"
Transport: stdio (default for MCP server process)
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from .tools.azure.prowler import run_prowler_scan as _run_azure_prowler
from .tools.aws.prowler import run_prowler_scan as _run_aws_prowler

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------

mcp = FastMCP("cloud-security-mcp")


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


@mcp.tool()
def run_prowler_scan(
    provider: str,
    cloud_account_id: str,
    benchmark: str = "cis_azure_foundations_benchmark_v2.0",
    output_format: str = "json-ocsf",
    role_arn: str = "",
) -> dict:
    """
    Run a Prowler security scan against a cloud account.

    Dispatches to the correct provider implementation based on the `provider` argument.
    Supported providers: "azure", "aws".

    In fixture mode (PROWLER_FIXTURE_MODE=true), returns pre-captured findings without
    invoking Prowler.

    Args:
        provider: Cloud provider — "azure" or "aws".
        cloud_account_id: Cloud account/subscription UID to scan.
        benchmark: Prowler compliance benchmark (default: CIS Azure v2.0).
        output_format: Prowler output format (default: json-ocsf).
        role_arn: IAM role ARN to assume before scanning (AWS only). When empty,
                  Prowler uses ambient AWS credentials.

    Returns:
        dict with keys: status, findings, error, prowler_version, returncode,
        started_at, finished_at, fixture_mode.
    """
    if provider == "azure":
        return _run_azure_prowler(
            cloud_account_id=cloud_account_id,
            benchmark=benchmark,
            output_format=output_format,
        )
    if provider == "aws":
        return _run_aws_prowler(
            cloud_account_id=cloud_account_id,
            benchmark=benchmark,
            output_format=output_format,
            role_arn=role_arn,
        )
    return {
        "status": "error",
        "findings": [],
        "error": f"unknown provider: {provider}",
        "prowler_version": None,
        "returncode": None,
        "started_at": None,
        "finished_at": None,
        "fixture_mode": False,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
