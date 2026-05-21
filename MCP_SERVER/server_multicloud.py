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
from .tools.aws.iam import analyze_iam_security as _analyze_iam_security
from .tools.aws.s3 import analyze_s3_security as _analyze_s3_security
from .tools.aws.ebs import analyze_ebs_security as _analyze_ebs_security
from .tools.aws.cloudtrail import analyze_cloudtrail_security as _analyze_cloudtrail_security
from .tools.aws.vpc import analyze_vpc_security as _analyze_vpc_security
from .tools.aws.ec2 import analyze_ec2_security as _analyze_ec2_security

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
    benchmark: str = "cis_2.0_azure",
    output_format: str = "json-ocsf",
    role_arn: str = "",
    services: list[str] | None = None,
    checks: list[str] | None = None,
    severity_filter: list[str] | None = None,
    only_failed: bool = False,
    resource_group: str | None = None,
    azure_region: str | None = None,
    aws_region: str | None = None,
    excluded_checks: list[str] | None = None,
    categories: list[str] | None = None,
    mutelist_file: str | None = None,
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
        services: Optional Prowler --services filter (e.g. ['iam', 'cloudtrail']).
                  When empty, Prowler scans all services.
        checks: Optional Prowler --checks filter (e.g. ['iam_root_mfa_enabled']).
                When set, overrides services — only those checks are run.
        severity_filter: Optional --severity filter (e.g. ['critical', 'high']).
                         When empty, all severities are returned.
        only_failed: When True, passes --status FAIL to exclude PASS findings at source.

    Returns:
        dict with keys: status, findings, error, prowler_version, returncode,
        started_at, finished_at, fixture_mode.
    """
    if provider == "azure":
        return _run_azure_prowler(
            cloud_account_id=cloud_account_id,
            benchmark=benchmark,
            output_format=output_format,
            services=services,
            checks=checks,
            severity_filter=severity_filter,
            only_failed=only_failed,
            resource_group=resource_group,
            azure_region=azure_region,
            excluded_checks=excluded_checks,
            categories=categories,
            mutelist_file=mutelist_file,
        )
    if provider == "aws":
        return _run_aws_prowler(
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
# Direct boto3 security tools (no Prowler — instant responses)
# ---------------------------------------------------------------------------


@mcp.tool()
def scan_iam_security_aws(
    access_key_age_days: int = 90,
    inactive_user_days: int = 90,
    role_arn: str = "",
) -> dict:
    """
    Analyze AWS IAM security posture directly via boto3.

    Checks performed:
    - Users without MFA enabled
    - Active access keys older than threshold (default 90 days)
    - Console users inactive longer than threshold (default 90 days)
    - Root account MFA and access key presence

    No Prowler CLI. No subprocess. Results in seconds.

    Args:
        access_key_age_days: Flag keys older than this (default 90).
        inactive_user_days:  Flag inactive console users (default 90).
        role_arn:            IAM role to assume before scanning (optional).

    Returns:
        dict with summary, users_without_mfa, old_access_keys,
        inactive_users, root_account_issues.
    """
    return _analyze_iam_security(
        access_key_age_days=access_key_age_days,
        inactive_user_days=inactive_user_days,
        role_arn=role_arn or None,
    )


@mcp.tool()
def scan_s3_security_aws(role_arn: str = "", region: str = "us-east-1") -> dict:
    """
    Analyze AWS S3 security posture directly via boto3.
    Checks: public buckets, unencrypted buckets, versioning disabled, logging disabled.
    No Prowler. Results in seconds.

    Args:
        role_arn: IAM role to assume before scanning (optional).
        region:   AWS region (ignored — S3 bucket listing is a global operation).

    Returns:
        dict with summary and per-check finding lists.
    """
    return _analyze_s3_security(role_arn=role_arn or None, region=region or None)


@mcp.tool()
def scan_ebs_security_aws(role_arn: str = "", region: str = "us-east-1") -> dict:
    """
    Analyze AWS EBS and Security Group security posture directly via boto3.
    Checks: unencrypted volumes, risky security groups (open ports), public snapshots.
    No Prowler. Results in seconds.

    Args:
        role_arn: IAM role to assume before scanning (optional).
        region:   AWS region (default us-east-1).

    Returns:
        dict with summary and per-check finding lists.
    """
    return _analyze_ebs_security(role_arn=role_arn or None, region=region or None)


@mcp.tool()
def scan_cloudtrail_security_aws(role_arn: str = "", region: str = "us-east-1") -> dict:
    """
    Analyze AWS CloudTrail security posture directly via boto3.
    Checks: multi-region trail, log file validation, CloudWatch integration, CIS metric filters.
    No Prowler. Results in seconds.

    Args:
        role_arn: IAM role to assume before scanning (optional).
        region:   AWS region (default us-east-1).

    Returns:
        dict with summary and per-check finding lists.
    """
    return _analyze_cloudtrail_security(role_arn=role_arn or None, region=region or None)


@mcp.tool()
def scan_vpc_security_aws(role_arn: str = "", region: str = "us-east-1") -> dict:
    """
    Analyze AWS VPC security posture directly via boto3.
    Checks: default VPC presence, VPCs without flow logs, subnets with auto-assign public IP.
    No Prowler. Results in seconds.

    Args:
        role_arn: IAM role to assume before scanning (optional).
        region:   AWS region (default us-east-1).

    Returns:
        dict with summary and per-check finding lists.
    """
    return _analyze_vpc_security(role_arn=role_arn or None, region=region or None)


@mcp.tool()
def scan_ec2_security_aws(role_arn: str = "", region: str = "us-east-1") -> dict:
    """
    Analyze AWS EC2 security posture directly via boto3.
    Checks: IMDSv2 enforcement, instances with public IPs, monitoring disabled.
    No Prowler. Results in seconds.

    Args:
        role_arn: IAM role to assume before scanning (optional).
        region:   AWS region (default us-east-1).

    Returns:
        dict with summary and per-check finding lists.
    """
    return _analyze_ec2_security(role_arn=role_arn or None, region=region or None)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
