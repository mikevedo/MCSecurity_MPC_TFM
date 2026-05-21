"""
vpc.py — MCP tool for AWS VPC security analysis via boto3.

Checks performed:
- Default VPC present in region (CIS 5.4)
- VPCs without active VPC flow logs (CIS 5.1)
- Subnets with auto-assign public IPv4 addresses enabled (CIS 5.3)

No subprocess. No Prowler. Direct boto3 calls.
Uses ambient credentials (env vars / instance profile / ~/.aws/credentials)
unless role_arn is provided, in which case STS assume_role is used.

Return schema:
{
    "success": True,
    "region": str,
    "summary": {
        "default_vpcs": int,
        "vpcs_without_flow_logs": int,
        "subnets_with_public_ip": int,
        "total_issues": int,
    },
    "default_vpcs": [{"vpc_id": str, "cidr_block": str, "state": str}],
    "vpcs_without_flow_logs": [{"vpc_id": str, "cidr_block": str, "is_default": bool}],
    "subnets_with_public_ip": [{"subnet_id": str, "vpc_id": str, "cidr_block": str, "availability_zone": str}],
}
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def _get_ec2_client(role_arn: Optional[str], region: Optional[str] = None):
    """
    Return a boto3 EC2 client.

    - If role_arn is provided: STS assume_role, then build client with temp creds.
    - If role_arn is None/empty: use ambient credentials.
    - region defaults to 'us-east-1' if not specified.
    """
    resolved_region = region or "us-east-1"
    kwargs: dict[str, Any] = {"region_name": resolved_region}

    if not role_arn:
        return boto3.client("ec2", **kwargs)

    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="vpc-security-scan",
    )["Credentials"]
    return boto3.client(
        "ec2",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        **kwargs,
    )


def analyze_vpc_security(
    role_arn: Optional[str] = None,
    region: Optional[str] = "us-east-1",
) -> dict[str, Any]:
    """
    Analyze AWS VPC security posture.

    Args:
        role_arn: IAM role to assume before scanning (optional).
        region:   AWS region to target (defaults to 'us-east-1').

    Returns:
        dict with keys: success, region, summary, default_vpcs,
        vpcs_without_flow_logs, subnets_with_public_ip.
    """
    effective_region = region or "us-east-1"

    try:
        ec2 = _get_ec2_client(role_arn, effective_region)
    except Exception as exc:
        return {"success": False, "error": f"Auth failed: {exc}"}

    default_vpcs: list[dict] = []
    vpcs_without_flow_logs: list[dict] = []
    subnets_with_public_ip: list[dict] = []

    # -------------------------------------------------------------------------
    # Check 1 — Default VPC present in region (CIS 5.4)
    # -------------------------------------------------------------------------
    try:
        response = ec2.describe_vpcs(
            Filters=[{"Name": "isDefault", "Values": ["true"]}]
        )
        for vpc in response.get("Vpcs", []):
            default_vpcs.append({
                "vpc_id": vpc["VpcId"],
                "cidr_block": vpc.get("CidrBlock", ""),
                "state": vpc.get("State", ""),
            })
    except ClientError as exc:
        return {"success": False, "error": str(exc)}

    # -------------------------------------------------------------------------
    # Check 2 — VPCs without active flow logs (CIS 5.1)
    # -------------------------------------------------------------------------
    try:
        all_vpcs_response = ec2.describe_vpcs()
        all_vpcs = all_vpcs_response.get("Vpcs", [])

        for vpc in all_vpcs:
            vpc_id = vpc["VpcId"]
            try:
                fl_response = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                )
                flow_logs = fl_response.get("FlowLogs", [])
                # A VPC is considered covered if it has at least one ACTIVE flow log
                has_active_flow_log = any(
                    fl.get("FlowLogStatus") == "ACTIVE" for fl in flow_logs
                )
                if not has_active_flow_log:
                    vpcs_without_flow_logs.append({
                        "vpc_id": vpc_id,
                        "cidr_block": vpc.get("CidrBlock", ""),
                        "is_default": vpc.get("IsDefault", False),
                    })
            except ClientError as exc:
                logger.warning("Flow log check failed for VPC %s: %s", vpc_id, exc)

    except ClientError as exc:
        return {"success": False, "error": str(exc)}

    # -------------------------------------------------------------------------
    # Check 3 — Subnets with auto-assign public IPv4 (CIS 5.3)
    # -------------------------------------------------------------------------
    try:
        paginator = ec2.get_paginator("describe_subnets")
        for page in paginator.paginate():
            for subnet in page["Subnets"]:
                if subnet.get("MapPublicIpOnLaunch") is True:
                    subnets_with_public_ip.append({
                        "subnet_id": subnet["SubnetId"],
                        "vpc_id": subnet.get("VpcId", ""),
                        "cidr_block": subnet.get("CidrBlock", ""),
                        "availability_zone": subnet.get("AvailabilityZone", ""),
                    })
    except ClientError as exc:
        logger.warning("Subnet check failed: %s", exc)

    total_issues = len(default_vpcs) + len(vpcs_without_flow_logs) + len(subnets_with_public_ip)

    return {
        "success": True,
        "region": effective_region,
        "summary": {
            "default_vpcs": len(default_vpcs),
            "vpcs_without_flow_logs": len(vpcs_without_flow_logs),
            "subnets_with_public_ip": len(subnets_with_public_ip),
            "total_issues": total_issues,
        },
        "default_vpcs": default_vpcs,
        "vpcs_without_flow_logs": vpcs_without_flow_logs,
        "subnets_with_public_ip": subnets_with_public_ip,
    }
