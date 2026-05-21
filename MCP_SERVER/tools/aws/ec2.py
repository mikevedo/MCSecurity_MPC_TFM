"""
ec2.py — MCP tool for AWS EC2 security analysis via boto3.

Checks performed:
- IMDSv2 not enforced: instances with MetadataOptions.HttpTokens != "required" (CIS 5.6)
- Instances with public IPv4 addresses (CIS 5.5)
- Instances without detailed monitoring enabled

No subprocess. No Prowler. Direct boto3 calls.
Uses ambient credentials (env vars / instance profile / ~/.aws/credentials)
unless role_arn is provided, in which case STS assume_role is used.

Return schema:
{
    "success": True,
    "region": str,
    "summary": {
        "imdsv2_not_enforced": int,
        "public_ip_instances": int,
        "monitoring_disabled": int,
        "total_issues": int,
    },
    "imdsv2_not_enforced": [{"instance_id": str, "instance_type": str, "state": str, "http_tokens": str}],
    "public_ip_instances": [{"instance_id": str, "instance_type": str, "public_ip": str, "state": str}],
    "monitoring_disabled": [{"instance_id": str, "instance_type": str, "monitoring_state": str}],
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
        RoleSessionName="ec2-security-scan",
    )["Credentials"]
    return boto3.client(
        "ec2",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        **kwargs,
    )


def analyze_ec2_security(
    role_arn: Optional[str] = None,
    region: Optional[str] = "us-east-1",
) -> dict[str, Any]:
    """
    Analyze AWS EC2 instances for security issues.

    Args:
        role_arn: IAM role to assume before scanning (optional).
        region:   AWS region to target (defaults to 'us-east-1').

    Returns:
        dict with keys: success, region, summary, imdsv2_not_enforced,
        public_ip_instances, monitoring_disabled.
    """
    effective_region = region or "us-east-1"

    try:
        ec2 = _get_ec2_client(role_arn, effective_region)
    except Exception as exc:
        return {"success": False, "error": f"Auth failed: {exc}"}

    imdsv2_not_enforced: list[dict] = []
    public_ip_instances: list[dict] = []
    monitoring_disabled: list[dict] = []

    # -------------------------------------------------------------------------
    # Collect all instances via paginator
    # -------------------------------------------------------------------------
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_id = instance["InstanceId"]
                    instance_type = instance.get("InstanceType", "")
                    state = instance.get("State", {}).get("Name", "")

                    # Only consider running or stopped instances — skip terminated
                    if state == "terminated":
                        continue

                    # Check 1 — IMDSv2 not enforced (CIS 5.6)
                    metadata_options = instance.get("MetadataOptions", {})
                    http_tokens = metadata_options.get("HttpTokens", "optional")
                    if http_tokens != "required":
                        imdsv2_not_enforced.append({
                            "instance_id": instance_id,
                            "instance_type": instance_type,
                            "state": state,
                            "http_tokens": http_tokens,
                        })

                    # Check 2 — Instance has a public IP (CIS 5.5)
                    public_ip = instance.get("PublicIpAddress", "")
                    if public_ip:
                        public_ip_instances.append({
                            "instance_id": instance_id,
                            "instance_type": instance_type,
                            "public_ip": public_ip,
                            "state": state,
                        })

                    # Check 3 — Detailed monitoring disabled
                    monitoring_state = instance.get("Monitoring", {}).get("State", "disabled")
                    if monitoring_state != "enabled":
                        monitoring_disabled.append({
                            "instance_id": instance_id,
                            "instance_type": instance_type,
                            "monitoring_state": monitoring_state,
                        })

    except ClientError as exc:
        return {"success": False, "error": str(exc)}

    total_issues = len(imdsv2_not_enforced) + len(public_ip_instances) + len(monitoring_disabled)

    return {
        "success": True,
        "region": effective_region,
        "summary": {
            "imdsv2_not_enforced": len(imdsv2_not_enforced),
            "public_ip_instances": len(public_ip_instances),
            "monitoring_disabled": len(monitoring_disabled),
            "total_issues": total_issues,
        },
        "imdsv2_not_enforced": imdsv2_not_enforced,
        "public_ip_instances": public_ip_instances,
        "monitoring_disabled": monitoring_disabled,
    }
