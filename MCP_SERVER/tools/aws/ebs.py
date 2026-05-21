"""
ebs.py — MCP tool for AWS EBS and Security Group security analysis via boto3.

Checks performed:
- Unencrypted EBS volumes (Encrypted=False, state=available or in-use)
- Risky Security Groups: port 22, 3389, or all-traffic (protocol -1) open to 0.0.0.0/0 or ::/0
- Public EBS snapshots: createVolumePermission includes group=all

No subprocess. No Prowler. Direct boto3 calls.
Uses ambient credentials (env vars / instance profile / ~/.aws/credentials)
unless role_arn is provided, in which case STS assume_role is used.

Return schema:
{
    "success": True,
    "region": str,
    "summary": {
        "unencrypted_volumes": int,
        "risky_security_groups": int,
        "public_snapshots": int,
        "total_issues": int,
    },
    "unencrypted_volumes": [{"volume_id": str, "size_gb": int, "state": str, "availability_zone": str}],
    "risky_security_groups": [{"group_id": str, "group_name": str, "vpc_id": str, "issues": [str]}],
    "public_snapshots": [{"snapshot_id": str, "volume_id": str, "start_time": str, "description": str}],
}
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Ports considered risky when open to the internet (0.0.0.0/0 or ::/0)
_RISKY_PORTS = {22, 3389}


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
        RoleSessionName="ebs-security-scan",
    )["Credentials"]
    return boto3.client(
        "ec2",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        **kwargs,
    )


def _is_rule_risky(rule: dict) -> Optional[str]:
    """
    Check if an IP permission rule is risky (exposes a sensitive port to the internet).

    Returns an issue string if risky, None otherwise.
    """
    from_port = rule.get("FromPort", 0)
    to_port = rule.get("ToPort", 65535)
    protocol = rule.get("IpProtocol", "")

    # Collect CIDRs that are open to the internet
    open_cidrs: list[str] = []
    for ip_range in rule.get("IpRanges", []):
        if ip_range.get("CidrIp") == "0.0.0.0/0":
            open_cidrs.append("0.0.0.0/0")
    for ipv6_range in rule.get("Ipv6Ranges", []):
        if ipv6_range.get("CidrIpv6") == "::/0":
            open_cidrs.append("::/0")

    if not open_cidrs:
        return None

    cidr_str = ", ".join(open_cidrs)

    # All-traffic rule (protocol == "-1")
    if protocol == "-1":
        return f"All traffic open to {cidr_str}"

    # Check risky ports — rule spans a port range; flag if any risky port is included
    for risky_port in _RISKY_PORTS:
        if from_port <= risky_port <= to_port:
            return f"Port {risky_port} open to {cidr_str}"

    return None


def analyze_ebs_security(
    role_arn: Optional[str] = None,
    region: Optional[str] = "us-east-1",
) -> dict[str, Any]:
    """
    Analyze AWS EBS and Security Group security posture.

    Args:
        role_arn: IAM role to assume before scanning (optional).
        region:   AWS region to target (defaults to 'us-east-1').

    Returns:
        dict with keys: success, region, summary, unencrypted_volumes,
        risky_security_groups, public_snapshots.
    """
    effective_region = region or "us-east-1"
    try:
        ec2 = _get_ec2_client(role_arn, effective_region)
    except Exception as exc:
        return {"success": False, "error": f"Auth failed: {exc}"}

    unencrypted_volumes: list[dict] = []
    risky_security_groups: list[dict] = []
    public_snapshots: list[dict] = []

    # -------------------------------------------------------------------------
    # Check 1 — Unencrypted EBS volumes
    # -------------------------------------------------------------------------
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                # Only consider active volumes; filter in Python (moto doesn't
                # implement the "state" filter for describe_volumes yet)
                vol_state = vol.get("State", "")
                if vol_state not in ("available", "in-use"):
                    continue
                if vol.get("Encrypted") is False:
                    unencrypted_volumes.append({
                        "volume_id": vol["VolumeId"],
                        "size_gb": vol.get("Size", 0),
                        "state": vol_state,
                        "availability_zone": vol.get("AvailabilityZone", ""),
                    })
    except ClientError as exc:
        return {"success": False, "error": str(exc)}

    # -------------------------------------------------------------------------
    # Check 2 — Risky Security Groups
    # -------------------------------------------------------------------------
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                issues: list[str] = []
                for rule in sg.get("IpPermissions", []):
                    issue = _is_rule_risky(rule)
                    if issue:
                        issues.append(issue)
                if issues:
                    risky_security_groups.append({
                        "group_id": sg["GroupId"],
                        "group_name": sg.get("GroupName", ""),
                        "vpc_id": sg.get("VpcId", ""),
                        "issues": issues,
                    })
    except ClientError as exc:
        logger.warning("Security group check failed: %s", exc)

    # -------------------------------------------------------------------------
    # Check 3 — Public EBS Snapshots
    # -------------------------------------------------------------------------
    try:
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page["Snapshots"]:
                snap_id = snap["SnapshotId"]
                try:
                    attr = ec2.describe_snapshot_attribute(
                        SnapshotId=snap_id,
                        Attribute="createVolumePermission",
                    )
                    permissions = attr.get("CreateVolumePermissions", [])
                    if any(p.get("Group") == "all" for p in permissions):
                        start_time = snap.get("StartTime", "")
                        public_snapshots.append({
                            "snapshot_id": snap_id,
                            "volume_id": snap.get("VolumeId", ""),
                            "start_time": start_time.isoformat() if hasattr(start_time, "isoformat") else str(start_time),
                            "description": snap.get("Description", ""),
                        })
                except ClientError as exc:
                    logger.warning("Snapshot attribute check failed for %s: %s", snap_id, exc)
    except ClientError as exc:
        logger.warning("Snapshot listing failed: %s", exc)

    total_issues = len(unencrypted_volumes) + len(risky_security_groups) + len(public_snapshots)

    return {
        "success": True,
        "region": effective_region,
        "summary": {
            "unencrypted_volumes": len(unencrypted_volumes),
            "risky_security_groups": len(risky_security_groups),
            "public_snapshots": len(public_snapshots),
            "total_issues": total_issues,
        },
        "unencrypted_volumes": unencrypted_volumes,
        "risky_security_groups": risky_security_groups,
        "public_snapshots": public_snapshots,
    }
