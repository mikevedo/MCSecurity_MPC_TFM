"""
security_tools.py — LangChain tools wrapping the 6 AWS boto3 security analyzers.

Each tool delegates to the corresponding MCP_SERVER/tools/aws/<domain>.py function.
role_arn and region are baked in at build time via _make_tools() — the agent
does not need to pass them explicitly.
"""

from __future__ import annotations

from typing import Optional

from langchain_core.tools import tool

from MCP_SERVER.tools.aws.cloudtrail import analyze_cloudtrail_security
from MCP_SERVER.tools.aws.ebs import analyze_ebs_security
from MCP_SERVER.tools.aws.ec2 import analyze_ec2_security
from MCP_SERVER.tools.aws.iam import analyze_iam_security
from MCP_SERVER.tools.aws.s3 import analyze_s3_security
from MCP_SERVER.tools.aws.vpc import analyze_vpc_security


def build_security_tools(role_arn: str = "", region: str = "us-east-1") -> list:
    """
    Return the 6 LangChain security tools with role_arn and region pre-bound.
    Call once per chat session when the account context is known.
    """
    _role = role_arn or None
    _region = region or "us-east-1"

    @tool
    def scan_iam() -> dict:
        """
        Analyze AWS IAM security posture.
        Checks: users without MFA, access keys older than 90 days,
        inactive console users, root account MFA and access keys.
        Use this for questions about identity, permissions, MFA, access keys, or root account.
        """
        return analyze_iam_security(role_arn=_role)

    @tool
    def scan_s3() -> dict:
        """
        Analyze AWS S3 security posture.
        Checks: public buckets (ACL or policy), unencrypted buckets,
        buckets without versioning, buckets without access logging.
        Use this for questions about storage, buckets, S3, or data exposure.
        """
        return analyze_s3_security(role_arn=_role, region=_region)

    @tool
    def scan_ebs() -> dict:
        """
        Analyze AWS EBS and Security Group security posture.
        Checks: unencrypted EBS volumes, security groups with open ports
        (22, 3389, all-traffic) from 0.0.0.0/0 or ::/0, public snapshots.
        Use this for questions about volumes, disks, security groups, firewall rules, or open ports.
        """
        return analyze_ebs_security(role_arn=_role, region=_region)

    @tool
    def scan_cloudtrail() -> dict:
        """
        Analyze AWS CloudTrail security posture.
        Checks: no multi-region trail, log file validation disabled,
        no CloudWatch Logs integration, missing CIS metric filters
        (root usage, unauthorized API calls, MFA sign-in failures, CloudTrail changes).
        Use this for questions about audit logs, API activity, trail configuration, or metric filters.
        """
        return analyze_cloudtrail_security(role_arn=_role, region=_region)

    @tool
    def scan_vpc() -> dict:
        """
        Analyze AWS VPC security posture.
        Checks: default VPC still present, VPCs without flow logs enabled,
        subnets with auto-assign public IP.
        Use this for questions about VPC, network configuration, flow logs, or subnets.
        """
        return analyze_vpc_security(role_arn=_role, region=_region)

    @tool
    def scan_ec2() -> dict:
        """
        Analyze AWS EC2 security posture.
        Checks: instances without IMDSv2 enforced, instances with public IP addresses,
        instances with detailed monitoring disabled.
        Use this for questions about EC2 instances, servers, IMDSv2, or compute security.
        """
        return analyze_ec2_security(role_arn=_role, region=_region)

    return [scan_iam, scan_s3, scan_ebs, scan_cloudtrail, scan_vpc, scan_ec2]
