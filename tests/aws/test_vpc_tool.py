"""
test_vpc_tool.py — TDD tests for analyze_vpc_security (MCP_SERVER/tools/aws/vpc.py).

RED phase: written before vpc.py exists. All tests must be RED until T-5-2 is implemented.

Checks covered:
- test_vpc_detects_default_vpc: moto creates a default VPC automatically — assert it's flagged.
- test_vpc_detects_vpc_without_flow_logs: create custom VPC with no flow logs — assert flagged.
- test_vpc_detects_subnet_with_public_ip: create subnet with MapPublicIpOnLaunch=True — assert flagged.
- test_vpc_clean_account_no_custom_findings: custom VPC + flow logs + private subnet — no custom findings.
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from MCP_SERVER.tools.aws.vpc import analyze_vpc_security


@mock_aws
def test_vpc_detects_default_vpc():
    """
    moto automatically creates a default VPC in us-east-1.
    analyze_vpc_security must detect it and include it in default_vpcs.
    """
    result = analyze_vpc_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    assert "default_vpcs" in result
    assert len(result["default_vpcs"]) >= 1
    # Each entry must have a vpc_id
    assert all("vpc_id" in item for item in result["default_vpcs"])


@mock_aws
def test_vpc_detects_vpc_without_flow_logs():
    """
    Create a custom VPC with no flow logs configured.
    It must appear in result["vpcs_without_flow_logs"].
    """
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_response = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    custom_vpc_id = vpc_response["Vpc"]["VpcId"]

    result = analyze_vpc_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    vpc_ids_without_flow_logs = [item["vpc_id"] for item in result["vpcs_without_flow_logs"]]
    assert custom_vpc_id in vpc_ids_without_flow_logs


@mock_aws
def test_vpc_detects_subnet_with_public_ip():
    """
    Create a VPC and a subnet, then set MapPublicIpOnLaunch=True.
    The subnet must appear in result["subnets_with_public_ip"].
    """
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_response = ec2.create_vpc(CidrBlock="10.1.0.0/16")
    vpc_id = vpc_response["Vpc"]["VpcId"]

    subnet_response = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.1.1.0/24",
        AvailabilityZone="us-east-1a",
    )
    subnet_id = subnet_response["Subnet"]["SubnetId"]

    ec2.modify_subnet_attribute(
        SubnetId=subnet_id,
        MapPublicIpOnLaunch={"Value": True},
    )

    result = analyze_vpc_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    subnet_ids_with_public_ip = [item["subnet_id"] for item in result["subnets_with_public_ip"]]
    assert subnet_id in subnet_ids_with_public_ip


@mock_aws
def test_vpc_clean_account_no_custom_findings():
    """
    Create a custom VPC with flow logs enabled and a subnet with MapPublicIpOnLaunch=False.
    The custom VPC must NOT appear in vpcs_without_flow_logs.
    The subnet must NOT appear in subnets_with_public_ip.
    (The default VPC will still appear in default_vpcs — that's expected.)
    """
    ec2 = boto3.client("ec2", region_name="us-east-1")

    # Create a custom VPC
    vpc_response = ec2.create_vpc(CidrBlock="10.2.0.0/16")
    custom_vpc_id = vpc_response["Vpc"]["VpcId"]

    # Create a private subnet (MapPublicIpOnLaunch is False by default)
    subnet_response = ec2.create_subnet(
        VpcId=custom_vpc_id,
        CidrBlock="10.2.1.0/24",
        AvailabilityZone="us-east-1a",
    )
    subnet_id = subnet_response["Subnet"]["SubnetId"]

    # Create flow logs for the custom VPC using CloudWatch Logs as destination
    logs_client = boto3.client("logs", region_name="us-east-1")
    log_group_name = "/vpc/flow-logs"
    logs_client.create_log_group(logGroupName=log_group_name)

    # Create IAM role for flow logs (moto accepts any role ARN)
    ec2.create_flow_logs(
        ResourceIds=[custom_vpc_id],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="cloud-watch-logs",
        LogGroupName=log_group_name,
        DeliverLogsPermissionArn="arn:aws:iam::123456789012:role/flow-logs-role",
    )

    result = analyze_vpc_security(role_arn=None, region="us-east-1")

    assert result["success"] is True

    # The custom VPC must NOT appear in vpcs_without_flow_logs
    vpc_ids_without_flow_logs = [item["vpc_id"] for item in result["vpcs_without_flow_logs"]]
    assert custom_vpc_id not in vpc_ids_without_flow_logs

    # The private subnet must NOT appear in subnets_with_public_ip
    subnet_ids_with_public_ip = [item["subnet_id"] for item in result["subnets_with_public_ip"]]
    assert subnet_id not in subnet_ids_with_public_ip
