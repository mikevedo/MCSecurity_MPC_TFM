"""
test_ec2_tool.py — TDD tests for MCP_SERVER/tools/aws/ec2.py

Tests:
- test_ec2_detects_imdsv2_not_enforced: instance with HttpTokens=optional appears in imdsv2_not_enforced
- test_ec2_detects_instance_with_public_ip: instance with public IP appears in public_ip_instances
- test_ec2_detects_monitoring_disabled: instance without detailed monitoring in monitoring_disabled
- test_ec2_no_instances_no_findings: no instances → all lists empty, success=True
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from MCP_SERVER.tools.aws.ec2 import analyze_ec2_security


@mock_aws
def test_ec2_detects_imdsv2_not_enforced():
    """An instance with HttpTokens=optional should appear in imdsv2_not_enforced."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    # Retrieve a moto-available AMI
    images = ec2.describe_images(Owners=["amazon"])["Images"]
    ami_id = images[0]["ImageId"] if images else "ami-12c6146b"

    instance_resp = ec2.run_instances(
        ImageId=ami_id,
        MinCount=1,
        MaxCount=1,
        MetadataOptions={"HttpTokens": "optional"},
    )
    instance_id = instance_resp["Instances"][0]["InstanceId"]

    result = analyze_ec2_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    flagged_ids = [i["instance_id"] for i in result["imdsv2_not_enforced"]]
    assert instance_id in flagged_ids


@mock_aws
def test_ec2_detects_instance_with_public_ip():
    """An instance launched in the default VPC/subnet gets a public IP and should be flagged."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    images = ec2.describe_images(Owners=["amazon"])["Images"]
    ami_id = images[0]["ImageId"] if images else "ami-12c6146b"

    instance_resp = ec2.run_instances(
        ImageId=ami_id,
        MinCount=1,
        MaxCount=1,
    )
    instance_id = instance_resp["Instances"][0]["InstanceId"]

    result = analyze_ec2_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    # moto assigns a public IP in the default VPC — verify it was detected
    public_ids = [i["instance_id"] for i in result["public_ip_instances"]]
    assert instance_id in public_ids


@mock_aws
def test_ec2_detects_monitoring_disabled():
    """An instance without detailed monitoring should appear in monitoring_disabled."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    images = ec2.describe_images(Owners=["amazon"])["Images"]
    ami_id = images[0]["ImageId"] if images else "ami-12c6146b"

    # moto creates instances with Monitoring.State='disabled' by default
    instance_resp = ec2.run_instances(
        ImageId=ami_id,
        MinCount=1,
        MaxCount=1,
    )
    instance_id = instance_resp["Instances"][0]["InstanceId"]

    result = analyze_ec2_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    disabled_ids = [i["instance_id"] for i in result["monitoring_disabled"]]
    assert instance_id in disabled_ids


@mock_aws
def test_ec2_no_instances_no_findings():
    """When there are no instances, all finding lists must be empty and success must be True."""
    result = analyze_ec2_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    assert result["imdsv2_not_enforced"] == []
    assert result["public_ip_instances"] == []
    assert result["monitoring_disabled"] == []
    assert result["summary"]["total_issues"] == 0
