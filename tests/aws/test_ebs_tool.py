"""
test_ebs_tool.py — TDD tests for MCP_SERVER/tools/aws/ebs.py

Tests:
- test_ebs_detects_unencrypted_volume: unencrypted EBS volume appears in unencrypted_volumes
- test_ebs_detects_risky_security_group: SG with port 22 open to 0.0.0.0/0 appears in risky_security_groups
- test_ebs_detects_public_snapshot: public snapshot appears in public_snapshots
- test_ebs_clean_account_no_findings: encrypted volume + locked SG + private snapshot → all lists empty
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from MCP_SERVER.tools.aws.ebs import analyze_ebs_security


@mock_aws
def test_ebs_detects_unencrypted_volume():
    """An unencrypted EBS volume (Encrypted=False) should appear in unencrypted_volumes."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    # Create an unencrypted volume
    ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=20,
        Encrypted=False,
    )

    result = analyze_ebs_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    assert len(result["unencrypted_volumes"]) >= 1
    # Each entry must include volume_id
    assert all("volume_id" in v for v in result["unencrypted_volumes"])


@mock_aws
def test_ebs_detects_risky_security_group():
    """A security group with port 22 open to 0.0.0.0/0 should appear in risky_security_groups."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(
        GroupName="risky-sg",
        Description="Security group with open SSH",
    )
    group_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    result = analyze_ebs_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    risky_ids = [sg_item["group_id"] for sg_item in result["risky_security_groups"]]
    assert group_id in risky_ids


@mock_aws
def test_ebs_detects_public_snapshot():
    """A snapshot made public via createVolumePermission should appear in public_snapshots."""
    ec2 = boto3.client("ec2", region_name="us-east-1")
    # Create a volume first, then snapshot it
    volume = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=10,
        Encrypted=True,
    )
    volume_id = volume["VolumeId"]
    snap = ec2.create_snapshot(VolumeId=volume_id, Description="test snapshot")
    snapshot_id = snap["SnapshotId"]

    # Make the snapshot public
    ec2.modify_snapshot_attribute(
        SnapshotId=snapshot_id,
        Attribute="createVolumePermission",
        OperationType="add",
        GroupNames=["all"],
    )

    result = analyze_ebs_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    public_snap_ids = [s["snapshot_id"] for s in result["public_snapshots"]]
    assert snapshot_id in public_snap_ids


@mock_aws
def test_ebs_clean_account_no_findings():
    """An encrypted volume, a locked-down SG, and a private snapshot should produce no findings."""
    ec2 = boto3.client("ec2", region_name="us-east-1")

    # Create an encrypted volume
    ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=20,
        Encrypted=True,
    )

    # Create a security group with no public ingress rules (inbound-only on private CIDR)
    sg = ec2.create_security_group(
        GroupName="clean-sg",
        Description="No risky rules",
    )
    group_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    )

    # Create a private snapshot (no permission change — not public)
    volume = ec2.create_volume(
        AvailabilityZone="us-east-1a",
        Size=5,
        Encrypted=True,
    )
    ec2.create_snapshot(VolumeId=volume["VolumeId"], Description="private snapshot")

    result = analyze_ebs_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    assert result["unencrypted_volumes"] == []
    # clean-sg should NOT appear in risky SGs
    risky_ids = {sg_item["group_id"] for sg_item in result["risky_security_groups"]}
    assert group_id not in risky_ids
    assert result["public_snapshots"] == []
