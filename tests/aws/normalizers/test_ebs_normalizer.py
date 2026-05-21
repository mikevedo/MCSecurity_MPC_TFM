"""
test_ebs_normalizer.py — TDD tests for _ebs_result_to_normalized in backend/app/chat.py

Tests:
- test_ebs_normalizer_maps_unencrypted_volume: check_id=ec2_ebs_volume_encryption_enabled, MEDIUM, CIS 2.2.1
- test_ebs_normalizer_maps_risky_security_group: check_id=ec2_securitygroup_allow_ingress_from_internet, HIGH, CIS 5.2
- test_ebs_normalizer_maps_public_snapshot: check_id=ec2_ebs_snapshot_is_not_public, CRITICAL, CIS 2.2.2
"""

from __future__ import annotations

import pytest

from backend.app.chat import _ebs_result_to_normalized
from backend.app.poc_contracts import Benchmark, FindingStatus, Provider, Severity


def _make_ebs_result(**overrides) -> dict:
    """Build a minimal successful EBS tool result dict."""
    base = {
        "success": True,
        "region": "us-east-1",
        "summary": {
            "unencrypted_volumes": 0,
            "risky_security_groups": 0,
            "public_snapshots": 0,
            "total_issues": 0,
        },
        "unencrypted_volumes": [],
        "risky_security_groups": [],
        "public_snapshots": [],
    }
    base.update(overrides)
    return base


def test_ebs_normalizer_maps_unencrypted_volume():
    """An unencrypted volume maps to check_id ec2_ebs_volume_encryption_enabled, severity MEDIUM, CIS 2.2.1."""
    tool_out = _make_ebs_result(
        unencrypted_volumes=[
            {
                "volume_id": "vol-0abc1234",
                "size_gb": 20,
                "state": "available",
                "availability_zone": "us-east-1a",
            }
        ],
        summary={"unencrypted_volumes": 1, "risky_security_groups": 0, "public_snapshots": 0, "total_issues": 1},
    )

    nf = _ebs_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "ec2_ebs_volume_encryption_enabled"
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["2.2.1"]}
    assert f.resource_type == "AWS::EC2::Volume"
    assert "vol-0abc1234" in f.resource_id


def test_ebs_normalizer_maps_risky_security_group():
    """A risky SG maps to check_id ec2_securitygroup_allow_ingress_from_internet, severity HIGH, CIS 5.2."""
    tool_out = _make_ebs_result(
        risky_security_groups=[
            {
                "group_id": "sg-0def5678",
                "group_name": "risky-sg",
                "vpc_id": "vpc-00001234",
                "issues": ["Port 22 open to 0.0.0.0/0"],
            }
        ],
        summary={"unencrypted_volumes": 0, "risky_security_groups": 1, "public_snapshots": 0, "total_issues": 1},
    )

    nf = _ebs_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "ec2_securitygroup_allow_ingress_from_internet"
    assert f.severity == Severity.HIGH
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["5.2"]}
    assert f.resource_type == "AWS::EC2::SecurityGroup"
    assert "sg-0def5678" in f.resource_id


def test_ebs_normalizer_maps_public_snapshot():
    """A public snapshot maps to check_id ec2_ebs_snapshot_is_not_public, severity CRITICAL, CIS 2.2.2."""
    tool_out = _make_ebs_result(
        public_snapshots=[
            {
                "snapshot_id": "snap-0aaa1111",
                "volume_id": "vol-0abc1234",
                "start_time": "2026-01-01T00:00:00+00:00",
                "description": "leaked snapshot",
            }
        ],
        summary={"unencrypted_volumes": 0, "risky_security_groups": 0, "public_snapshots": 1, "total_issues": 1},
    )

    nf = _ebs_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "ec2_ebs_snapshot_is_not_public"
    assert f.severity == Severity.CRITICAL
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["2.2.2"]}
    assert f.resource_type == "AWS::EC2::Snapshot"
    assert "snap-0aaa1111" in f.resource_id
