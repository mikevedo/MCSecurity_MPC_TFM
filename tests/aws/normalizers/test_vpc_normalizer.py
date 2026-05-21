"""
test_vpc_normalizer.py — TDD tests for _vpc_result_to_normalized (backend/app/chat.py).

RED phase: written before _vpc_result_to_normalized exists.
All tests must be RED until T-5-5 implements the function.

Checks covered:
- Default VPC → check_id=vpc_default_security_group_restricts_all_traffic, severity=MEDIUM, CIS ["5.4"]
- VPC without flow logs → check_id=vpc_flow_logs_enabled, severity=MEDIUM, CIS ["5.1"]
- Subnet with auto public IP → check_id=ec2_subnet_no_public_ip_auto_assign, severity=LOW, CIS ["5.3"]
- None returned when result["success"] is False
"""

from __future__ import annotations

import pytest

from backend.app.chat import _vpc_result_to_normalized
from backend.app.poc_contracts import Benchmark, FindingStatus, Provider, Severity


def _make_result(**kwargs) -> dict:
    """Helper: build a minimal valid vpc tool output dict."""
    base = {
        "success": True,
        "region": "us-east-1",
        "summary": {
            "default_vpcs": 0,
            "vpcs_without_flow_logs": 0,
            "subnets_with_public_ip": 0,
            "total_issues": 0,
        },
        "default_vpcs": [],
        "vpcs_without_flow_logs": [],
        "subnets_with_public_ip": [],
    }
    base.update(kwargs)
    return base


ACCOUNT_ID = "123456789012"


def test_vpc_normalizer_default_vpc_maps_to_cis_5_4():
    """
    A default VPC finding must map to:
    - check_id = vpc_default_security_group_restricts_all_traffic
    - severity = MEDIUM
    - CIS = ["5.4"]
    - resource_type = AWS::EC2::VPC
    - resource_id = arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678
    - status = FAIL
    """
    tool_out = _make_result(
        default_vpcs=[
            {
                "vpc_id": "vpc-12345678",
                "cidr_block": "172.31.0.0/16",
                "state": "available",
            }
        ],
        summary={"default_vpcs": 1, "vpcs_without_flow_logs": 0, "subnets_with_public_ip": 0, "total_issues": 1},
    )
    nf = _vpc_result_to_normalized(
        tool_out, account_id=ACCOUNT_ID, provider=Provider.AWS, benchmark=Benchmark.CIS_6_0_AWS
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "vpc_default_security_group_restricts_all_traffic"
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["5.4"]}
    assert f.resource_type == "AWS::EC2::VPC"
    assert f.resource_id == f"arn:aws:ec2:us-east-1:{ACCOUNT_ID}:vpc/vpc-12345678"
    assert f.cloud_account_id == ACCOUNT_ID


def test_vpc_normalizer_no_flow_logs_maps_to_cis_5_1():
    """
    A VPC without flow logs must map to:
    - check_id = vpc_flow_logs_enabled
    - severity = MEDIUM
    - CIS = ["5.1"]
    - resource_type = AWS::EC2::VPC
    - resource_id = arn:aws:ec2:us-east-1:123456789012:vpc/vpc-abcdef12
    - status = FAIL
    """
    tool_out = _make_result(
        vpcs_without_flow_logs=[
            {
                "vpc_id": "vpc-abcdef12",
                "cidr_block": "10.0.0.0/16",
                "is_default": False,
            }
        ],
        summary={"default_vpcs": 0, "vpcs_without_flow_logs": 1, "subnets_with_public_ip": 0, "total_issues": 1},
    )
    nf = _vpc_result_to_normalized(
        tool_out, account_id=ACCOUNT_ID, provider=Provider.AWS, benchmark=Benchmark.CIS_6_0_AWS
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "vpc_flow_logs_enabled"
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["5.1"]}
    assert f.resource_type == "AWS::EC2::VPC"
    assert f.resource_id == f"arn:aws:ec2:us-east-1:{ACCOUNT_ID}:vpc/vpc-abcdef12"
    assert f.cloud_account_id == ACCOUNT_ID


def test_vpc_normalizer_subnet_auto_public_ip_maps_to_cis_5_3():
    """
    A subnet with auto-assign public IP must map to:
    - check_id = ec2_subnet_no_public_ip_auto_assign
    - severity = LOW
    - CIS = ["5.3"]
    - resource_type = AWS::EC2::Subnet
    - resource_id = arn:aws:ec2:us-east-1:123456789012:subnet/subnet-11223344
    - status = FAIL
    """
    tool_out = _make_result(
        subnets_with_public_ip=[
            {
                "subnet_id": "subnet-11223344",
                "vpc_id": "vpc-aabbccdd",
                "cidr_block": "10.1.1.0/24",
                "availability_zone": "us-east-1a",
            }
        ],
        summary={"default_vpcs": 0, "vpcs_without_flow_logs": 0, "subnets_with_public_ip": 1, "total_issues": 1},
    )
    nf = _vpc_result_to_normalized(
        tool_out, account_id=ACCOUNT_ID, provider=Provider.AWS, benchmark=Benchmark.CIS_6_0_AWS
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "ec2_subnet_no_public_ip_auto_assign"
    assert f.severity == Severity.LOW
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["5.3"]}
    assert f.resource_type == "AWS::EC2::Subnet"
    assert f.resource_id == f"arn:aws:ec2:us-east-1:{ACCOUNT_ID}:subnet/subnet-11223344"
    assert f.cloud_account_id == ACCOUNT_ID


def test_vpc_normalizer_returns_none_on_failure():
    """When result['success'] is False, _vpc_result_to_normalized must return None."""
    tool_out = {"success": False, "error": "Auth failed: something went wrong"}
    nf = _vpc_result_to_normalized(
        tool_out, account_id=ACCOUNT_ID, provider=Provider.AWS, benchmark=Benchmark.CIS_6_0_AWS
    )
    assert nf is None
