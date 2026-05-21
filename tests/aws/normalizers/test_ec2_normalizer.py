"""
test_ec2_normalizer.py — TDD tests for _ec2_result_to_normalized in backend/app/chat.py

Tests:
- test_ec2_imdsv2_not_enforced_maps_to_cis_5_6: IMDSv2 finding → HIGH/CIS 5.6
- test_ec2_public_ip_maps_to_cis_5_5: public IP finding → MEDIUM/CIS 5.5
- test_ec2_monitoring_disabled_maps_to_low_no_cis: monitoring disabled → LOW/no CIS code
"""

from __future__ import annotations

from backend.app.chat import _ec2_result_to_normalized
from backend.app.poc_contracts import Benchmark, FindingStatus, Provider, Severity


_ACCOUNT_ID = "123456789012"
_REGION = "us-east-1"


def _make_result(
    imdsv2=None,
    public_ip=None,
    monitoring=None,
    region=_REGION,
):
    """Build a minimal analyze_ec2_security-shaped result dict."""
    return {
        "success": True,
        "region": region,
        "summary": {
            "imdsv2_not_enforced": len(imdsv2 or []),
            "public_ip_instances": len(public_ip or []),
            "monitoring_disabled": len(monitoring or []),
            "total_issues": len(imdsv2 or []) + len(public_ip or []) + len(monitoring or []),
        },
        "imdsv2_not_enforced": imdsv2 or [],
        "public_ip_instances": public_ip or [],
        "monitoring_disabled": monitoring or [],
    }


def test_ec2_imdsv2_not_enforced_maps_to_cis_5_6():
    """IMDSv2 not enforced finding → check_id=ec2_instance_imdsv2_enabled, HIGH, CIS 5.6."""
    tool_out = _make_result(
        imdsv2=[{
            "instance_id": "i-0123456789abcdef0",
            "instance_type": "t3.micro",
            "state": "running",
            "http_tokens": "optional",
        }]
    )

    nf = _ec2_result_to_normalized(
        tool_out,
        account_id=_ACCOUNT_ID,
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "ec2_instance_imdsv2_enabled"
    assert f.severity == Severity.HIGH
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["5.6"]}
    assert "i-0123456789abcdef0" in f.resource_id
    assert f.resource_type == "AWS::EC2::Instance"


def test_ec2_public_ip_maps_to_cis_5_5():
    """Instance with public IP → check_id=ec2_instance_public_ip, MEDIUM, CIS 5.5."""
    tool_out = _make_result(
        public_ip=[{
            "instance_id": "i-0abcdef1234567890",
            "instance_type": "t3.small",
            "public_ip": "54.123.45.67",
            "state": "running",
        }]
    )

    nf = _ec2_result_to_normalized(
        tool_out,
        account_id=_ACCOUNT_ID,
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "ec2_instance_public_ip"
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["5.5"]}
    assert "i-0abcdef1234567890" in f.resource_id
    assert f.resource_type == "AWS::EC2::Instance"


def test_ec2_monitoring_disabled_maps_to_low_no_cis():
    """Monitoring disabled → check_id=ec2_instance_detailed_monitoring_enabled, LOW, CIS=[]."""
    tool_out = _make_result(
        monitoring=[{
            "instance_id": "i-0deadbeef0000000",
            "instance_type": "t2.micro",
            "monitoring_state": "disabled",
        }]
    )

    nf = _ec2_result_to_normalized(
        tool_out,
        account_id=_ACCOUNT_ID,
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "ec2_instance_detailed_monitoring_enabled"
    assert f.severity == Severity.LOW
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": []}
    assert "i-0deadbeef0000000" in f.resource_id
    assert f.resource_type == "AWS::EC2::Instance"


def test_ec2_normalizer_returns_none_on_failure():
    """When success=False, the normalizer must return None."""
    tool_out = {"success": False, "error": "Auth failed"}
    nf = _ec2_result_to_normalized(
        tool_out,
        account_id=_ACCOUNT_ID,
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )
    assert nf is None
