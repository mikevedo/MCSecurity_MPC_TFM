"""
test_cloudtrail_normalizer.py — TDD tests for _cloudtrail_result_to_normalized in backend/app/chat.py

Tests:
- test_cloudtrail_normalizer_maps_single_region_trail: CIS 3.1, HIGH, cloudtrail_multi_region_enabled
- test_cloudtrail_normalizer_maps_log_validation_disabled: CIS 3.2, MEDIUM, cloudtrail_log_file_validation_enabled
- test_cloudtrail_normalizer_maps_no_cloudwatch: CIS 3.4, MEDIUM, cloudtrail_cloudwatch_logging_enabled
- test_cloudtrail_normalizer_maps_missing_metric_filter: CIS 3.3, MEDIUM, cloudwatch_log_metric_filter_*
"""

from __future__ import annotations

import pytest

from backend.app.chat import _cloudtrail_result_to_normalized
from backend.app.poc_contracts import Benchmark, FindingStatus, Provider, Severity


def _make_ct_result(**overrides) -> dict:
    """Build a minimal successful CloudTrail tool result dict."""
    base = {
        "success": True,
        "region": "us-east-1",
        "summary": {
            "trails_checked": 0,
            "trail_issues": 0,
            "missing_metric_filters": 0,
            "total_issues": 0,
        },
        "trail_issues": [],
        "missing_metric_filters": [],
    }
    base.update(overrides)
    return base


def test_cloudtrail_normalizer_maps_single_region_trail():
    """
    A single-region trail issue maps to:
    check_id=cloudtrail_multi_region_enabled, severity=HIGH, CIS 3.1
    """
    tool_out = _make_ct_result(
        trail_issues=[
            {
                "trail_name": "single-region-trail",
                "trail_arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/single-region-trail",
                "issue": "Trail is not multi-region (CIS 3.1)",
                "severity": "high",
            }
        ],
        summary={
            "trails_checked": 1,
            "trail_issues": 1,
            "missing_metric_filters": 0,
            "total_issues": 1,
        },
    )

    nf = _cloudtrail_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "cloudtrail_multi_region_enabled"
    assert f.severity == Severity.HIGH
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["3.1"]}
    assert f.resource_type == "AWS::CloudTrail::Trail"
    assert "single-region-trail" in f.resource_id


def test_cloudtrail_normalizer_maps_log_validation_disabled():
    """
    A log validation disabled issue maps to:
    check_id=cloudtrail_log_file_validation_enabled, severity=MEDIUM, CIS 3.2
    """
    tool_out = _make_ct_result(
        trail_issues=[
            {
                "trail_name": "no-validation-trail",
                "trail_arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/no-validation-trail",
                "issue": "Log file validation disabled (CIS 3.2)",
                "severity": "medium",
            }
        ],
        summary={
            "trails_checked": 1,
            "trail_issues": 1,
            "missing_metric_filters": 0,
            "total_issues": 1,
        },
    )

    nf = _cloudtrail_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "cloudtrail_log_file_validation_enabled"
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["3.2"]}
    assert f.resource_type == "AWS::CloudTrail::Trail"
    assert "no-validation-trail" in f.resource_id


def test_cloudtrail_normalizer_maps_no_cloudwatch():
    """
    A missing CloudWatch integration issue maps to:
    check_id=cloudtrail_cloudwatch_logging_enabled, severity=MEDIUM, CIS 3.4
    """
    tool_out = _make_ct_result(
        trail_issues=[
            {
                "trail_name": "no-cw-trail",
                "trail_arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/no-cw-trail",
                "issue": "Not integrated with CloudWatch Logs (CIS 3.4)",
                "severity": "medium",
            }
        ],
        summary={
            "trails_checked": 1,
            "trail_issues": 1,
            "missing_metric_filters": 0,
            "total_issues": 1,
        },
    )

    nf = _cloudtrail_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "cloudtrail_cloudwatch_logging_enabled"
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["3.4"]}
    assert f.resource_type == "AWS::CloudTrail::Trail"
    assert "no-cw-trail" in f.resource_id


def test_cloudtrail_normalizer_maps_missing_metric_filter():
    """
    A missing metric filter maps to:
    check_id=cloudwatch_log_metric_filter_{filter_name}, severity=MEDIUM, CIS 3.3
    """
    tool_out = _make_ct_result(
        missing_metric_filters=[
            {
                "filter_name": "root_account_usage",
                "cis_control": "3.3",
                "description": "Root account usage — CIS 3.3",
            }
        ],
        summary={
            "trails_checked": 1,
            "trail_issues": 0,
            "missing_metric_filters": 1,
            "total_issues": 1,
        },
    )

    nf = _cloudtrail_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "cloudwatch_log_metric_filter_root_account_usage"
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["3.3"]}
    assert f.resource_type == "AWS::CloudWatch::MetricFilter"
    assert f.resource_id == "root_account_usage"


def test_cloudtrail_normalizer_returns_none_on_failure():
    """Returns None when success=False."""
    tool_out = {"success": False, "error": "Auth failed"}
    nf = _cloudtrail_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )
    assert nf is None
