"""
test_cloudtrail_tool.py — TDD tests for MCP_SERVER/tools/aws/cloudtrail.py

Tests:
- test_cloudtrail_detects_single_region_trail: single-region trail flagged with multi-region issue
- test_cloudtrail_detects_log_validation_disabled: trail without log validation flagged
- test_cloudtrail_detects_no_cloudwatch_integration: trail without CloudWatch integration flagged
- test_cloudtrail_detects_missing_metric_filter: trail with CW integration but missing metric filter
- test_cloudtrail_healthy_trail_no_findings: multi-region trail with validation has no multi-region/validation issues
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from MCP_SERVER.tools.aws.cloudtrail import analyze_cloudtrail_security


@mock_aws
def test_cloudtrail_detects_single_region_trail():
    """A single-region trail should appear in trail_issues with a multi-region issue."""
    # Create an S3 bucket for CloudTrail (required)
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="ct-logs-bucket")

    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(
        Name="single-region-trail",
        S3BucketName="ct-logs-bucket",
        IsMultiRegionTrail=False,
    )
    ct.start_logging(Name="single-region-trail")

    result = analyze_cloudtrail_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    trail_issue_names = [issue["trail_name"] for issue in result["trail_issues"]]
    assert "single-region-trail" in trail_issue_names

    # Specifically the multi-region issue
    multi_region_issues = [
        issue for issue in result["trail_issues"]
        if issue["trail_name"] == "single-region-trail"
        and "multi-region" in issue["issue"].lower()
    ]
    assert len(multi_region_issues) >= 1, "Expected a multi-region issue for single-region trail"


@mock_aws
def test_cloudtrail_detects_log_validation_disabled():
    """A trail without log file validation should appear in trail_issues with a validation issue."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="ct-logs-noval")

    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(
        Name="no-validation-trail",
        S3BucketName="ct-logs-noval",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=False,
    )
    ct.start_logging(Name="no-validation-trail")

    result = analyze_cloudtrail_security(role_arn=None, region="us-east-1")

    assert result["success"] is True

    validation_issues = [
        issue for issue in result["trail_issues"]
        if issue["trail_name"] == "no-validation-trail"
        and "validation" in issue["issue"].lower()
    ]
    assert len(validation_issues) >= 1, "Expected a log validation issue"


@mock_aws
def test_cloudtrail_detects_no_cloudwatch_integration():
    """A trail without CloudWatch Logs integration should appear in trail_issues."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="ct-logs-nocw")

    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(
        Name="no-cloudwatch-trail",
        S3BucketName="ct-logs-nocw",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
        # No CloudWatchLogsLogGroupArn
    )
    ct.start_logging(Name="no-cloudwatch-trail")

    result = analyze_cloudtrail_security(role_arn=None, region="us-east-1")

    assert result["success"] is True

    cw_issues = [
        issue for issue in result["trail_issues"]
        if issue["trail_name"] == "no-cloudwatch-trail"
        and "cloudwatch" in issue["issue"].lower()
    ]
    assert len(cw_issues) >= 1, "Expected a CloudWatch integration issue"


@mock_aws
def test_cloudtrail_detects_missing_metric_filter():
    """
    A trail with CloudWatch Logs integration but missing metric filters
    should have entries in missing_metric_filters.
    """
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="ct-logs-cw")

    ct = boto3.client("cloudtrail", region_name="us-east-1")

    # We need to set CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn.
    # moto supports this on create_trail via update_trail.
    ct.create_trail(
        Name="cw-trail",
        S3BucketName="ct-logs-cw",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
        CloudWatchLogsLogGroupArn="arn:aws:logs:us-east-1:123456789012:log-group:CloudTrail/test:*",
        CloudWatchLogsRoleArn="arn:aws:iam::123456789012:role/CloudTrail_CWL_Role",
    )
    ct.start_logging(Name="cw-trail")

    # Mock boto3.client("logs").describe_metric_filters to return empty filters
    with patch("MCP_SERVER.tools.aws.cloudtrail.boto3") as mock_boto3:
        # Set up the cloudtrail client to return real moto results but mock logs client
        real_ct_client = boto3.client("cloudtrail", region_name="us-east-1")
        mock_logs_client = MagicMock()
        mock_logs_client.describe_metric_filters.return_value = {"metricFilters": []}

        def fake_client(service_name, **kwargs):
            if service_name == "cloudtrail":
                return real_ct_client
            if service_name == "logs":
                return mock_logs_client
            return boto3.client(service_name, **kwargs)

        mock_boto3.client.side_effect = fake_client

        result = analyze_cloudtrail_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    assert len(result["missing_metric_filters"]) >= 1, (
        "Expected at least one missing metric filter when describe_metric_filters returns empty"
    )


@mock_aws
def test_cloudtrail_healthy_trail_no_findings():
    """
    A multi-region trail with log validation enabled should NOT have
    multi-region or validation issues in trail_issues.
    (CloudWatch issue may still appear — that is acceptable.)
    """
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="ct-logs-healthy")

    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.create_trail(
        Name="healthy-trail",
        S3BucketName="ct-logs-healthy",
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
    )
    ct.start_logging(Name="healthy-trail")

    result = analyze_cloudtrail_security(role_arn=None, region="us-east-1")

    assert result["success"] is True

    # Should have NO multi-region or validation issues for healthy-trail
    multi_region_issues = [
        issue for issue in result["trail_issues"]
        if issue["trail_name"] == "healthy-trail"
        and "multi-region" in issue["issue"].lower()
    ]
    assert multi_region_issues == [], "Healthy multi-region trail should not have multi-region issues"

    validation_issues = [
        issue for issue in result["trail_issues"]
        if issue["trail_name"] == "healthy-trail"
        and "validation" in issue["issue"].lower()
    ]
    assert validation_issues == [], "Trail with log validation enabled should not have validation issues"
