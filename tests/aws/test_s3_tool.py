"""
test_s3_tool.py — TDD tests for MCP_SERVER/tools/aws/s3.py

Tests:
- test_s3_detects_public_bucket: bucket with public access block disabled appears in public_buckets
- test_s3_clean_bucket_no_findings: private, encrypted, versioned, logged bucket has no findings
- test_s3_auth_failure_returns_error_dict: invalid role_arn returns success=False + error key
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from MCP_SERVER.tools.aws.s3 import analyze_s3_security


@mock_aws
def test_s3_detects_public_bucket():
    """A bucket with public access block disabled should appear in public_buckets."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="public-test")
    s3.put_public_access_block(
        Bucket="public-test",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )

    result = analyze_s3_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    assert any(b["bucket_name"] == "public-test" for b in result["public_buckets"])


@mock_aws
def test_s3_clean_bucket_no_findings():
    """A private, encrypted, versioned, logged bucket should not appear in any finding list."""
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="hardened-bucket")

    # Block all public access
    s3.put_public_access_block(
        Bucket="hardened-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    # Enable default encryption
    s3.put_bucket_encryption(
        Bucket="hardened-bucket",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256",
                    }
                }
            ],
        },
    )

    # Enable versioning
    s3.put_bucket_versioning(
        Bucket="hardened-bucket",
        VersioningConfiguration={"Status": "Enabled"},
    )

    # Enable logging: moto requires a separate log-target bucket with the proper ACL
    s3.create_bucket(Bucket="log-target-bucket")
    s3.put_bucket_acl(
        Bucket="log-target-bucket",
        ACL="log-delivery-write",
    )
    s3.put_bucket_logging(
        Bucket="hardened-bucket",
        BucketLoggingStatus={
            "LoggingEnabled": {
                "TargetBucket": "log-target-bucket",
                "TargetPrefix": "access-logs/",
            }
        },
    )

    result = analyze_s3_security(role_arn=None, region="us-east-1")

    assert result["success"] is True
    assert not any(b["bucket_name"] == "hardened-bucket" for b in result["public_buckets"])
    assert not any(b["bucket_name"] == "hardened-bucket" for b in result["unencrypted_buckets"])
    assert not any(b["bucket_name"] == "hardened-bucket" for b in result["buckets_without_versioning"])
    assert not any(b["bucket_name"] == "hardened-bucket" for b in result["buckets_without_logging"])


def test_s3_auth_failure_returns_error_dict():
    """An invalid role_arn that cannot be assumed should return success=False with an error key."""
    result = analyze_s3_security(
        role_arn="arn:aws:iam::000000000000:role/nonexistent-role",
        region="us-east-1",
    )

    assert result["success"] is False
    assert "error" in result
