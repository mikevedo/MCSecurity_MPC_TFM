"""
test_s3_normalizer.py — TDD tests for _s3_result_to_normalized in backend/app/chat.py

Tests:
- test_s3_normalizer_maps_public_bucket_to_cis_2_1_5
- test_s3_normalizer_maps_unencrypted_bucket
- test_s3_normalizer_maps_no_versioning
- test_s3_normalizer_maps_no_logging
- test_s3_normalizer_returns_none_on_failure
"""

from __future__ import annotations

import pytest

from backend.app.chat import _s3_result_to_normalized
from backend.app.poc_contracts import Benchmark, FindingStatus, Provider, Severity


def _make_s3_result(**overrides) -> dict:
    """Build a minimal successful S3 tool result dict."""
    base = {
        "success": True,
        "summary": {
            "total_buckets": 1,
            "public_buckets": 0,
            "unencrypted_buckets": 0,
            "buckets_without_versioning": 0,
            "buckets_without_logging": 0,
            "total_issues": 0,
        },
        "public_buckets": [],
        "unencrypted_buckets": [],
        "buckets_without_versioning": [],
        "buckets_without_logging": [],
    }
    base.update(overrides)
    return base


def test_s3_normalizer_maps_public_bucket_to_cis_2_1_5():
    """A public bucket in tool output maps to check_id s3_bucket_public_access, severity HIGH, CIS 2.1.5."""
    tool_out = _make_s3_result(
        public_buckets=[
            {
                "bucket_name": "leaky-bucket",
                "reason": "Public access block disabled",
            }
        ],
        summary={
            "total_buckets": 1,
            "public_buckets": 1,
            "unencrypted_buckets": 0,
            "buckets_without_versioning": 0,
            "buckets_without_logging": 0,
            "total_issues": 1,
        },
    )

    nf = _s3_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    assert nf.summary.total == 1
    f = nf.security_findings[0]
    assert f.check_id == "s3_bucket_public_access"
    assert f.severity == Severity.HIGH
    assert f.status == FindingStatus.FAIL
    assert f.compliance == {"CIS": ["2.1.5"]}
    assert f.resource_id == "arn:aws:s3:::leaky-bucket"


def test_s3_normalizer_maps_unencrypted_bucket():
    """An unencrypted bucket maps to check_id s3_bucket_default_encryption_disabled, severity MEDIUM, CIS 2.1.1."""
    tool_out = _make_s3_result(
        unencrypted_buckets=[{"bucket_name": "plain-bucket"}],
        summary={
            "total_buckets": 1,
            "public_buckets": 0,
            "unencrypted_buckets": 1,
            "buckets_without_versioning": 0,
            "buckets_without_logging": 0,
            "total_issues": 1,
        },
    )

    nf = _s3_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    f = nf.security_findings[0]
    assert f.check_id == "s3_bucket_default_encryption_disabled"
    assert f.severity == Severity.MEDIUM
    assert f.compliance == {"CIS": ["2.1.1"]}
    assert f.resource_id == "arn:aws:s3:::plain-bucket"


def test_s3_normalizer_maps_no_versioning():
    """A bucket without versioning maps to check_id s3_bucket_no_mfa_delete, severity LOW, CIS 2.1.3."""
    tool_out = _make_s3_result(
        buckets_without_versioning=[{"bucket_name": "no-version-bucket"}],
        summary={
            "total_buckets": 1,
            "public_buckets": 0,
            "unencrypted_buckets": 0,
            "buckets_without_versioning": 1,
            "buckets_without_logging": 0,
            "total_issues": 1,
        },
    )

    nf = _s3_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    f = nf.security_findings[0]
    assert f.check_id == "s3_bucket_no_mfa_delete"
    assert f.severity == Severity.LOW
    assert f.compliance == {"CIS": ["2.1.3"]}
    assert f.resource_id == "arn:aws:s3:::no-version-bucket"


def test_s3_normalizer_maps_no_logging():
    """A bucket without logging maps to check_id s3_bucket_access_logging_disabled, severity LOW, CIS 2.1.2."""
    tool_out = _make_s3_result(
        buckets_without_logging=[{"bucket_name": "no-log-bucket"}],
        summary={
            "total_buckets": 1,
            "public_buckets": 0,
            "unencrypted_buckets": 0,
            "buckets_without_versioning": 0,
            "buckets_without_logging": 1,
            "total_issues": 1,
        },
    )

    nf = _s3_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is not None
    f = nf.security_findings[0]
    assert f.check_id == "s3_bucket_access_logging_disabled"
    assert f.severity == Severity.LOW
    assert f.compliance == {"CIS": ["2.1.2"]}
    assert f.resource_id == "arn:aws:s3:::no-log-bucket"


def test_s3_normalizer_returns_none_on_failure():
    """A tool result with success=False returns None."""
    tool_out = {"success": False, "error": "Auth failed: some error"}

    nf = _s3_result_to_normalized(
        tool_out,
        account_id="123456789012",
        provider=Provider.AWS,
        benchmark=Benchmark.CIS_6_0_AWS,
    )

    assert nf is None
