"""
Tests for poc_contracts.py — Pydantic v2 models.

Covers:
1. Valid construction of all major models
2. Field validation on invalid inputs raises ValidationError
3. NormalizedFindings roundtrip (serialize → deserialize)
4. model_validator enforcement on NormalizedFindings summary counts
"""

import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from backend.app.poc_contracts import (
    Severity,
    Provider,
    Benchmark,
    FindingStatus,
    SecurityFinding,
    ComplianceCheck,
    ScanSummary,
    NormalizedFindings,
    NormalizedReport,
    ScanRequest,
    ScanResult,
    ScanResponse,
    FilterCriteria,
    ReportPolicy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_security_finding(**overrides) -> dict:
    base = {
        "finding_id": "f-001",
        "check_id": "iam_check_001",
        "title": "IAM check title",
        "severity": Severity.HIGH,
        "status": FindingStatus.FAIL,
        "resource_id": "/subscriptions/abc/resources/def",
        "resource_type": "microsoft.iam/serviceprincipals",
        "region": "eastus",
        "cloud_account_id": "1e11569b-de29-4e51-ad5e-8f7facd3d07f",
        "description": "Description of the finding.",
        "risk": "High risk explanation.",
        "remediation": "Fix the thing.",
        "references": ["https://example.com/ref1"],
        "compliance": {"CIS-2.0": ["1.1"], "CIS-2.1": ["1.1"]},
        "categories": ["iam"],
        "finding_uid": "prowler-azure-iam_check_001-abc",
        "scan_time": "2026-05-13T09:10:55.058583",
    }
    base.update(overrides)
    return base


def make_compliance_check(**overrides) -> dict:
    base = {
        "control_id": "1.1",
        "framework": "CIS",
        "framework_version": "2.0",
        "title": "Control 1.1 title",
        "status": FindingStatus.FAIL,
        "related_findings": ["f-001"],
        "pass_count": 0,
        "fail_count": 1,
        "manual_count": 0,
    }
    base.update(overrides)
    return base


def make_scan_summary(**overrides) -> dict:
    base = {
        "provider": Provider.AZURE,
        "benchmark": Benchmark.CIS_2_0_AZURE,
        "cloud_account_id": "1e11569b-de29-4e51-ad5e-8f7facd3d07f",
        "started_at": "2026-05-13T09:10:55.000000",
        "finished_at": "2026-05-13T09:15:00.000000",
        "total": 2,
        "passed": 1,
        "failed": 1,
        "manual": 0,
        "severity_breakdown": {"High": 1, "Medium": 0, "Low": 0},
        "fixture_mode": False,
    }
    base.update(overrides)
    return base


def make_normalized_findings(n_fail: int = 1, n_pass: int = 1) -> dict:
    findings = []
    for i in range(n_fail):
        findings.append(make_security_finding(
            finding_id=f"f-fail-{i}",
            status=FindingStatus.FAIL,
            severity=Severity.HIGH,
        ))
    for i in range(n_pass):
        findings.append(make_security_finding(
            finding_id=f"f-pass-{i}",
            status=FindingStatus.PASS,
            severity=Severity.LOW,
        ))

    compliance = [
        make_compliance_check(
            control_id="1.1",
            status=FindingStatus.FAIL,
            fail_count=n_fail,
            pass_count=n_pass,
        )
    ]

    summary = make_scan_summary(
        total=n_fail + n_pass,
        passed=n_pass,
        failed=n_fail,
        severity_breakdown={"High": n_fail, "Medium": 0, "Low": n_pass},
    )

    return {
        "security_findings": findings,
        "compliance_checks": compliance,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# SecurityFinding
# ---------------------------------------------------------------------------

class TestSecurityFinding:
    def test_valid_construction(self):
        finding = SecurityFinding(**make_security_finding())
        assert finding.check_id == "iam_check_001"
        assert finding.status == FindingStatus.FAIL
        assert finding.severity == Severity.HIGH

    def test_invalid_status_raises(self):
        data = make_security_finding(status="UNKNOWN_STATUS")
        with pytest.raises(ValidationError):
            SecurityFinding(**data)

    def test_invalid_severity_raises(self):
        data = make_security_finding(severity="ULTRA")
        with pytest.raises(ValidationError):
            SecurityFinding(**data)

    def test_missing_required_field_raises(self):
        data = make_security_finding()
        del data["check_id"]
        with pytest.raises(ValidationError):
            SecurityFinding(**data)

    def test_references_default_empty(self):
        data = make_security_finding()
        del data["references"]
        finding = SecurityFinding(**data)
        assert finding.references == []

    def test_compliance_default_empty(self):
        data = make_security_finding()
        del data["compliance"]
        finding = SecurityFinding(**data)
        assert finding.compliance == {}


# ---------------------------------------------------------------------------
# ComplianceCheck
# ---------------------------------------------------------------------------

class TestComplianceCheck:
    def test_valid_construction(self):
        check = ComplianceCheck(**make_compliance_check())
        assert check.control_id == "1.1"
        assert check.status == FindingStatus.FAIL

    def test_missing_control_id_raises(self):
        data = make_compliance_check()
        del data["control_id"]
        with pytest.raises(ValidationError):
            ComplianceCheck(**data)

    def test_negative_counts_rejected(self):
        data = make_compliance_check(fail_count=-1)
        with pytest.raises(ValidationError):
            ComplianceCheck(**data)


# ---------------------------------------------------------------------------
# ScanSummary
# ---------------------------------------------------------------------------

class TestScanSummary:
    def test_valid_construction(self):
        summary = ScanSummary(**make_scan_summary())
        assert summary.total == 2
        assert summary.passed == 1
        assert summary.failed == 1

    def test_negative_total_rejected(self):
        data = make_scan_summary(total=-1)
        with pytest.raises(ValidationError):
            ScanSummary(**data)


# ---------------------------------------------------------------------------
# NormalizedFindings
# ---------------------------------------------------------------------------

class TestNormalizedFindings:
    def test_valid_construction(self):
        nf = NormalizedFindings(**make_normalized_findings())
        assert len(nf.security_findings) == 2
        assert len(nf.compliance_checks) == 1

    def test_missing_security_findings_raises(self):
        data = make_normalized_findings()
        del data["security_findings"]
        with pytest.raises(ValidationError):
            NormalizedFindings(**data)

    def test_missing_compliance_checks_raises(self):
        data = make_normalized_findings()
        del data["compliance_checks"]
        with pytest.raises(ValidationError):
            NormalizedFindings(**data)

    def test_missing_summary_raises(self):
        data = make_normalized_findings()
        del data["summary"]
        with pytest.raises(ValidationError):
            NormalizedFindings(**data)

    def test_summary_count_mismatch_raises(self):
        """model_validator must reject when summary.total != len(security_findings)."""
        data = make_normalized_findings(n_fail=1, n_pass=1)
        # Tamper with summary total to create a mismatch
        data["summary"]["total"] = 999
        with pytest.raises(ValidationError):
            NormalizedFindings(**data)

    def test_summary_passed_mismatch_raises(self):
        """model_validator must reject when summary.passed != count of PASS findings."""
        data = make_normalized_findings(n_fail=1, n_pass=1)
        data["summary"]["passed"] = 999
        with pytest.raises(ValidationError):
            NormalizedFindings(**data)

    def test_summary_failed_mismatch_raises(self):
        """model_validator must reject when summary.failed != count of FAIL findings."""
        data = make_normalized_findings(n_fail=1, n_pass=1)
        data["summary"]["failed"] = 999
        with pytest.raises(ValidationError):
            NormalizedFindings(**data)

    def test_roundtrip_serialize_deserialize(self):
        """Serialize to dict, then reconstruct — must be equal."""
        nf_original = NormalizedFindings(**make_normalized_findings(n_fail=2, n_pass=3))
        serialized = nf_original.model_dump()
        nf_restored = NormalizedFindings.model_validate(serialized)
        assert nf_restored.summary.total == nf_original.summary.total
        assert nf_restored.summary.passed == nf_original.summary.passed
        assert nf_restored.summary.failed == nf_original.summary.failed
        assert len(nf_restored.security_findings) == len(nf_original.security_findings)

    def test_json_roundtrip(self):
        """Serialize to JSON, then reconstruct — must be equal."""
        nf_original = NormalizedFindings(**make_normalized_findings(n_fail=1, n_pass=2))
        json_str = nf_original.model_dump_json()
        nf_restored = NormalizedFindings.model_validate_json(json_str)
        assert nf_restored.summary.total == nf_original.summary.total


# ---------------------------------------------------------------------------
# ScanRequest
# ---------------------------------------------------------------------------

class TestScanRequest:
    def test_valid_non_fixture(self):
        req = ScanRequest(
            provider=Provider.AZURE,
            benchmark=Benchmark.CIS_2_0_AZURE,
            cloud_account_id="abc-123",
        )
        assert req.fixture_mode is False
        assert req.fixture_path is None

    def test_fixture_mode_with_path(self):
        req = ScanRequest(
            provider=Provider.AZURE,
            benchmark=Benchmark.CIS_2_0_AZURE,
            cloud_account_id="abc-123",
            fixture_mode=True,
            fixture_path="tests/fixtures/prowler_azure_sample.json",
        )
        assert req.fixture_mode is True
        assert req.fixture_path == "tests/fixtures/prowler_azure_sample.json"

    def test_missing_provider_raises(self):
        with pytest.raises(ValidationError):
            ScanRequest(
                benchmark=Benchmark.CIS_2_0_AZURE,
                cloud_account_id="abc-123",
            )


# ---------------------------------------------------------------------------
# FilterCriteria
# ---------------------------------------------------------------------------

class TestFilterCriteria:
    def test_all_none_is_valid(self):
        fc = FilterCriteria()
        assert fc.min_severity is None
        assert fc.only_failed is False

    def test_with_values(self):
        fc = FilterCriteria(
            min_severity=Severity.HIGH,
            only_failed=True,
            include_controls=["1.1", "1.2"],
            exclude_controls=["2.1"],
            resource_types=["microsoft.iam/serviceprincipals"],
        )
        assert fc.only_failed is True
        assert "1.1" in fc.include_controls


# ---------------------------------------------------------------------------
# ReportPolicy
# ---------------------------------------------------------------------------

class TestReportPolicy:
    def test_valid_construction(self):
        policy = ReportPolicy(
            title="CIS Level 1 Report",
            audience="Security Team",
            benchmark=Benchmark.CIS_2_0_AZURE,
            filter=FilterCriteria(only_failed=True),
        )
        assert policy.title == "CIS Level 1 Report"
        assert policy.include_remediation is True  # default

    def test_missing_title_raises(self):
        with pytest.raises(ValidationError):
            ReportPolicy(
                audience="Team",
                benchmark=Benchmark.CIS_2_0_AZURE,
                filter=FilterCriteria(),
            )


# ---------------------------------------------------------------------------
# ScanResult (W-2 housekeeping — spec-verify PR 1 warning)
# ---------------------------------------------------------------------------

class TestScanResult:
    def test_valid_construction_with_defaults(self):
        """ScanResult can be constructed with no arguments (all fields optional)."""
        result = ScanResult()
        assert result.raw_path is None
        assert result.raw_payload is None
        assert result.started_at is None
        assert result.finished_at is None
        assert result.returncode is None
        assert result.fixture_mode is False
        assert result.error is None

    def test_raw_payload_accepts_list(self):
        """raw_payload accepts a list of dicts (Prowler OCSF JSON top-level array)."""
        payload = [{"finding_id": "f1"}, {"finding_id": "f2"}]
        result = ScanResult(raw_payload=payload)
        assert result.raw_payload == payload
        assert len(result.raw_payload) == 2

    def test_error_accepts_none(self):
        result = ScanResult(error=None)
        assert result.error is None

    def test_error_accepts_string(self):
        result = ScanResult(error="Prowler CLI not found on PATH.")
        assert result.error == "Prowler CLI not found on PATH."

    def test_fixture_mode_default_false(self):
        result = ScanResult()
        assert result.fixture_mode is False

    def test_fixture_mode_set_true(self):
        result = ScanResult(fixture_mode=True, raw_path="tests/fixtures/prowler_azure_sample.json")
        assert result.fixture_mode is True


# ---------------------------------------------------------------------------
# Alias smoke tests (W-1 housekeeping)
# ---------------------------------------------------------------------------

class TestAliases:
    def test_normalized_report_is_normalized_findings(self):
        """NormalizedReport alias must point to the same class."""
        assert NormalizedReport is NormalizedFindings

    def test_scan_response_is_scan_result(self):
        """ScanResponse alias must point to the same class."""
        assert ScanResponse is ScanResult


# ---------------------------------------------------------------------------
# RENAME-1 spec tests (cloud_account_id rename)
# ---------------------------------------------------------------------------

class TestCloudAccountIdRename:
    """Spec RENAME-1: cloud_account_id must replace subscription_id on all models."""

    def test_security_finding_uses_cloud_account_id(self):
        """RENAME-1-1: SecurityFinding must accept cloud_account_id and expose it."""
        data = make_security_finding()
        finding = SecurityFinding(**data)
        assert finding.cloud_account_id == "1e11569b-de29-4e51-ad5e-8f7facd3d07f"
        assert not hasattr(finding, "subscription_id")

    def test_security_finding_rejects_subscription_id(self):
        """RENAME-1-2: SecurityFinding must raise ValidationError when subscription_id is passed."""
        data = {k: v for k, v in make_security_finding().items() if k != "cloud_account_id"}
        data["subscription_id"] = "should-fail"
        with pytest.raises(ValidationError):
            SecurityFinding(**data)

    def test_scan_summary_serializes_cloud_account_id(self):
        """RENAME-1-3: ScanSummary.model_dump() must contain cloud_account_id, not subscription_id."""
        summary = ScanSummary(**make_scan_summary())
        dumped = summary.model_dump()
        assert "cloud_account_id" in dumped
        assert dumped["cloud_account_id"] == "1e11569b-de29-4e51-ad5e-8f7facd3d07f"
        assert "subscription_id" not in dumped

    def test_scan_request_round_trips_cloud_account_id(self):
        """RENAME-1-4: ScanRequest must construct with cloud_account_id without error."""
        req = ScanRequest(
            provider=Provider.AZURE,
            benchmark=Benchmark.CIS_2_0_AZURE,
            cloud_account_id="sub-abc",
            fixture_mode=True,
        )
        assert req.cloud_account_id == "sub-abc"

    def test_no_subscription_id_kwarg_in_test_suite(self):
        """RENAME-1-5: No test file in tests/ may reference subscription_id= as a kwarg for these models.

        Pattern: subscription_id= appearing as a Python keyword argument (preceded by a comma
        or opening paren and optional whitespace, NOT inside a string literal).
        """
        import re
        from pathlib import Path

        test_dir = Path("tests")
        # Match subscription_id= used as a Python kwarg (not inside a quoted string).
        # We look for the pattern where subscription_id= is NOT preceded by ["'] (dict key string).
        kwarg_pattern = re.compile(r'(?<!["\'])subscription_id\s*=(?!=)')
        violations = []
        for py_file in sorted(test_dir.glob("*.py")):
            # Skip this file — it intentionally mentions the old name in comments/docstrings
            if py_file.name == "test_contracts.py":
                continue
            content = py_file.read_text()
            for lineno, line in enumerate(content.splitlines(), 1):
                # Skip comment lines
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                # Skip lines that are docstrings or string literals discussing the field name
                if stripped.startswith('"""') or stripped.startswith("'''") or stripped.startswith('"') or stripped.startswith("'"):
                    continue
                if kwarg_pattern.search(line):
                    violations.append(f"{py_file}:{lineno}: {stripped}")
        assert violations == [], (
            f"These lines still use subscription_id= as a kwarg:\n" + "\n".join(violations)
        )


# ---------------------------------------------------------------------------
# RENAME-2 spec tests — Provider.AWS and Benchmark AWS enum expansion (PR 2)
# ---------------------------------------------------------------------------

class TestAWSEnumExpansion:
    """Spec RENAME-2: Provider.AWS and three AWS CIS benchmarks must exist."""

    def test_provider_aws_enum_value(self):
        """RENAME-2-1: Provider('aws') must return Provider.AWS."""
        assert Provider("aws") == Provider.AWS
        assert Provider.AWS.value == "aws"

    def test_benchmark_aws_enum_values(self):
        """RENAME-2-2: All three AWS CIS benchmarks must be valid enum members."""
        assert Benchmark("cis_1.5_aws") == Benchmark.CIS_1_5_AWS
        assert Benchmark("cis_2.0_aws") == Benchmark.CIS_2_0_AWS
        assert Benchmark("cis_3.0_aws") == Benchmark.CIS_3_0_AWS

    def test_scan_request_accepts_aws_provider_and_benchmark(self):
        """RENAME-2-3: ScanRequest must validate with Provider.AWS and AWS benchmark."""
        req = ScanRequest(
            provider=Provider.AWS,
            benchmark=Benchmark.CIS_2_0_AWS,
            cloud_account_id="123456789012",
        )
        assert req.provider == Provider.AWS
        assert req.benchmark == Benchmark.CIS_2_0_AWS
        assert req.cloud_account_id == "123456789012"
