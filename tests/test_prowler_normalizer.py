"""
Tests for backend/app/normalizers/prowler_normalizer.py

Covers:
1. normalize() returns NormalizedFindings instance from real fixture
2. summary.total == 197, summary.failed == 136, summary.passed == 61
3. All SecurityFinding objects have non-empty check_id and title
4. compliance_checks is non-empty
5. Empty input returns zero-count summary with empty lists
6. Finding with empty resources list does not raise (uses empty strings)
7. FAIL + PASS same control_id → FAIL wins (precedence rule)

TDD: tests written before implementation (RED phase).
Implementation reference: sdd/poc-foundation/design Section 5 (Normalizer)
"""

import json
import pytest
from pathlib import Path

from backend.app.normalizers.prowler_normalizer import normalize
from backend.app.poc_contracts import (
    NormalizedFindings,
    FindingStatus,
    Severity,
    Provider,
    Benchmark,
    ScanRequest,
)

FIXTURE_PATH = Path("tests/fixtures/prowler_azure_sample.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_fixture() -> list[dict]:
    with open(FIXTURE_PATH) as f:
        return json.load(f)


def make_scan_request() -> ScanRequest:
    return ScanRequest(
        provider=Provider.AZURE,
        benchmark=Benchmark.CIS_2_0_AZURE,
        cloud_account_id="1e11569b-de29-4e51-ad5e-8f7facd3d07f",
        fixture_mode=True,
        fixture_path=str(FIXTURE_PATH),
    )


# ---------------------------------------------------------------------------
# Core normalization tests (real fixture)
# ---------------------------------------------------------------------------

class TestNormalizeWithRealFixture:
    def test_returns_normalized_findings_instance(self):
        """normalize() must return a NormalizedFindings object."""
        raw = load_fixture()
        result = normalize(raw, make_scan_request())
        assert isinstance(result, NormalizedFindings)

    def test_summary_total_matches_fixture(self):
        """197 total findings — matches real azure-cis-report.ocsf.json."""
        raw = load_fixture()
        result = normalize(raw, make_scan_request())
        assert result.summary.total == 197

    def test_summary_failed_matches_fixture(self):
        """136 FAIL findings confirmed from real fixture."""
        raw = load_fixture()
        result = normalize(raw, make_scan_request())
        assert result.summary.failed == 136

    def test_summary_passed_matches_fixture(self):
        """61 PASS findings confirmed from real fixture."""
        raw = load_fixture()
        result = normalize(raw, make_scan_request())
        assert result.summary.passed == 61

    def test_all_findings_have_non_empty_check_id(self):
        """Every SecurityFinding must have a non-empty check_id."""
        raw = load_fixture()
        result = normalize(raw, make_scan_request())
        for finding in result.security_findings:
            assert finding.check_id, f"Empty check_id found for finding {finding.finding_uid}"

    def test_all_findings_have_non_empty_title(self):
        """Every SecurityFinding must have a non-empty title."""
        raw = load_fixture()
        result = normalize(raw, make_scan_request())
        for finding in result.security_findings:
            assert finding.title, f"Empty title found for finding {finding.check_id}"

    def test_compliance_checks_is_non_empty(self):
        """Compliance checks must be populated from fixture data."""
        raw = load_fixture()
        result = normalize(raw, make_scan_request())
        assert len(result.compliance_checks) > 0

    def test_model_validator_passes(self):
        """NormalizedFindings model_validator must accept the output without errors."""
        raw = load_fixture()
        result = normalize(raw, make_scan_request())
        # model_validate round-trip triggers the validator again
        NormalizedFindings.model_validate(result.model_dump())

    def test_cloud_account_id_propagated(self):
        """summary.cloud_account_id must be extracted from fixture findings."""
        raw = load_fixture()
        result = normalize(raw, make_scan_request())
        assert result.summary.cloud_account_id == "1e11569b-de29-4e51-ad5e-8f7facd3d07f"

    def test_fixture_mode_flag(self):
        """summary.fixture_mode must be True when ScanRequest has fixture_mode=True."""
        raw = load_fixture()
        request = make_scan_request()
        result = normalize(raw, request)
        assert result.summary.fixture_mode is True


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------

class TestNormalizeEmptyInput:
    def test_empty_list_returns_zero_summary(self):
        """normalize([]) must return a valid NormalizedFindings with zero counts."""
        request = ScanRequest(
            provider=Provider.AZURE,
            benchmark=Benchmark.CIS_2_0_AZURE,
            cloud_account_id="sub-unknown",
        )
        result = normalize([], request)
        assert isinstance(result, NormalizedFindings)
        assert result.summary.total == 0
        assert result.summary.passed == 0
        assert result.summary.failed == 0
        assert result.security_findings == []
        assert result.compliance_checks == []

    def test_empty_list_passes_model_validator(self):
        """Zero-count NormalizedFindings must satisfy the model_validator invariant."""
        request = ScanRequest(
            provider=Provider.AZURE,
            benchmark=Benchmark.CIS_2_0_AZURE,
            cloud_account_id="sub-unknown",
        )
        result = normalize([], request)
        NormalizedFindings.model_validate(result.model_dump())


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestNormalizeEdgeCases:
    def test_finding_with_empty_resources_does_not_raise(self):
        """Finding with resources=[] must use empty strings, not raise IndexError."""
        raw = [{
            "metadata": {
                "event_code": "test_check",
                "product": {"version": "5.0"},
            },
            "finding_info": {
                "uid": "prowler-azure-test_check-sub-abc",
                "title": "Test check title",
                "desc": "Test description.",
                "created_time_dt": "2026-05-13T09:10:55.058583",
            },
            "status_code": "FAIL",
            "severity": "High",
            "resources": [],  # empty — must not raise IndexError
            "cloud": {
                "account": {"uid": "sub-abc"},
                "provider": "azure",
                "region": "global",
            },
            "remediation": {"desc": "Fix it.", "references": []},
            "risk_details": "Some risk.",
            "time_dt": "2026-05-13T09:10:55.058583",
            "unmapped": {
                "compliance": {"CIS-2.0": ["1.1"]},
                "categories": ["iam"],
            },
        }]
        request = ScanRequest(
            provider=Provider.AZURE,
            benchmark=Benchmark.CIS_2_0_AZURE,
            cloud_account_id="sub-abc",
        )
        result = normalize(raw, request)
        assert len(result.security_findings) == 1
        finding = result.security_findings[0]
        # resource_id, resource_type, region must be empty strings (not raise)
        assert finding.resource_id == ""
        assert finding.resource_type == ""
        assert finding.region == ""

    def test_compliance_precedence_fail_over_pass(self):
        """When same control_id appears in FAIL and PASS findings, aggregate = FAIL."""
        raw = [
            {
                "metadata": {
                    "event_code": "check_a",
                    "product": {"version": "5.0"},
                },
                "finding_info": {
                    "uid": "prowler-azure-check_a-sub-1",
                    "title": "Check A",
                    "desc": "Desc A.",
                    "created_time_dt": "2026-05-13T09:10:55.058583",
                },
                "status_code": "FAIL",
                "severity": "High",
                "resources": [],
                "cloud": {"account": {"uid": "sub-abc"}, "provider": "azure", "region": "global"},
                "remediation": {"desc": "Fix.", "references": []},
                "risk_details": "Risk.",
                "time_dt": "2026-05-13T09:10:55.058583",
                "unmapped": {
                    "compliance": {"CIS-2.0": ["1.1"]},
                    "categories": [],
                },
            },
            {
                "metadata": {
                    "event_code": "check_b",
                    "product": {"version": "5.0"},
                },
                "finding_info": {
                    "uid": "prowler-azure-check_b-sub-2",
                    "title": "Check B",
                    "desc": "Desc B.",
                    "created_time_dt": "2026-05-13T09:10:55.058583",
                },
                "status_code": "PASS",
                "severity": "Low",
                "resources": [],
                "cloud": {"account": {"uid": "sub-abc"}, "provider": "azure", "region": "global"},
                "remediation": {"desc": "Fix.", "references": []},
                "risk_details": "Risk.",
                "time_dt": "2026-05-13T09:10:55.058583",
                "unmapped": {
                    "compliance": {"CIS-2.0": ["1.1"]},  # Same control as FAIL above
                    "categories": [],
                },
            },
        ]
        request = ScanRequest(
            provider=Provider.AZURE,
            benchmark=Benchmark.CIS_2_0_AZURE,
            cloud_account_id="sub-abc",
        )
        result = normalize(raw, request)
        # Find CIS-2.0 / 1.1
        cis_checks = [
            c for c in result.compliance_checks
            if c.control_id == "1.1" and "2.0" in c.framework_version
        ]
        assert len(cis_checks) == 1
        # FAIL must win over PASS
        assert cis_checks[0].status == FindingStatus.FAIL
        assert cis_checks[0].fail_count == 1
        assert cis_checks[0].pass_count == 1
