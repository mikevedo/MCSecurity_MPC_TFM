"""
test_report_generator.py — Tests for the Jinja2 Markdown report generator.

TDD: RED phase first — these tests were written before generator.py implementation.

Spec reference: sdd/poc-foundation/spec — report-generation RPT-1, RPT-3, RPT-4
Design reference: sdd/poc-foundation/design Section 8 (Reporting)
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from backend.app.poc_contracts import (
    Benchmark,
    ComplianceCheck,
    FilterCriteria,
    FindingStatus,
    NormalizedFindings,
    Provider,
    ReportPolicy,
    ScanSummary,
    SecurityFinding,
    Severity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_finding(
    finding_id: str = "f-001",
    check_id: str = "iam_check_001",
    title: str = "MFA enabled for all users",
    status: FindingStatus = FindingStatus.FAIL,
    severity: Severity = Severity.HIGH,
    compliance: dict | None = None,
) -> SecurityFinding:
    return SecurityFinding(
        finding_id=finding_id,
        check_id=check_id,
        title=title,
        severity=severity,
        status=status,
        resource_id="/subscriptions/abc/providers/Microsoft.IAM/user/alice",
        resource_type="microsoft.iam/user",
        region="global",
        cloud_account_id="1e11569b-de29-4e51-ad5e-8f7facd3d07f",
        description="Checks that MFA is enabled for all users.",
        risk="Users without MFA are vulnerable to credential compromise.",
        remediation="Enable MFA via Azure AD settings.",
        references=["https://docs.microsoft.com/en-us/azure/active-directory/"],
        compliance=compliance or {"CIS-2.0": ["1.1"]},
        categories=["iam"],
        finding_uid="prowler-azure-iam_check_001-abc-alice",
        scan_time="2026-05-14T10:00:00+00:00",
    )


def _make_normalized(
    findings: list[SecurityFinding] | None = None,
) -> NormalizedFindings:
    if findings is None:
        fail = _make_finding(finding_id="f-001", status=FindingStatus.FAIL)
        pass_ = _make_finding(finding_id="f-002", status=FindingStatus.PASS)
        findings = [fail, pass_]

    passed = sum(1 for f in findings if f.status == FindingStatus.PASS)
    failed = sum(1 for f in findings if f.status == FindingStatus.FAIL)

    summary = ScanSummary(
        provider=Provider.AZURE,
        benchmark=Benchmark.CIS_2_0_AZURE,
        cloud_account_id="1e11569b-de29-4e51-ad5e-8f7facd3d07f",
        started_at="2026-05-14T10:00:00+00:00",
        finished_at="2026-05-14T10:05:00+00:00",
        total=len(findings),
        passed=passed,
        failed=failed,
    )

    compliance_checks = []
    if findings:
        compliance_checks = [
            ComplianceCheck(
                control_id="1.1",
                framework="CIS",
                framework_version="2.0",
                title="MFA for all users",
                status=FindingStatus.FAIL,
                related_findings=["f-001"],
                pass_count=passed,
                fail_count=failed,
            )
        ]

    return NormalizedFindings(
        security_findings=findings,
        compliance_checks=compliance_checks,
        summary=summary,
    )


def _make_policy() -> ReportPolicy:
    return ReportPolicy(
        title="CIS Azure Audit",
        audience="Security Team",
        benchmark=Benchmark.CIS_2_0_AZURE,
        filter=FilterCriteria(),
        include_remediation=True,
        include_compliance_overview=True,
    )


def _make_narrative() -> dict:
    return {
        "executive_summary": "Test executive summary text.",
        "key_risks": ["Risk A — iam_check_001 is failing."],
        "remediation_priorities": ["Enable MFA for all users immediately."],
    }


# ---------------------------------------------------------------------------
# Tests: render() happy path
# ---------------------------------------------------------------------------


class TestRenderHappyPath:
    """Tests for the main render() function with valid input."""

    def test_render_returns_non_empty_string(self):
        """render() must return a non-empty Markdown string."""
        from backend.app.reporting.generator import render

        result = render(
            findings=_make_normalized(),
            policy=_make_policy(),
            narrative=_make_narrative(),
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_render_contains_report_title(self):
        """Output must contain the CIS Security Audit Report heading."""
        from backend.app.reporting.generator import render

        result = render(
            findings=_make_normalized(),
            policy=_make_policy(),
            narrative=_make_narrative(),
        )
        assert "# CIS Security Audit Report" in result

    def test_render_contains_finding_title(self):
        """Output must reference at least one finding title."""
        from backend.app.reporting.generator import render

        findings = _make_normalized()
        result = render(
            findings=findings,
            policy=_make_policy(),
            narrative=_make_narrative(),
        )
        assert "MFA enabled for all users" in result

    def test_render_contains_summary_total(self):
        """Output must display the total findings count from summary."""
        from backend.app.reporting.generator import render

        findings = _make_normalized()
        result = render(
            findings=findings,
            policy=_make_policy(),
            narrative=_make_narrative(),
        )
        # summary.total == 2 (1 FAIL + 1 PASS)
        assert "2" in result

    def test_render_contains_executive_summary(self):
        """Output must include the narrative executive_summary text."""
        from backend.app.reporting.generator import render

        narrative = _make_narrative()
        result = render(
            findings=_make_normalized(),
            policy=_make_policy(),
            narrative=narrative,
        )
        assert "Test executive summary text." in result

    def test_render_contains_cloud_account_label(self):
        """Output must use 'Cloud Account' label, not 'Subscription'."""
        from backend.app.reporting.generator import render

        result = render(
            findings=_make_normalized(),
            policy=_make_policy(),
            narrative=_make_narrative(),
        )
        assert "Cloud Account" in result
        assert "**Subscription**" not in result

    def test_render_contains_provider(self):
        """Output must include the provider name."""
        from backend.app.reporting.generator import render

        result = render(
            findings=_make_normalized(),
            policy=_make_policy(),
            narrative=_make_narrative(),
        )
        assert "AZURE" in result

    def test_render_contains_benchmark(self):
        """Output must include the benchmark identifier."""
        from backend.app.reporting.generator import render

        result = render(
            findings=_make_normalized(),
            policy=_make_policy(),
            narrative=_make_narrative(),
        )
        assert "cis_azure_foundations_benchmark_v2.0" in result


# ---------------------------------------------------------------------------
# Tests: edge cases
# ---------------------------------------------------------------------------


class TestRenderEdgeCases:
    """Tests for edge/boundary conditions."""

    def test_render_zero_findings_does_not_raise(self):
        """render() with empty security_findings must not raise."""
        from backend.app.reporting.generator import render

        # Build NormalizedFindings with zero findings
        summary = ScanSummary(
            provider=Provider.AZURE,
            benchmark=Benchmark.CIS_2_0_AZURE,
            cloud_account_id="1e11569b-de29-4e51-ad5e-8f7facd3d07f",
            started_at="2026-05-14T10:00:00+00:00",
            finished_at="2026-05-14T10:05:00+00:00",
            total=0,
            passed=0,
            failed=0,
        )
        empty_findings = NormalizedFindings(
            security_findings=[],
            compliance_checks=[],
            summary=summary,
        )
        result = render(
            findings=empty_findings,
            policy=_make_policy(),
            narrative=_make_narrative(),
        )
        assert isinstance(result, str)
        assert "# CIS Security Audit Report" in result

    def test_render_finding_with_empty_compliance_does_not_raise(self):
        """Finding with empty compliance dict must render without error."""
        from backend.app.reporting.generator import render

        finding_no_compliance = _make_finding(compliance={})
        findings = _make_normalized(findings=[finding_no_compliance])

        result = render(
            findings=findings,
            policy=_make_policy(),
            narrative=_make_narrative(),
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_render_finding_with_multiple_compliance_frameworks(self):
        """Finding with multiple compliance mappings renders all frameworks."""
        from backend.app.reporting.generator import render

        finding = _make_finding(
            compliance={"CIS-2.0": ["1.1", "1.2"], "NIST-800-53": ["AC-2"]}
        )
        findings = _make_normalized(findings=[finding])

        result = render(
            findings=findings,
            policy=_make_policy(),
            narrative=_make_narrative(),
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_render_degraded_returns_non_empty_markdown(self):
        """render_degraded(error, policy) must return non-empty Markdown."""
        from backend.app.reporting.generator import render_degraded

        result = render_degraded(
            error="Scan failed: Prowler CLI not found",
            policy=_make_policy(),
        )
        assert isinstance(result, str)
        assert len(result) > 0
        assert "Scan failed" in result or "error" in result.lower() or "Error" in result

    def test_render_degraded_no_policy(self):
        """render_degraded must not raise when policy is None."""
        from backend.app.reporting.generator import render_degraded

        result = render_degraded(
            error="An unexpected error occurred",
            policy=None,
        )
        assert isinstance(result, str)
        assert len(result) > 0
