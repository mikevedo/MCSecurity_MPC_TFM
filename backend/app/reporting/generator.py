"""
generator.py — Jinja2-based Markdown report renderer.

Responsibilities:
- render(): Render NormalizedFindings + narrative + policy to a Markdown string.
- render_degraded(): Render a minimal error report when the pipeline fails.

Rules (spec):
- RPT-1: Render only from NormalizedFindings, ReportPolicy, and narrative dict.
- RPT-4: MUST NOT write files — writing is delegated to report_storage.py.

Design reference: sdd/poc-foundation/design Section 8 (Reporting)
Spec reference:   sdd/poc-foundation/spec  — report-generation RPT-1, RPT-3, RPT-4
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from datetime import datetime, timezone

from backend.app.poc_contracts import NormalizedFindings, ReportPolicy

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _make_env() -> Environment:
    """Build and return a configured Jinja2 Environment (not file-writing)."""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render(
    findings: NormalizedFindings,
    policy: ReportPolicy,
    narrative: dict,
    template_name: str = "cis_report.md.j2",
) -> str:
    """
    Render NormalizedFindings + narrative to a Markdown string.

    Args:
        findings:      Normalized and filtered scan findings.
        policy:        ReportPolicy controlling report scope.
        narrative:     Dict with keys: executive_summary, key_risks,
                       remediation_priorities.
        template_name: Jinja2 template filename (default: cis_report.md.j2).

    Returns:
        Rendered Markdown string.  Does NOT write to disk (RPT-4).
    """
    env = _make_env()
    template = env.get_template(template_name)
    return template.render(
        summary=findings.summary,
        policy=policy,
        narrative=narrative,
        findings=findings.security_findings,
        compliance=findings.compliance_checks,
    )


def render_multicloud(
    findings_list: list[NormalizedFindings],
    policies: list[ReportPolicy],
    template_name: str = "multi_cloud_report.md.j2",
) -> str:
    """
    Render a unified multi-cloud Markdown report from multiple NormalizedFindings.

    Each entry in findings_list corresponds to one cloud account scan.
    The report is organized by account with a global summary table.

    Args:
        findings_list: One NormalizedFindings per scanned account.
        policies:      Corresponding ReportPolicy per account (same order).
        template_name: Jinja2 template filename.

    Returns:
        Rendered Markdown string. Does NOT write to disk (RPT-4).
    """
    env = _make_env()
    template = env.get_template(template_name)
    accounts = [
        {"summary": nf.summary, "policy": p, "findings": nf.security_findings, "compliance": nf.compliance_checks}
        for nf, p in zip(findings_list, policies)
    ]
    return template.render(
        accounts=accounts,
        generated_at=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        total_accounts=len(accounts),
        grand_total=sum(nf.summary.total for nf in findings_list),
        grand_failed=sum(nf.summary.failed for nf in findings_list),
        grand_passed=sum(nf.summary.passed for nf in findings_list),
    )


def render_degraded(
    error: str,
    policy: Optional[ReportPolicy],
) -> str:
    """
    Render a minimal error report when the pipeline fails mid-execution.

    Args:
        error:  Error message describing the failure.
        policy: Optional ReportPolicy (may be None if pipeline failed early).

    Returns:
        Minimal Markdown string with error details.  Does NOT write to disk.
    """
    policy_info = ""
    if policy is not None:
        policy_info = (
            f"**Benchmark**: {policy.benchmark.value}\n"
            f"**Report Title**: {policy.title}\n"
        )

    return (
        "# CIS Security Audit Report — Pipeline Error\n\n"
        + policy_info
        + "\n---\n\n"
        "## Error Details\n\n"
        f"The report pipeline encountered an error and could not complete:\n\n"
        f"> {error}\n\n"
        "Please review the system logs for details. "
        "Partial findings may be available in the artifact directories.\n"
    )
