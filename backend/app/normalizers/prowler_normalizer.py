"""
prowler_normalizer.py — Pure, side-effect-free normalizer for Prowler OCSF JSON output.

Transforms a raw Prowler findings list (json-ocsf format) into the internal
NormalizedFindings schema.  This module MUST NOT:
- Call external services
- Write files
- Import from agents, services, or MCP_SERVER modules

Design reference: sdd/poc-foundation/design Section 5 (Normalizer)
OCSF field mapping: engram #7 — verified against 197 real findings (Prowler 5.26.1)

# T-2-1: Verified OCSF field paths (from real azure-cis-report.ocsf.json)
# -------------------------------------------------------------------------
# check_id        → metadata.event_code
# title           → finding_info.title
# description     → finding_info.desc
# status          → status_code ("PASS" | "FAIL")
# severity        → severity   ("Low" | "Medium" | "High")
# resource_name   → resources[0].name          (guard: len > 0 else "")
# resource_type   → resources[0].type          (guard: len > 0 else "")
# resource_region → resources[0].region        (guard: len > 0 else "")
# resource_uid    → resources[0].uid           (guard: len > 0 else "")
# cloud_account_id → cloud.account.uid
# remediation     → remediation.desc
# remediation_refs→ remediation.references
# risk_details    → risk_details               (top-level string)
# compliance      → unmapped.compliance        (dict[str, list[str]])
# categories      → unmapped.categories        (list[str])
# finding_uid     → finding_info.uid
# scan_time       → time_dt                    (ISO datetime string)
# prowler_version → metadata.product.version
# cloud_provider  → cloud.provider
# cloud_region    → cloud.region               (subscription-level fallback)
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from backend.app.poc_contracts import (
    Benchmark,
    ComplianceCheck,
    FindingStatus,
    NormalizedFindings,
    Provider,
    ScanRequest,
    ScanSummary,
    SecurityFinding,
    Severity,
)

# ---------------------------------------------------------------------------
# Severity mapping: Prowler string → internal Severity enum
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
}

# Compliance status precedence: FAIL > MANUAL > PASS
_STATUS_PRECEDENCE: dict[FindingStatus, int] = {
    FindingStatus.FAIL: 2,
    FindingStatus.MANUAL: 1,
    FindingStatus.PASS: 0,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalize(
    raw_findings: list[dict[str, Any]],
    scan_request: ScanRequest,
    started_at: str | None = None,
    finished_at: str | None = None,
) -> NormalizedFindings:
    """
    Transform raw Prowler OCSF JSON findings into NormalizedFindings.

    Args:
        raw_findings:  Top-level list from Prowler json-ocsf output.
        scan_request:  The original ScanRequest (carries benchmark, provider, fixture_mode).
        started_at:    Optional ISO 8601 scan start time (defaults to first finding's time_dt).
        finished_at:   Optional ISO 8601 scan finish time (defaults to now).

    Returns:
        NormalizedFindings — fully validated, invariants guaranteed by model_validator.
    """
    now_iso = datetime.now(tz=timezone.utc).isoformat()

    if not raw_findings:
        # Empty input — return zero-count, valid NormalizedFindings
        summary = ScanSummary(
            provider=scan_request.provider,
            benchmark=scan_request.benchmark,
            cloud_account_id=scan_request.cloud_account_id,
            started_at=started_at or now_iso,
            finished_at=finished_at or now_iso,
            total=0,
            passed=0,
            failed=0,
            manual=0,
            severity_breakdown={},
            fixture_mode=scan_request.fixture_mode,
        )
        return NormalizedFindings(
            security_findings=[],
            compliance_checks=[],
            summary=summary,
        )

    # -------------------------------------------------------------------
    # Phase 1: Map each raw finding → SecurityFinding
    # -------------------------------------------------------------------
    security_findings: list[SecurityFinding] = []
    # severity_breakdown: severity_label → count of ALL findings
    severity_counter: dict[str, int] = defaultdict(int)

    # Collect compliance data: (framework, control_id) → {status_set, finding_ids, framework_ver}
    # Key: (framework_name, control_id), value accumulates data across findings
    compliance_accumulator: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    scan_time_first: str = now_iso
    # Always use scan_request.cloud_account_id as the authoritative value for the summary.
    # Individual findings carry their own cloud.account.uid which may differ per finding.
    cloud_account_id: str = scan_request.cloud_account_id

    for idx, raw in enumerate(raw_findings):
        # --- Extract resource fields with empty-string guards ---
        resources = raw.get("resources") or []
        if resources:
            resource = resources[0]
            resource_uid = resource.get("uid", "")
            resource_type = resource.get("type", "")
            resource_region = resource.get("region", "")
            resource_name = resource.get("name", "")
        else:
            resource_uid = ""
            resource_type = ""
            resource_region = ""
            resource_name = ""

        # --- Cloud context ---
        cloud = raw.get("cloud") or {}
        cloud_account = cloud.get("account") or {}
        finding_cloud_account_id = cloud_account.get("uid", "") or scan_request.cloud_account_id

        # --- Metadata ---
        metadata = raw.get("metadata") or {}
        product = metadata.get("product") or {}
        check_id = metadata.get("event_code", "")
        prowler_version = product.get("version", "")

        # --- Finding info ---
        finding_info = raw.get("finding_info") or {}
        finding_uid = finding_info.get("uid", f"unknown-{idx}")
        title = finding_info.get("title", "")
        description = finding_info.get("desc", "")

        # --- Status ---
        status_code = raw.get("status_code", "PASS").upper()
        if status_code == "FAIL":
            status = FindingStatus.FAIL
        elif status_code == "MANUAL":
            status = FindingStatus.MANUAL
        else:
            status = FindingStatus.PASS

        # --- Severity ---
        severity_raw = raw.get("severity", "informational").lower()
        severity = _SEVERITY_MAP.get(severity_raw, Severity.INFORMATIONAL)

        # --- Remediation ---
        remediation_block = raw.get("remediation") or {}
        remediation_desc = remediation_block.get("desc", "")
        remediation_refs = remediation_block.get("references") or []

        # --- Risk ---
        risk_details = raw.get("risk_details", "")

        # --- Unmapped (compliance + categories) ---
        unmapped = raw.get("unmapped") or {}
        compliance_map: dict[str, list[str]] = unmapped.get("compliance") or {}
        categories: list[str] = unmapped.get("categories") or []

        # --- Scan time ---
        scan_time = raw.get("time_dt", now_iso)
        if idx == 0:
            scan_time_first = scan_time

        # --- Build unique finding_id ---
        finding_id = str(uuid.uuid4())

        # --- Build SecurityFinding ---
        finding = SecurityFinding(
            finding_id=finding_id,
            check_id=check_id,
            title=title,
            severity=severity,
            status=status,
            resource_id=resource_uid,
            resource_type=resource_type,
            region=resource_region,
            cloud_account_id=finding_cloud_account_id or scan_request.cloud_account_id,
            description=description,
            risk=risk_details,
            remediation=remediation_desc,
            references=list(remediation_refs),
            compliance=compliance_map,
            categories=categories,
            finding_uid=finding_uid,
            scan_time=scan_time,
        )
        security_findings.append(finding)

        # --- Severity counter ---
        severity_counter[severity.value] += 1

        # --- Accumulate compliance data ---
        for framework_name, control_ids in compliance_map.items():
            for control_id in control_ids:
                key = (framework_name, control_id)
                if key not in compliance_accumulator:
                    compliance_accumulator[key] = {
                        "framework_version": _extract_framework_version(framework_name),
                        "status": status,
                        "finding_ids": [finding_id],
                        "pass_count": 0,
                        "fail_count": 0,
                        "manual_count": 0,
                    }
                else:
                    acc = compliance_accumulator[key]
                    # Apply status precedence: FAIL > MANUAL > PASS
                    if _STATUS_PRECEDENCE[status] > _STATUS_PRECEDENCE[acc["status"]]:
                        acc["status"] = status
                    acc["finding_ids"].append(finding_id)

                # Update counts
                acc = compliance_accumulator[key]
                if status == FindingStatus.FAIL:
                    acc["fail_count"] += 1
                elif status == FindingStatus.MANUAL:
                    acc["manual_count"] += 1
                else:
                    acc["pass_count"] += 1

    # -------------------------------------------------------------------
    # Phase 2: Build ComplianceCheck list
    # -------------------------------------------------------------------
    compliance_checks: list[ComplianceCheck] = []
    for (framework_name, control_id), acc in compliance_accumulator.items():
        check = ComplianceCheck(
            control_id=control_id,
            framework=framework_name,
            framework_version=acc["framework_version"],
            title=f"{framework_name} — {control_id}",
            status=acc["status"],
            related_findings=acc["finding_ids"],
            pass_count=acc["pass_count"],
            fail_count=acc["fail_count"],
            manual_count=acc["manual_count"],
        )
        compliance_checks.append(check)

    # -------------------------------------------------------------------
    # Phase 3: Build ScanSummary
    # -------------------------------------------------------------------
    passed_count = sum(1 for f in security_findings if f.status == FindingStatus.PASS)
    failed_count = sum(1 for f in security_findings if f.status == FindingStatus.FAIL)
    manual_count = sum(1 for f in security_findings if f.status == FindingStatus.MANUAL)

    summary = ScanSummary(
        provider=scan_request.provider,
        benchmark=scan_request.benchmark,
        cloud_account_id=cloud_account_id,
        started_at=started_at or scan_time_first,
        finished_at=finished_at or now_iso,
        total=len(security_findings),
        passed=passed_count,
        failed=failed_count,
        manual=manual_count,
        severity_breakdown=dict(severity_counter),
        fixture_mode=scan_request.fixture_mode,
    )

    return NormalizedFindings(
        security_findings=security_findings,
        compliance_checks=compliance_checks,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _extract_framework_version(framework_name: str) -> str:
    """
    Extract a version string from a framework name like 'CIS-2.0' → '2.0'.
    Falls back to the full name if no pattern is found.
    """
    # Common patterns: 'CIS-2.0', 'CIS-3.0', 'PCI-4.0', 'ISO27001-2022'
    parts = framework_name.rsplit("-", 1)
    if len(parts) == 2 and parts[1] and (parts[1][0].isdigit()):
        return parts[1]
    return framework_name
