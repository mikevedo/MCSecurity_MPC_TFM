"""
poc_contracts.py — Shared Pydantic v2 contracts for the MCP Security Audit PoC.

All inter-layer data MUST pass through these validated models.  No module outside
this file may define canonical domain types; all layers import from here.

Design reference: sdd/poc-foundation/design — Section 2 (Pydantic Contracts)
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class Provider(str, Enum):
    AZURE = "azure"
    AWS = "aws"


class Benchmark(str, Enum):
    # Azure — CIS
    CIS_2_0_AZURE = "cis_2.0_azure"
    CIS_2_1_AZURE = "cis_2.1_azure"
    CIS_3_0_AZURE = "cis_3.0_azure"
    CIS_4_0_AZURE = "cis_4.0_azure"
    CIS_5_0_AZURE = "cis_5.0_azure"
    # Azure — other frameworks
    PCI_4_0_AZURE = "pci_4.0_azure"
    SOC2_AZURE = "soc2_azure"
    HIPAA_AZURE = "hipaa_azure"
    ISO27001_2022_AZURE = "iso27001_2022_azure"
    NIS2_AZURE = "nis2_azure"
    MITRE_ATTACK_AZURE = "mitre_attack_azure"
    # AWS — CIS
    CIS_1_5_AWS = "cis_1.5_aws"
    CIS_2_0_AWS = "cis_2.0_aws"
    CIS_3_0_AWS = "cis_3.0_aws"
    CIS_4_0_AWS = "cis_4.0_aws"
    CIS_5_0_AWS = "cis_5.0_aws"
    CIS_6_0_AWS = "cis_6.0_aws"
    # AWS — other frameworks
    SOC2_AWS = "soc2_aws"
    PCI_4_0_AWS = "pci_4.0_aws"
    HIPAA_AWS = "hipaa_aws"
    ISO27001_2022_AWS = "iso27001_2022_aws"
    NIS2_AWS = "nis2_aws"
    NIST_800_53_R5_AWS = "nist_800_53_revision_5_aws"


class FindingStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"


# ---------------------------------------------------------------------------
# Core finding types
# ---------------------------------------------------------------------------


class SecurityFinding(BaseModel):
    """A single cloud security finding produced by Prowler and normalized to OCSF."""

    finding_id: str = Field(..., description="Internal unique ID for this finding instance.")
    check_id: str = Field(..., description="Prowler check identifier (e.g. iam_check_001).")
    title: str = Field(..., description="Human-readable check title.")
    severity: Severity = Field(..., description="Finding severity level.")
    status: FindingStatus = Field(..., description="PASS, FAIL, or MANUAL.")

    # Resource context
    resource_id: str = Field(..., description="Full cloud resource UID.")
    resource_type: str = Field(..., description="Cloud resource type (e.g. microsoft.iam/...).")
    region: str = Field(..., description="Cloud region or 'global'.")
    cloud_account_id: str = Field(..., description="Cloud account/subscription UID.")

    # Detail fields
    description: str = Field(..., description="Markdown description of the check purpose.")
    risk: str = Field(..., description="Risk explanation if the check fails.")
    remediation: str = Field(..., description="Markdown remediation guidance.")
    references: list[str] = Field(default_factory=list, description="External reference URLs.")

    # Compliance and categorization
    compliance: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Compliance framework → control IDs mapping (e.g. {'CIS-2.0': ['1.1']}).",
    )
    categories: list[str] = Field(default_factory=list, description="Finding category tags.")

    # Identifiers
    finding_uid: str = Field(..., description="Prowler global finding UID.")
    scan_time: str = Field(..., description="ISO 8601 timestamp when the scan ran.")

    # Optional raw reference kept for traceability; not used by agents
    raw_ref: Optional[str] = Field(None, description="Optional reference to raw source path.")


class ComplianceCheck(BaseModel):
    """Aggregated compliance status for a single CIS control."""

    control_id: str = Field(..., description="CIS control identifier (e.g. '1.1').")
    framework: str = Field("CIS", description="Compliance framework name.")
    framework_version: str = Field(..., description="Framework version (e.g. '2.0').")
    title: str = Field(..., description="Control title.")
    status: FindingStatus = Field(
        ..., description="Aggregated status: FAIL > MANUAL > PASS precedence."
    )
    related_findings: list[str] = Field(
        default_factory=list, description="finding_id values contributing to this control."
    )
    pass_count: int = Field(0, ge=0)
    fail_count: int = Field(0, ge=0)
    manual_count: int = Field(0, ge=0)


class ScanSummary(BaseModel):
    """Aggregate statistics over all findings in a scan."""

    provider: Provider
    benchmark: Benchmark
    cloud_account_id: str
    started_at: str = Field(..., description="ISO 8601 scan start timestamp.")
    finished_at: str = Field(..., description="ISO 8601 scan finish timestamp.")

    total: int = Field(..., ge=0, description="Total number of findings.")
    passed: int = Field(..., ge=0)
    failed: int = Field(..., ge=0)
    manual: int = Field(0, ge=0)
    severity_breakdown: dict[str, int] = Field(
        default_factory=dict, description="Severity label → finding count."
    )
    fixture_mode: bool = Field(False, description="True when results came from fixture file.")


class NormalizedFindings(BaseModel):
    """
    Top-level normalized output from the Prowler normalizer.

    Invariant enforced by model_validator:
    - summary.total == len(security_findings)
    - summary.passed == count of PASS findings
    - summary.failed == count of FAIL findings
    """

    security_findings: list[SecurityFinding] = Field(
        ..., description="Flat list of individual security findings."
    )
    compliance_checks: list[ComplianceCheck] = Field(
        ..., description="Aggregated compliance checks keyed by control_id."
    )
    summary: ScanSummary = Field(..., description="Scan-wide aggregate statistics.")

    @model_validator(mode="after")
    def validate_summary_counts(self) -> "NormalizedFindings":
        actual_total = len(self.security_findings)
        actual_passed = sum(
            1 for f in self.security_findings if f.status == FindingStatus.PASS
        )
        actual_failed = sum(
            1 for f in self.security_findings if f.status == FindingStatus.FAIL
        )

        errors = []
        if self.summary.total != actual_total:
            errors.append(
                f"summary.total={self.summary.total} != len(security_findings)={actual_total}"
            )
        if self.summary.passed != actual_passed:
            errors.append(
                f"summary.passed={self.summary.passed} != actual_passed={actual_passed}"
            )
        if self.summary.failed != actual_failed:
            errors.append(
                f"summary.failed={self.summary.failed} != actual_failed={actual_failed}"
            )

        if errors:
            raise ValueError(
                "NormalizedFindings summary counts are inconsistent with findings: "
                + "; ".join(errors)
            )
        return self


# ---------------------------------------------------------------------------
# Scan orchestration types
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Parameters for a Prowler cloud security scan."""

    provider: Provider
    benchmark: Benchmark = Field(Benchmark.CIS_2_0_AZURE)
    cloud_account_id: str
    output_format: str = Field("json-ocsf", description="Prowler output format.")
    fixture_mode: bool = Field(False, description="Use fixture file instead of live scan.")
    fixture_path: Optional[str] = Field(
        None, description="Path to fixture file (required if fixture_mode=True)."
    )
    services: list[str] = Field(
        default_factory=list,
        description="Prowler --services filter (e.g. ['iam', 'cloudtrail']). Empty = all services.",
    )
    checks: list[str] = Field(
        default_factory=list,
        description="Prowler --checks filter (e.g. ['iam_root_mfa_enabled']). Overrides services when set.",
    )
    severity_filter: list[str] = Field(
        default_factory=list,
        description="Prowler --severity filter (e.g. ['critical', 'high']). Empty = all severities.",
    )
    only_failed: bool = Field(
        False,
        description="Pass --status FAIL to Prowler to exclude PASS findings at source.",
    )
    resource_group: Optional[str] = Field(
        None,
        description="Azure resource group filter (Azure only). Maps to --resource-group.",
    )
    azure_region: Optional[str] = Field(
        None,
        description="Azure region filter (Azure only, e.g. 'westeurope'). Maps to --azure-region.",
    )
    aws_region: Optional[str] = Field(
        None,
        description="AWS region filter (AWS only, e.g. 'us-east-1'). Maps to --region.",
    )
    role_arn: Optional[str] = Field(
        None,
        description="IAM role ARN to assume before scanning (AWS only). Empty = ambient credentials.",
    )
    excluded_checks: list[str] = Field(
        default_factory=list,
        description="Prowler --excluded-checks filter. Check IDs to skip.",
    )
    categories: list[str] = Field(
        default_factory=list,
        description="Prowler --category filter (e.g. ['software_and_configuration_checks']).",
    )
    mutelist_file: Optional[str] = Field(
        None,
        description="Path to Prowler mutelist YAML file. Maps to --mutelist-file.",
    )


class ScanResult(BaseModel):
    """Raw output from the MCP tool (before normalization)."""

    raw_path: Optional[str] = Field(None, description="Path to raw JSON file on disk.")
    raw_payload: Optional[list] = Field(None, description="Parsed raw findings list.")
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    returncode: Optional[int] = None
    fixture_mode: bool = False
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Agent types
# ---------------------------------------------------------------------------


class FilterCriteria(BaseModel):
    """Criteria for filtering normalized findings by the CIS agent."""

    min_severity: Optional[Severity] = Field(
        None, description="Minimum severity level to include (inclusive)."
    )
    only_failed: bool = Field(False, description="Include only FAIL status findings.")
    include_controls: list[str] = Field(
        default_factory=list, description="Explicit CIS control IDs to include."
    )
    exclude_controls: list[str] = Field(
        default_factory=list, description="CIS control IDs to exclude."
    )
    resource_types: list[str] = Field(
        default_factory=list, description="Filter to specific resource types."
    )
    services: list[str] = Field(
        default_factory=list,
        description="Filter findings to specific Prowler services (e.g. ['iam', 's3']). Matches check_id prefix.",
    )


class ReportPolicy(BaseModel):
    """Policy built by the CIS agent to govern what appears in the final report."""

    title: str = Field(..., description="Report title.")
    audience: str = Field(..., description="Intended report audience.")
    benchmark: Benchmark
    filter: FilterCriteria = Field(default_factory=FilterCriteria)
    include_remediation: bool = Field(True, description="Include remediation guidance.")
    include_compliance_overview: bool = Field(True, description="Include compliance matrix.")
    created_at: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat(),
        description="ISO 8601 creation timestamp.",
    )


# ---------------------------------------------------------------------------
# Spec-compatible aliases (W-1 housekeeping — sdd-verify PR 1 warnings)
# ---------------------------------------------------------------------------

#: Alias for NormalizedFindings — used in spec narrative as NormalizedReport
NormalizedReport = NormalizedFindings

#: Alias for ScanResult — used in spec narrative as ScanResponse
ScanResponse = ScanResult
