"""
cloudtrail.py — MCP tool for AWS CloudTrail security analysis via boto3.

Checks performed:
- Trails not configured as multi-region (CIS 3.1)
- Trails with log file validation disabled (CIS 3.2)
- Trails not integrated with CloudWatch Logs (CIS 3.4)
- Missing CloudWatch metric filters for CIS 3.x security events

No subprocess. No Prowler. Direct boto3 calls.
Uses ambient credentials (env vars / instance profile / ~/.aws/credentials)
unless role_arn is provided, in which case STS assume_role is used.

Return schema:
{
    "success": True,
    "region": str,
    "summary": {
        "trails_checked": int,
        "trail_issues": int,
        "missing_metric_filters": int,
        "total_issues": int,
    },
    "trail_issues": [{"trail_name": str, "trail_arn": str, "issue": str, "severity": str}],
    "missing_metric_filters": [{"filter_name": str, "cis_control": str, "description": str}],
}
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


# CIS metric filter checks: (filter_name, cis_control, description, pattern_substring)
_REQUIRED_METRIC_FILTERS = [
    (
        "root_account_usage",
        "3.3",
        "Root account usage — CIS 3.3",
        'userIdentity.type = "Root"',
    ),
    (
        "unauthorized_api_calls",
        "3.1",
        "Unauthorized API calls — CIS 3.1",
        'errorCode = "AccessDenied"',
    ),
    (
        "no_mfa_console_signin",
        "3.2",
        "Console sign-in without MFA — CIS 3.2",
        'additionalEventData.MFAUsed != "Yes"',
    ),
    (
        "cloudtrail_changes",
        "3.5",
        "CloudTrail configuration changes — CIS 3.5",
        'eventName = "StopLogging"',
    ),
]


def _get_client(service_name: str, role_arn: Optional[str], region: Optional[str] = None):
    """
    Return a boto3 client for the given service.

    - If role_arn is provided: STS assume_role, then build client with temp creds.
    - If role_arn is None/empty: use ambient credentials.
    - region defaults to 'us-east-1' if not specified.
    """
    resolved_region = region or "us-east-1"
    kwargs: dict[str, Any] = {"region_name": resolved_region}

    if not role_arn:
        return boto3.client(service_name, **kwargs)

    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="cloudtrail-security-scan",
    )["Credentials"]
    return boto3.client(
        service_name,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        **kwargs,
    )


def analyze_cloudtrail_security(
    role_arn: Optional[str] = None,
    region: Optional[str] = "us-east-1",
) -> dict[str, Any]:
    """
    Analyze AWS CloudTrail security posture.

    Args:
        role_arn: IAM role to assume before scanning (optional).
        region:   AWS region to target (defaults to 'us-east-1').

    Returns:
        dict with keys: success, region, summary, trail_issues, missing_metric_filters.
    """
    effective_region = region or "us-east-1"

    try:
        ct = _get_client("cloudtrail", role_arn, effective_region)
        logs = _get_client("logs", role_arn, effective_region)
    except Exception as exc:
        return {"success": False, "error": f"Auth failed: {exc}"}

    trail_issues: list[dict] = []
    missing_metric_filters: list[dict] = []

    # -------------------------------------------------------------------------
    # Checks 1, 2, 3 — trail configuration issues
    # -------------------------------------------------------------------------
    try:
        response = ct.describe_trails(includeShadowTrails=False)
        trails = response.get("trailList", [])
    except ClientError as exc:
        return {"success": False, "error": str(exc)}

    trails_checked = len(trails)
    log_groups_to_check: list[str] = []

    for trail in trails:
        trail_name = trail.get("Name", "")
        trail_arn = trail.get("TrailARN", "")

        # Check 1 — Not multi-region (CIS 3.1)
        if not trail.get("IsMultiRegionTrail", False):
            trail_issues.append({
                "trail_name": trail_name,
                "trail_arn": trail_arn,
                "issue": "Trail is not multi-region (CIS 3.1)",
                "severity": "high",
            })

        # Check 2 — Log file validation disabled (CIS 3.2)
        if not trail.get("LogFileValidationEnabled", False):
            trail_issues.append({
                "trail_name": trail_name,
                "trail_arn": trail_arn,
                "issue": "Log file validation disabled (CIS 3.2)",
                "severity": "medium",
            })

        # Check 3 — No CloudWatch Logs integration (CIS 3.4)
        log_group_arn = trail.get("CloudWatchLogsLogGroupArn", "")
        if not log_group_arn:
            trail_issues.append({
                "trail_name": trail_name,
                "trail_arn": trail_arn,
                "issue": "Not integrated with CloudWatch Logs (CIS 3.4)",
                "severity": "medium",
            })
        else:
            # Collect log group name for metric filter check (strip ARN suffix if present)
            # ARN format: arn:aws:logs:region:account:log-group:name:*
            log_group_name = _extract_log_group_name(log_group_arn)
            if log_group_name and log_group_name not in log_groups_to_check:
                log_groups_to_check.append(log_group_name)

    # -------------------------------------------------------------------------
    # Check 4 — Missing CIS metric filters
    # -------------------------------------------------------------------------
    if log_groups_to_check:
        for log_group_name in log_groups_to_check:
            try:
                filters_response = logs.describe_metric_filters(
                    logGroupName=log_group_name
                )
                existing_filters = filters_response.get("metricFilters", [])
                existing_patterns = [
                    f.get("filterPattern", "") for f in existing_filters
                ]

                for filter_name, cis_control, description, pattern_substring in _REQUIRED_METRIC_FILTERS:
                    found = any(
                        pattern_substring in pattern
                        for pattern in existing_patterns
                    )
                    if not found:
                        missing_metric_filters.append({
                            "filter_name": filter_name,
                            "cis_control": cis_control,
                            "description": description,
                        })

                # Only check the first log group to avoid duplicates
                break
            except ClientError as exc:
                logger.warning(
                    "Metric filter check failed for log group %s: %s",
                    log_group_name,
                    exc,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Unexpected error checking metric filters for %s: %s",
                    log_group_name,
                    exc,
                )

    total_issues = len(trail_issues) + len(missing_metric_filters)

    return {
        "success": True,
        "region": effective_region,
        "summary": {
            "trails_checked": trails_checked,
            "trail_issues": len(trail_issues),
            "missing_metric_filters": len(missing_metric_filters),
            "total_issues": total_issues,
        },
        "trail_issues": trail_issues,
        "missing_metric_filters": missing_metric_filters,
    }


def _extract_log_group_name(log_group_arn: str) -> str:
    """
    Extract the log group name from a CloudWatch Logs ARN.

    ARN format: arn:aws:logs:region:account-id:log-group:log-group-name[:*]
    Returns the log group name or the full ARN if parsing fails.
    """
    if not log_group_arn:
        return ""
    # Split on ":log-group:" to extract the name portion
    if ":log-group:" in log_group_arn:
        parts = log_group_arn.split(":log-group:", 1)
        if len(parts) == 2:
            # Remove trailing ":*" if present
            name = parts[1].rstrip(":*").rstrip(":")
            return name if name else ""
    return log_group_arn
