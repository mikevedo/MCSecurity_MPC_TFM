"""
iam.py — MCP tool for AWS IAM security analysis via boto3.

Checks performed:
- Users without MFA
- Active access keys older than threshold
- Inactive console users
- Root account MFA and access keys

No subprocess. No Prowler. Direct boto3 calls.
Uses ambient credentials (env vars / instance profile / ~/.aws/credentials).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_STALE_KEY_DAYS = 90
_INACTIVE_USER_DAYS = 90


def analyze_iam_security(
    access_key_age_days: int = _STALE_KEY_DAYS,
    inactive_user_days: int = _INACTIVE_USER_DAYS,
    role_arn: Optional[str] = None,
) -> dict[str, Any]:
    """
    Analyze AWS IAM for security issues.

    Args:
        access_key_age_days: Flag active keys older than this (default 90).
        inactive_user_days:  Flag console users inactive longer than this (default 90).
        role_arn:            IAM role to assume before scanning (optional).

    Returns:
        dict with keys: success, summary, users_without_mfa,
        old_access_keys, inactive_users, root_account_issues.
    """
    try:
        iam = _get_iam_client(role_arn)
    except Exception as exc:
        return {"success": False, "error": f"Auth failed: {exc}"}

    now = datetime.now(tz=timezone.utc)
    key_cutoff = now - timedelta(days=access_key_age_days)
    inactive_cutoff = now - timedelta(days=inactive_user_days)

    old_access_keys: list[dict] = []
    inactive_users: list[dict] = []
    users_without_mfa: list[dict] = []
    root_account_issues: list[dict] = []

    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                created = user["CreateDate"]

                # --- Access keys ---
                try:
                    for key in iam.list_access_keys(UserName=uname)["AccessKeyMetadata"]:
                        if key["Status"] != "Active":
                            continue
                        if key["CreateDate"] >= key_cutoff:
                            continue
                        age = (now - key["CreateDate"]).days
                        try:
                            lu = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                            last_used = lu["AccessKeyLastUsed"].get("LastUsedDate", "Never")
                            last_used_str = (
                                last_used.isoformat()
                                if hasattr(last_used, "isoformat")
                                else str(last_used)
                            )
                        except Exception:
                            last_used_str = "unknown"
                        old_access_keys.append({
                            "user_name": uname,
                            "access_key_id": key["AccessKeyId"],
                            "age_days": age,
                            "created_date": key["CreateDate"].isoformat(),
                            "last_used_date": last_used_str,
                            "recommendation": f"Rotate — key is {age} days old",
                        })
                except Exception as exc:
                    logger.warning("access keys check failed for %s: %s", uname, exc)

                # --- MFA ---
                try:
                    if not iam.list_mfa_devices(UserName=uname)["MFADevices"]:
                        users_without_mfa.append({
                            "user_name": uname,
                            "created_date": created.isoformat(),
                            "recommendation": "Enable MFA",
                        })
                except Exception as exc:
                    logger.warning("MFA check failed for %s: %s", uname, exc)

                # --- Inactive console users ---
                if "PasswordLastUsed" in user:
                    last_pw = user["PasswordLastUsed"]
                    if last_pw < inactive_cutoff:
                        days = (now - last_pw).days
                        inactive_users.append({
                            "user_name": uname,
                            "days_inactive": days,
                            "last_activity": last_pw.isoformat(),
                            "recommendation": f"Review — inactive for {days} days",
                        })

    except ClientError as exc:
        return {"success": False, "error": str(exc)}

    # --- Root account ---
    try:
        sm = iam.get_account_summary()["SummaryMap"]
        if sm.get("AccountMFAEnabled", 0) == 0:
            root_account_issues.append({
                "issue": "Root account MFA not enabled",
                "severity": "critical",
                "recommendation": "Enable MFA on root account immediately",
            })
        if sm.get("AccountAccessKeysPresent", 0) > 0:
            root_account_issues.append({
                "issue": "Root account has access keys",
                "severity": "critical",
                "recommendation": "Delete root account access keys",
            })
    except Exception as exc:
        logger.warning("root account check failed: %s", exc)

    return {
        "success": True,
        "summary": {
            "users_without_mfa": len(users_without_mfa),
            "old_access_keys": len(old_access_keys),
            "inactive_users": len(inactive_users),
            "root_issues": len(root_account_issues),
            "total_issues": (
                len(users_without_mfa)
                + len(old_access_keys)
                + len(inactive_users)
                + len(root_account_issues)
            ),
        },
        "users_without_mfa": users_without_mfa,
        "old_access_keys": old_access_keys,
        "inactive_users": inactive_users,
        "root_account_issues": root_account_issues,
    }


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _get_iam_client(role_arn: Optional[str]):
    if not role_arn:
        return boto3.client("iam")
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn, RoleSessionName="iam-security-scan"
    )["Credentials"]
    return boto3.client(
        "iam",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
