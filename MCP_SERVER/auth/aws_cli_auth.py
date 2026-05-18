"""
aws_cli_auth.py — AWS CLI authentication helpers.

Design reference: sdd/aws-multicloud/design — PR 2 (MCP Layer / auth/aws_cli_auth.py)
Spec reference: MCP-AWS-3

Key contracts:
- check_aws_cli_login() → bool: runs `aws sts get-caller-identity`, returns True if exit code 0.
- get_account_id() → str | None: parses Account from `aws sts get-caller-identity` JSON output.
- get_credentials_for_scan(role_arn) → dict: returns temp credentials env-var dict when
  role_arn is provided; empty dict otherwise (Prowler uses ambient credentials).

Both functions handle subprocess failures gracefully — no unhandled exceptions.
Unlike Azure auth there is no ensure_logged_in() — AWS auth is non-interactive.
assume_role is NOT imported directly — use get_credentials_for_scan instead.
"""

from __future__ import annotations

import json
import subprocess
from typing import Optional


def check_aws_cli_login() -> bool:
    """
    Verify that AWS credentials are available via the AWS CLI.

    Runs `aws sts get-caller-identity` and returns True if exit code is 0,
    False otherwise. Does NOT raise on subprocess errors — returns False instead.
    """
    try:
        result = subprocess.run(
            ["aws", "sts", "get-caller-identity"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_credentials_for_scan(role_arn: str = "") -> dict[str, str]:
    """
    Return env-var overrides for the Prowler subprocess.

    If role_arn is provided, assumes the role via STS and returns temporary credentials
    as a dict with keys AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN.
    If role_arn is empty, returns an empty dict — Prowler inherits ambient credentials.

    Raises RuntimeError if assume role fails (caller decides how to handle it).
    """
    if not role_arn:
        return {}
    from .assume_role import assume_role
    return assume_role(role_arn)


def get_account_id() -> Optional[str]:
    """
    Return the AWS account ID from the current caller identity.

    Runs `aws sts get-caller-identity` and parses the JSON response.
    Returns the Account field value, or None on any failure.
    """
    try:
        result = subprocess.run(
            ["aws", "sts", "get-caller-identity"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data.get("Account")
        return None
    except Exception:
        return None
