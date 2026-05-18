"""
azure_cli_auth.py — Azure CLI authentication helpers.

Design reference: sdd/poc-foundation/design — Section 4 (MCP Layer / auth)
Spec reference: MCP-4 — must provide auth interface stubbable without real Azure account.

Key contracts:
- check_azure_cli_login() → bool: runs `az account show`, returns True if exit code 0.
- get_subscription_id() → str | None: parses `az account show --query id -o tsv` output.
- ensure_logged_in(subscription_id) → None: raises RuntimeError if not logged in.

All functions handle subprocess failures gracefully — no unhandled exceptions.
"""

from __future__ import annotations

import subprocess
from typing import Optional


def check_azure_cli_login() -> bool:
    """
    Verify that the user is logged in via Azure CLI.

    Runs `az account show` and returns True if exit code is 0, False otherwise.
    Does NOT raise on subprocess errors — returns False instead.
    """
    try:
        result = subprocess.run(
            ["az", "account", "show"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_subscription_id() -> Optional[str]:
    """
    Return the active Azure subscription ID from the CLI.

    Runs `az account show --query id -o tsv` and returns the stripped output.
    Returns None on any error.
    """
    try:
        result = subprocess.run(
            ["az", "account", "show", "--query", "id", "-o", "tsv"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except Exception:
        return None


def ensure_logged_in(subscription_id: Optional[str] = None) -> None:
    """
    Assert that the user is logged in via Azure CLI.

    Raises RuntimeError if not logged in. Designed to be bypassed entirely
    in fixture mode — callers check `fixture_mode` before calling this.

    Args:
        subscription_id: Optional subscription to validate against; currently
            used only for the error message (no re-login is attempted).

    Raises:
        RuntimeError: if `check_azure_cli_login()` returns False.
    """
    if not check_azure_cli_login():
        msg = "Azure CLI is not authenticated. Run `az login`"
        if subscription_id:
            msg += f" and ensure subscription '{subscription_id}' is accessible."
        else:
            msg += "."
        raise RuntimeError(msg)
