"""
assume_role.py — STS AssumeRole helper.

NOT imported directly by user code — used internally by aws_cli_auth.py.
"""

from __future__ import annotations

import json
import subprocess


def assume_role(role_arn: str, session_name: str = "prowler-scan") -> dict[str, str]:
    """
    Assume an IAM role via STS and return temporary credentials as env-var dict.

    Returns a dict with keys: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN.
    Raises RuntimeError if the STS call fails for any reason.
    """
    try:
        result = subprocess.run(
            [
                "aws", "sts", "assume-role",
                "--role-arn", role_arn,
                "--role-session-name", session_name,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        raise RuntimeError("AWS CLI not found on PATH — cannot assume role")
    except subprocess.TimeoutExpired:
        raise RuntimeError("sts:AssumeRole timed out after 30 seconds")

    if result.returncode != 0:
        raise RuntimeError(f"sts:AssumeRole failed: {result.stderr.strip()}")

    data = json.loads(result.stdout)
    creds = data["Credentials"]
    return {
        "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
        "AWS_SESSION_TOKEN": creds["SessionToken"],
    }
