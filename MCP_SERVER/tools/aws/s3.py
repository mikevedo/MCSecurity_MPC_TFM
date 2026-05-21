"""
s3.py — MCP tool for AWS S3 security analysis via boto3.

Checks performed:
- Public buckets: ACL AllUsers/AuthenticatedUsers grants, policy status IsPublic, or public access block disabled
- Unencrypted buckets: no default SSE configuration
- Buckets without versioning: versioning not Enabled
- Buckets without access logging: no LoggingEnabled configuration

No subprocess. No Prowler. Direct boto3 calls.
Uses ambient credentials (env vars / instance profile / ~/.aws/credentials)
unless role_arn is provided, in which case STS assume_role is used.

Return schema:
{
    "success": True,
    "summary": {
        "total_buckets": int,
        "public_buckets": int,
        "unencrypted_buckets": int,
        "buckets_without_versioning": int,
        "buckets_without_logging": int,
        "total_issues": int,
    },
    "public_buckets": [{"bucket_name": str, "reason": str}],
    "unencrypted_buckets": [{"bucket_name": str}],
    "buckets_without_versioning": [{"bucket_name": str}],
    "buckets_without_logging": [{"bucket_name": str}],
}
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# S3 URIs that indicate public access via ACL grants
_PUBLIC_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def _get_s3_client(role_arn: Optional[str], region: Optional[str] = None):
    """
    Return a boto3 S3 client.

    S3 is a global service for bucket listing — region is intentionally ignored
    for the client constructor. Per-bucket operations that need a region (e.g.
    encryption checks on regional endpoints) are still done via this global client.

    - If role_arn is provided: STS assume_role, then build client with temp creds.
    - If role_arn is None/empty: use ambient credentials.
    """
    if not role_arn:
        return boto3.client("s3")

    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="s3-security-scan",
    )["Credentials"]
    return boto3.client(
        "s3",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _is_bucket_public(s3, bucket_name: str) -> tuple[bool, str]:
    """
    Check whether a bucket is publicly accessible.

    Returns (is_public, reason_string).
    Checks:
    1. Public access block configuration — any field set to False means not fully blocked.
    2. Bucket ACL — AllUsers or AuthenticatedUsers grant.
    3. Bucket policy status — IsPublic: True.
    """
    # Check 1: Public Access Block
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        config = pab.get("PublicAccessBlockConfiguration", {})
        if not all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ]):
            return True, "Public access block not fully enabled"
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            # No PAB config means nothing is blocking public access
            return True, "No public access block configuration"
        # Other errors — fall through to other checks

    # Check 2: Bucket ACL
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("URI") in _PUBLIC_URIS:
                return True, f"ACL grants public access to {grantee['URI']}"
    except ClientError as exc:
        logger.warning("ACL check failed for %s: %s", bucket_name, exc)

    # Check 3: Bucket policy status
    try:
        policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
        if policy_status.get("PolicyStatus", {}).get("IsPublic", False):
            return True, "Bucket policy allows public access"
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code not in ("NoSuchBucketPolicy", "NoSuchPublicAccessBlockConfiguration"):
            logger.warning("Policy status check failed for %s: %s", bucket_name, exc)

    return False, ""


def _is_bucket_unencrypted(s3, bucket_name: str) -> bool:
    """Return True if the bucket has no default SSE configuration."""
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return False  # Encryption is configured
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            return True
        logger.warning("Encryption check failed for %s: %s", bucket_name, exc)
        return False


def _is_versioning_disabled(s3, bucket_name: str) -> bool:
    """Return True if versioning is not Enabled for the bucket."""
    try:
        resp = s3.get_bucket_versioning(Bucket=bucket_name)
        return resp.get("Status") != "Enabled"
    except ClientError as exc:
        logger.warning("Versioning check failed for %s: %s", bucket_name, exc)
        return False


def _is_logging_disabled(s3, bucket_name: str) -> bool:
    """Return True if access logging is not configured for the bucket."""
    try:
        resp = s3.get_bucket_logging(Bucket=bucket_name)
        return "LoggingEnabled" not in resp
    except ClientError as exc:
        logger.warning("Logging check failed for %s: %s", bucket_name, exc)
        return False


def analyze_s3_security(
    role_arn: Optional[str] = None,
    region: Optional[str] = None,
) -> dict[str, Any]:
    """
    Analyze AWS S3 buckets for security issues.

    Args:
        role_arn: IAM role to assume before scanning (optional).
        region:   Ignored — S3 bucket listing is a global operation.

    Returns:
        dict with keys: success, summary, public_buckets, unencrypted_buckets,
        buckets_without_versioning, buckets_without_logging.
    """
    try:
        s3 = _get_s3_client(role_arn, region)
    except Exception as exc:
        return {"success": False, "error": f"Auth failed: {exc}"}

    public_buckets: list[dict] = []
    unencrypted_buckets: list[dict] = []
    buckets_without_versioning: list[dict] = []
    buckets_without_logging: list[dict] = []

    try:
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])
    except ClientError as exc:
        return {"success": False, "error": str(exc)}

    for bucket in buckets:
        name = bucket["Name"]

        # Public access check
        try:
            is_public, reason = _is_bucket_public(s3, name)
            if is_public:
                public_buckets.append({"bucket_name": name, "reason": reason})
        except Exception as exc:
            logger.warning("Public check failed for %s: %s", name, exc)

        # Encryption check
        try:
            if _is_bucket_unencrypted(s3, name):
                unencrypted_buckets.append({"bucket_name": name})
        except Exception as exc:
            logger.warning("Encryption check failed for %s: %s", name, exc)

        # Versioning check
        try:
            if _is_versioning_disabled(s3, name):
                buckets_without_versioning.append({"bucket_name": name})
        except Exception as exc:
            logger.warning("Versioning check failed for %s: %s", name, exc)

        # Logging check
        try:
            if _is_logging_disabled(s3, name):
                buckets_without_logging.append({"bucket_name": name})
        except Exception as exc:
            logger.warning("Logging check failed for %s: %s", name, exc)

    total_issues = (
        len(public_buckets)
        + len(unencrypted_buckets)
        + len(buckets_without_versioning)
        + len(buckets_without_logging)
    )

    return {
        "success": True,
        "summary": {
            "total_buckets": len(buckets),
            "public_buckets": len(public_buckets),
            "unencrypted_buckets": len(unencrypted_buckets),
            "buckets_without_versioning": len(buckets_without_versioning),
            "buckets_without_logging": len(buckets_without_logging),
            "total_issues": total_issues,
        },
        "public_buckets": public_buckets,
        "unencrypted_buckets": unencrypted_buckets,
        "buckets_without_versioning": buckets_without_versioning,
        "buckets_without_logging": buckets_without_logging,
    }
