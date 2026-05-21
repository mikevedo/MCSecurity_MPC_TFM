"""
conftest.py — Shared pytest fixtures for tests/aws/.

The `aws_env` fixture is autouse=True, which means it applies to EVERY test
in this directory without needing an explicit import. It sets fake AWS
credentials so no test can accidentally make a real AWS call via boto3.

Any test that needs live-AWS behavior will fail at auth, not silently hit
production. Combined with moto's @mock_aws decorator, this guarantees
full test isolation from real AWS infrastructure.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Set fake AWS credentials for every test in tests/aws/.

    boto3 reads these env vars before falling through to ~/.aws/credentials
    or instance profile, so mocked creds take priority and prevent any
    real AWS call from succeeding.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
