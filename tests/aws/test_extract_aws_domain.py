"""
test_extract_aws_domain.py — TDD tests for _extract_aws_domain helper.

Tests are written FIRST (RED phase) before the implementation exists.
LLM is mocked with unittest.mock.MagicMock — no real LLM calls.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from langchain_core.messages import AIMessage

from backend.app.chat import _extract_aws_domain


class TestExtractAwsDomain:
    """TDD test suite for _extract_aws_domain."""

    def test_clear_s3_question_returns_s3(self):
        """Case 1: LLM returns a valid domain key → function returns it."""
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = AIMessage(content='{"domain": "s3"}')

        result = _extract_aws_domain(mock_llm, "¿tengo buckets S3 públicos?")

        assert result == "s3"

    def test_ambiguous_question_returns_none(self):
        """Case 2: LLM returns null domain → function returns None."""
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = AIMessage(content='{"domain": null}')

        result = _extract_aws_domain(mock_llm, "¿cómo está mi seguridad?")

        assert result is None

    def test_llm_exception_returns_none(self):
        """Case 3: LLM raises an exception → function returns None (never raises)."""
        mock_llm = MagicMock()
        mock_llm.invoke.side_effect = Exception("LLM error")

        result = _extract_aws_domain(mock_llm, "anything")

        assert result is None

    def test_invalid_domain_key_returns_none(self):
        """Guard: LLM returns a string not in _AWS_DOMAIN_KEYS → None."""
        mock_llm = MagicMock()
        mock_llm.invoke.return_value = AIMessage(content='{"domain": "lambda"}')

        result = _extract_aws_domain(mock_llm, "¿mis lambdas están bien?")

        assert result is None

    def test_all_valid_domain_keys_are_accepted(self):
        """All six domain keys must be accepted when returned by the LLM."""
        valid_keys = ["iam", "s3", "ebs", "cloudtrail", "vpc", "ec2"]
        for key in valid_keys:
            mock_llm = MagicMock()
            mock_llm.invoke.return_value = AIMessage(content=f'{{"domain": "{key}"}}')
            result = _extract_aws_domain(mock_llm, f"question about {key}")
            assert result == key, f"Expected '{key}', got '{result}'"
