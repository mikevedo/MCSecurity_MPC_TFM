"""
_llm.py — Shared LLM retry-repair helper for all agent nodes.

This module provides a single async function that wraps LangChain LLM calls
with automatic retry-with-repair logic and deterministic fallback on total failure.

Rules:
- MUST NOT import subprocess, mcp, MCP_SERVER, or Prowler modules
- MUST validate LLM output with Pydantic (retry on ValidationError or JSONDecodeError)
- MUST fall back deterministically after max_retries (raise on failure)

Design reference: sdd/poc-foundation/design Section 6 (Agents, shared helper)
Spec reference:   sdd/poc-foundation/spec  — CIS-2, DOC-3, ADR-004
"""

from __future__ import annotations

import json
from typing import Any, Type, TypeVar

from pydantic import BaseModel, ValidationError

M = TypeVar("M", bound=BaseModel)


async def call_llm_validated(
    llm: Any,
    prompt: str,
    model_cls: Type[M],
    max_retries: int = 3,
) -> M:
    """
    Call the LLM and validate its response against a Pydantic model.

    On JSONDecodeError or ValidationError, appends a repair hint to the prompt
    and retries up to max_retries times.  If all retries fail, raises the last
    exception so the caller can decide how to handle it (e.g. use a default).

    Args:
        llm:         A LangChain-compatible chat model with an `ainvoke` method.
        prompt:      The initial prompt string.
        model_cls:   The Pydantic model class to validate the LLM output against.
        max_retries: Maximum number of attempts (default 3).

    Returns:
        A validated instance of `model_cls`.

    Raises:
        json.JSONDecodeError | ValidationError: After all retries are exhausted.
    """
    current_prompt = prompt
    last_exc: Exception | None = None

    for attempt in range(max_retries):
        try:
            response = await llm.ainvoke(current_prompt)
            raw_content: str = response.content

            # Parse JSON
            data = json.loads(raw_content)

            # Validate with Pydantic
            validated: M = model_cls(**data)
            return validated

        except (json.JSONDecodeError, ValidationError, TypeError) as exc:
            last_exc = exc
            if attempt < max_retries - 1:
                # Build repair hint to help the LLM fix its output on next attempt
                schema_hint = json.dumps(model_cls.model_json_schema(), indent=2)
                error_hint = str(exc)
                current_prompt = (
                    f"{prompt}\n\n"
                    f"REPAIR REQUIRED: Your previous response was invalid.\n"
                    f"Error: {error_hint}\n"
                    f"Required JSON schema:\n{schema_hint}\n"
                    f"Respond ONLY with valid JSON matching this schema."
                )
            # Continue to next attempt

    # All retries exhausted — raise the last exception
    raise last_exc  # type: ignore[misc]
