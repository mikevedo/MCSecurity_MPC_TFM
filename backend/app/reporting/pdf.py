"""
pdf.py — PDF generation placeholder for the MCP Security Audit PoC.

This module is a STUB and must NOT be called from any live code path in the
initial PoC phase.

Design reference: sdd/poc-foundation/design Section 8 (Reporting)
Spec note: PDF generation is deferred to a future phase.
"""

from __future__ import annotations

from typing import Any, NoReturn


def render_pdf(*args: Any, **kwargs: Any) -> NoReturn:
    """
    Placeholder for PDF report generation.

    Raises:
        NotImplementedError: Always — PDF generation is not implemented yet.
    """
    raise NotImplementedError(
        "PDF rendering is not implemented in the initial PoC. "
        "Use generator.render() for Markdown output."
    )
