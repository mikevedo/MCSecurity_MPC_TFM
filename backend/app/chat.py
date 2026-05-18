"""
chat.py — Terminal REPL entrypoint for the MCP Security Audit PoC.

Usage:
    uv run python -m backend.app.chat

Fixture mode (no real Azure account needed):
    FIXTURE_MODE=1 uv run python -m backend.app.chat

The graph is built once and reused across REPL iterations.  Each user input
triggers a full ainvoke() cycle.  Errors are displayed as human-readable
messages without Python tracebacks (spec CHAT-4).

Rules:
- MUST run the graph end-to-end in fixture mode when FIXTURE_MODE=1 (CHAT-3)
- Fixture mode activatable WITHOUT source-code changes — env var only (CHAT-5)
- MUST NOT call Prowler CLI or import subprocess directly

Design reference: sdd/poc-foundation/design Section 9 (Terminal Chat)
Spec reference:   sdd/poc-foundation/spec  — terminal-chat CHAT-3, CHAT-5
"""

from __future__ import annotations

import asyncio
import os
import sys

from backend.app.poc_graph import build_graph

_BANNER = """
╔══════════════════════════════════════════════════════════╗
║        Cloud Security Audit — CIS Azure PoC             ║
║  Powered by Prowler + MCP + LangGraph + qwen2.5-coder   ║
╚══════════════════════════════════════════════════════════╝

Type your scan request, e.g.:
  Run a CIS Level 1 audit on subscription abc-123-xyz
  Scan subscription 1e11569b-de29-4e51-ad5e-8f7facd3d07f

Type 'exit' or 'quit' to stop.
"""

_FIXTURE_NOTICE = (
    "\n[FIXTURE MODE ACTIVE] Using local fixture file — no real Azure calls.\n"
)


def main() -> None:
    """
    Start the interactive terminal REPL.

    Builds the LangGraph graph once, then loops reading user input and
    invoking the graph.  On error, prints a friendly message. On success,
    prints the report path.
    """
    fixture_mode = bool(int(os.environ.get("FIXTURE_MODE", "0")))

    print(_BANNER.strip())
    if fixture_mode:
        print(_FIXTURE_NOTICE.strip())

    try:
        graph = build_graph()
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to initialise graph: {exc}", file=sys.stderr)
        sys.exit(1)

    while True:
        try:
            user_input = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit", "q"):
            print("Goodbye.")
            break

        print("Processing your request…")
        try:
            result = asyncio.run(graph.ainvoke({"user_input": user_input}))
        except Exception as exc:  # noqa: BLE001
            print(f"Error: {exc}")
            continue

        if result.get("error"):
            print(f"Scan failed: {result['error']}")
        elif result.get("report_path"):
            print(f"Report generated: {result['report_path']}")
        else:
            print("Scan completed but no report path was returned.")


if __name__ == "__main__":
    main()
