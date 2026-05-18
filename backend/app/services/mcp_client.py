"""
mcp_client.py — MCP stdio transport client for the MCP Security Audit PoC.

This is the ONLY module permitted to use mcp.client.stdio.
It spawns the FastMCP server as a subprocess via the MCP protocol and
calls the run_prowler_scan tool, returning its result as a dict.

Boundary rules (from spec and design ADR-001):
- ONLY this module may import from mcp.client
- Agents MUST NOT call this module directly (must go through scan_service.py)
- NO subprocess import here — subprocess lives in prowler.py (inside MCP server)

Design reference: sdd/poc-foundation/design Section 7 (Services)
Spec reference:   sdd/poc-foundation/spec  — scan-orchestration SVC-2
"""

from __future__ import annotations

import json
import os
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from backend.app.poc_contracts import ScanRequest


class MCPClient:
    """
    Async client that communicates with the FastMCP server via stdio transport.

    The server is spawned as a child process running:
        uv run python <server_script>

    Fixture mode env vars are forwarded to the spawned process so the MCP
    server uses the fixture file instead of invoking Prowler CLI live.
    """

    def __init__(
        self,
        server_script: str = "MCP_SERVER/server_multicloud.py",
    ) -> None:
        self.server_script = server_script

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Call a named tool on the MCP server and return its result as a dict.

        The MCP server is spawned fresh for each call (stateless PoC design).
        Fixture env vars are forwarded so the spawned server stays offline-capable.

        Args:
            tool_name:  Name of the MCP tool to invoke (e.g. "run_prowler_scan").
            arguments:  Keyword arguments forwarded to the tool.

        Returns:
            dict parsed from the tool's JSON text result.

        Raises:
            RuntimeError: If the tool returns no content or non-JSON content.
        """
        # Forward PROWLER_FIXTURE_MODE / PROWLER_FIXTURE_PATH so the server
        # stays in fixture mode without needing real Azure credentials.
        env = {**os.environ}

        server_params = StdioServerParameters(
            command="uv",
            args=["run", "python", "-m", "MCP_SERVER.server_multicloud"],
            env=env,
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments)

        # Extract and parse the first text content item
        if not result.content:
            raise RuntimeError(
                f"MCP tool '{tool_name}' returned no content."
            )

        raw_text: str = result.content[0].text
        try:
            return json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"MCP tool '{tool_name}' returned non-JSON content: {raw_text!r}"
            ) from exc

    async def call_prowler(self, request: ScanRequest) -> dict[str, Any]:
        """
        Convenience method: calls run_prowler_scan with a ScanRequest.

        Args:
            request: Validated ScanRequest from the agent layer.

        Returns:
            Dict from the MCP tool (raw_payload, returncode, error, fixture_mode, …).
        """
        arguments: dict[str, Any] = {
            "provider": request.provider.value,
            "benchmark": request.benchmark.value,
            "cloud_account_id": request.cloud_account_id,
            "output_format": request.output_format,
        }
        if request.fixture_mode:
            arguments["fixture_path"] = request.fixture_path

        return await self.call_tool("run_prowler_scan", arguments)
