"""
scan_service.py — Agent-facing facade for scan orchestration.

This is the ONLY entry point agents may use to request a scan.
It delegates to MCPClient for transport and to prowler_normalizer for
data transformation.  It MUST NOT import subprocess or call Prowler CLI directly.

Flow:
    ScanService.run_scan(request)
        → MCPClient.call_prowler(request)     [spawns MCP server via stdio]
        → prowler_normalizer.normalize(raw)   [pure transform]
        → ReportStorage.save_raw(...)         [persist raw artifact]
        → ScanResult(raw_path, raw_payload, …)

Rules enforced (from spec SVC-1, SVC-3, SVC-4):
- Agents MUST call this method — never mcp_client.py directly
- NO subprocess import in this file
- Error ScanResult from MCPClient MUST be propagated (not silenced)

Design reference: sdd/poc-foundation/design Section 7 (Services)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from backend.app.poc_contracts import ScanRequest, ScanResult
from backend.app.services.mcp_client import MCPClient
from backend.app.services.report_storage import ReportStorage


class ScanService:
    """
    Orchestrates a full scan cycle: MCP call → normalize → persist → return.

    Args:
        mcp_client: An MCPClient instance (injected for testability).
        storage:    A ReportStorage instance (injected for testability).
    """

    def __init__(
        self,
        mcp_client: MCPClient,
        storage: ReportStorage | None = None,
    ) -> None:
        self.mcp_client = mcp_client
        self.storage = storage or ReportStorage()

    async def run_scan(self, request: ScanRequest) -> ScanResult:
        """
        Execute a security scan and return raw results.

        1. Call MCPClient to invoke the MCP Server tool.
        2. If the tool returns an error, propagate it as an error ScanResult.
        3. Save raw findings to disk via ReportStorage.
        4. Return a ScanResult with raw_payload and raw_path populated.

        Normalization is handled separately by the LangGraph normalize node
        so that agents can call normalize on the raw_payload independently.

        Args:
            request: Validated ScanRequest from the CIS agent.

        Returns:
            ScanResult — with error set on failure, raw_payload on success.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(tz=timezone.utc).isoformat()

        # ----------------------------------------------------------------
        # Step 1: Call MCP tool
        # ----------------------------------------------------------------
        try:
            tool_result: dict = await self.mcp_client.call_tool(
                "run_prowler_scan",
                self._build_tool_arguments(request),
            )
        except Exception as exc:  # noqa: BLE001
            return ScanResult(
                raw_path=None,
                raw_payload=None,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc).isoformat(),
                returncode=-1,
                fixture_mode=request.fixture_mode,
                error=f"MCPClient transport error: {exc}",
            )

        # ----------------------------------------------------------------
        # Step 2: Check for tool-level error
        # ----------------------------------------------------------------
        if tool_result.get("error"):
            return ScanResult(
                raw_path=None,
                raw_payload=None,
                started_at=started_at,
                finished_at=datetime.now(tz=timezone.utc).isoformat(),
                returncode=tool_result.get("returncode", -1),
                fixture_mode=request.fixture_mode,
                error=tool_result["error"],
            )

        # ----------------------------------------------------------------
        # Step 3: Extract raw payload
        # ----------------------------------------------------------------
        raw_payload: list[dict] = tool_result.get("findings") or []
        returncode: int = tool_result.get("returncode", 0)
        fixture_mode: bool = tool_result.get("fixture_mode", request.fixture_mode)
        finished_at = datetime.now(tz=timezone.utc).isoformat()

        # ----------------------------------------------------------------
        # Step 4: Persist raw artifact
        # ----------------------------------------------------------------
        raw_path = self.storage.save_raw(scan_id, raw_payload)

        return ScanResult(
            raw_path=str(raw_path),
            raw_payload=raw_payload,
            started_at=started_at,
            finished_at=finished_at,
            returncode=returncode,
            fixture_mode=fixture_mode,
            error=None,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_tool_arguments(request: ScanRequest) -> dict:
        """Build the arguments dict for the run_prowler_scan MCP tool."""
        args: dict = {
            "provider": request.provider.value,
            "benchmark": request.benchmark.value,
            "cloud_account_id": request.cloud_account_id,
            "output_format": request.output_format,
        }
        if request.checks:
            args["checks"] = request.checks
        elif request.services:
            args["services"] = request.services
        if request.severity_filter:
            args["severity_filter"] = request.severity_filter
        if request.only_failed:
            args["only_failed"] = True
        if request.resource_group:
            args["resource_group"] = request.resource_group
        if request.azure_region:
            args["azure_region"] = request.azure_region
        if request.aws_region:
            args["aws_region"] = request.aws_region
        if request.role_arn:
            args["role_arn"] = request.role_arn
        if request.excluded_checks:
            args["excluded_checks"] = request.excluded_checks
        if request.categories:
            args["categories"] = request.categories
        if request.mutelist_file:
            args["mutelist_file"] = request.mutelist_file
        if request.fixture_mode and request.fixture_path:
            args["fixture_path"] = request.fixture_path
        return args
