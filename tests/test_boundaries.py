"""
test_boundaries.py — AST-level boundary guard tests.

Enforces architectural invariants via source-code inspection (no import needed):
1. subprocess import ONLY in MCP_SERVER/tools/azure/prowler.py
2. mcp.client import ONLY in backend/app/services/mcp_client.py
3. Agents (cis_agent.py, doc_agent.py) import nothing from MCP_SERVER,
   subprocess, or mcp.client
4. normalizers/ and reporting/ have no FS writes (no open(..., 'w') or Path.write*)

Design reference: sdd/poc-foundation/design — Section 1 (Architectural Approach)
                  ADR-007: boundary enforcement via AST scan
Spec reference:   sdd/poc-foundation/spec — CIS-1, DOC-1, MCP-2
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# Project root
PROJECT_ROOT = Path(__file__).parent.parent


def _get_module_source(rel_path: str) -> str:
    """Read source code of a project module by relative path."""
    full_path = PROJECT_ROOT / rel_path
    return full_path.read_text(encoding="utf-8")


def _ast_imports(source: str) -> list[str]:
    """
    Extract all imported module names from source using AST.

    Returns a flat list of dotted module names that appear in import
    or from...import statements.
    """
    tree = ast.parse(source)
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)
    return imports


def _contains_write_calls(source: str) -> bool:
    """
    Check if source contains file-write patterns:
    - open(...) in write mode  → 'w' or 'wb' as mode arg
    - Path(...).write_text / write_bytes
    Returns True if any write pattern is detected.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        # Check for .write_text or .write_bytes attribute calls
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in ("write_text", "write_bytes"):
                return True
            # open(..., 'w') or open(..., 'wb')
            if isinstance(func, ast.Name) and func.id == "open":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if "w" in arg.value:
                            return True
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        if isinstance(kw.value.value, str) and "w" in kw.value.value:
                            return True
    return False


# ---------------------------------------------------------------------------
# T-7-1 Guard 1: subprocess import only in prowler.py
# ---------------------------------------------------------------------------


class TestSubprocessBoundary:
    """subprocess MUST only appear in MCP_SERVER/tools/{azure,aws}/prowler.py and auth modules."""

    ALLOWED_SUBPROCESS_FILES = [
        "MCP_SERVER/tools/azure/prowler.py",
        "MCP_SERVER/tools/aws/prowler.py",
        "MCP_SERVER/auth/azure_cli_auth.py",
        "MCP_SERVER/auth/aws_cli_auth.py",
    ]
    # Legacy single-file reference kept for backward compat with existing tests
    ALLOWED_SUBPROCESS_FILE = "MCP_SERVER/tools/azure/prowler.py"

    MUST_NOT_HAVE_SUBPROCESS = [
        "backend/app/agents/cis_agent.py",
        "backend/app/agents/doc_agent.py",
        "backend/app/agents/_llm.py",
        "backend/app/normalizers/prowler_normalizer.py",
        "backend/app/reporting/generator.py",
        "backend/app/services/scan_service.py",
        "backend/app/poc_graph.py",
        "backend/app/chat.py",
    ]

    def test_prowler_tool_has_subprocess(self):
        """prowler.py is allowed to import subprocess."""
        source = _get_module_source(self.ALLOWED_SUBPROCESS_FILE)
        imports = _ast_imports(source)
        assert any("subprocess" in m for m in imports), (
            f"{self.ALLOWED_SUBPROCESS_FILE} must import subprocess (it IS the tool layer)"
        )

    def test_agents_no_subprocess(self):
        """Agent modules must not import subprocess."""
        agent_files = [
            f for f in self.MUST_NOT_HAVE_SUBPROCESS
            if "agents" in f
        ]
        for rel_path in agent_files:
            source = _get_module_source(rel_path)
            imports = _ast_imports(source)
            violators = [m for m in imports if "subprocess" in m]
            assert not violators, (
                f"{rel_path} illegally imports subprocess: {violators}"
            )

    def test_normalizer_no_subprocess(self):
        """prowler_normalizer.py must not import subprocess."""
        source = _get_module_source("backend/app/normalizers/prowler_normalizer.py")
        imports = _ast_imports(source)
        assert not any("subprocess" in m for m in imports), (
            "prowler_normalizer.py illegally imports subprocess"
        )

    def test_generator_no_subprocess(self):
        """reporting/generator.py must not import subprocess."""
        source = _get_module_source("backend/app/reporting/generator.py")
        imports = _ast_imports(source)
        assert not any("subprocess" in m for m in imports), (
            "generator.py illegally imports subprocess"
        )

    def test_scan_service_no_subprocess(self):
        """scan_service.py must not import subprocess."""
        source = _get_module_source("backend/app/services/scan_service.py")
        imports = _ast_imports(source)
        assert not any("subprocess" in m for m in imports), (
            "scan_service.py illegally imports subprocess"
        )

    def test_poc_graph_no_subprocess(self):
        """poc_graph.py must not import subprocess."""
        source = _get_module_source("backend/app/poc_graph.py")
        imports = _ast_imports(source)
        assert not any("subprocess" in m for m in imports), (
            "poc_graph.py illegally imports subprocess"
        )

    def test_aws_prowler_tool_has_subprocess(self):
        """MCP_SERVER/tools/aws/prowler.py is allowed to import subprocess."""
        source = _get_module_source("MCP_SERVER/tools/aws/prowler.py")
        imports = _ast_imports(source)
        assert any("subprocess" in m for m in imports), (
            "MCP_SERVER/tools/aws/prowler.py must import subprocess (it IS the tool layer)"
        )


# ---------------------------------------------------------------------------
# T-7-1 (PR 2): backend does not import MCP AWS tools
# ---------------------------------------------------------------------------


class TestBackendDoesNotImportMCPAWSTools:
    """backend/ modules must never import from MCP_SERVER.tools.aws."""

    BACKEND_FILES = [
        "backend/app/agents/cis_agent.py",
        "backend/app/agents/doc_agent.py",
        "backend/app/normalizers/prowler_normalizer.py",
        "backend/app/reporting/generator.py",
        "backend/app/services/scan_service.py",
        "backend/app/services/mcp_client.py",
        "backend/app/poc_graph.py",
    ]

    def test_backend_does_not_import_mcp_aws_tools(self):
        """No backend module may import from MCP_SERVER.tools.aws."""
        for rel_path in self.BACKEND_FILES:
            source = _get_module_source(rel_path)
            imports = _ast_imports(source)
            violations = [
                m for m in imports
                if "MCP_SERVER.tools.aws" in m or m.startswith("MCP_SERVER.tools.aws")
            ]
            assert not violations, (
                f"{rel_path} illegally imports from MCP_SERVER.tools.aws: {violations}"
            )

    def test_prowler_subprocess_isolated_to_tool_modules(self):
        """
        subprocess+prowler combination must only appear in tools/{azure,aws}/prowler.py.
        No other module should combine subprocess calls with prowler as a target process.
        This test checks that no backend module imports subprocess.
        """
        for rel_path in self.BACKEND_FILES:
            source = _get_module_source(rel_path)
            imports = _ast_imports(source)
            assert not any("subprocess" in m for m in imports), (
                f"{rel_path} illegally imports subprocess — "
                "subprocess is confined to MCP_SERVER/tools/*/prowler.py and auth modules"
            )


# ---------------------------------------------------------------------------
# T-7-1 Guard 2: mcp.client import only in mcp_client.py
# ---------------------------------------------------------------------------


class TestMCPClientBoundary:
    """mcp.client MUST only appear in backend/app/services/mcp_client.py."""

    ALLOWED_MCP_CLIENT_FILE = "backend/app/services/mcp_client.py"

    MUST_NOT_HAVE_MCP_CLIENT = [
        "backend/app/agents/cis_agent.py",
        "backend/app/agents/doc_agent.py",
        "backend/app/services/scan_service.py",
        "backend/app/normalizers/prowler_normalizer.py",
        "backend/app/reporting/generator.py",
        "backend/app/poc_graph.py",
    ]

    def test_mcp_client_has_mcp_client_import(self):
        """mcp_client.py is allowed to import mcp.client.*"""
        source = _get_module_source(self.ALLOWED_MCP_CLIENT_FILE)
        imports = _ast_imports(source)
        assert any("mcp" in m for m in imports), (
            f"{self.ALLOWED_MCP_CLIENT_FILE} must import mcp (it IS the MCP client layer)"
        )

    def test_scan_service_no_mcp_client_import(self):
        """scan_service.py must not import mcp.client directly."""
        source = _get_module_source("backend/app/services/scan_service.py")
        imports = _ast_imports(source)
        mcp_client_imports = [m for m in imports if m.startswith("mcp.client")]
        assert not mcp_client_imports, (
            f"scan_service.py illegally imports mcp.client: {mcp_client_imports}"
        )

    def test_agents_no_mcp_client_import(self):
        """Agent modules must not import mcp.client."""
        agent_files = [
            "backend/app/agents/cis_agent.py",
            "backend/app/agents/doc_agent.py",
        ]
        for rel_path in agent_files:
            source = _get_module_source(rel_path)
            imports = _ast_imports(source)
            mcp_imports = [m for m in imports if m.startswith("mcp.client")]
            assert not mcp_imports, (
                f"{rel_path} illegally imports mcp.client: {mcp_imports}"
            )

    def test_normalizer_no_mcp_client_import(self):
        """prowler_normalizer.py must not import mcp.client."""
        source = _get_module_source("backend/app/normalizers/prowler_normalizer.py")
        imports = _ast_imports(source)
        mcp_imports = [m for m in imports if m.startswith("mcp.client")]
        assert not mcp_imports, (
            f"prowler_normalizer.py illegally imports mcp.client: {mcp_imports}"
        )


# ---------------------------------------------------------------------------
# T-7-1 Guard 3: agents import nothing from MCP_SERVER
# ---------------------------------------------------------------------------


class TestAgentMCPServerBoundary:
    """Agents must never import from MCP_SERVER."""

    AGENT_FILES = [
        "backend/app/agents/cis_agent.py",
        "backend/app/agents/doc_agent.py",
        "backend/app/agents/_llm.py",
    ]

    def test_agents_no_mcp_server_import(self):
        """No agent module may import from the MCP_SERVER package."""
        for rel_path in self.AGENT_FILES:
            source = _get_module_source(rel_path)
            imports = _ast_imports(source)
            mcp_server_imports = [
                m for m in imports if "MCP_SERVER" in m or m.startswith("MCP_SERVER")
            ]
            assert not mcp_server_imports, (
                f"{rel_path} illegally imports from MCP_SERVER: {mcp_server_imports}"
            )


# ---------------------------------------------------------------------------
# T-7-1 Guard 4: normalizers and reporting have no FS writes
# ---------------------------------------------------------------------------


class TestNoFileWritesInPureLayers:
    """normalizers/ and reporting/ must not write files — only report_storage.py may."""

    PURE_LAYER_FILES = [
        "backend/app/normalizers/prowler_normalizer.py",
        "backend/app/reporting/generator.py",
    ]

    def test_normalizer_no_file_writes(self):
        """prowler_normalizer.py must not write to disk."""
        source = _get_module_source("backend/app/normalizers/prowler_normalizer.py")
        assert not _contains_write_calls(source), (
            "prowler_normalizer.py contains file write calls — "
            "pure normalizer must have no FS side effects"
        )

    def test_generator_no_file_writes(self):
        """reporting/generator.py must not write to disk (RPT-4)."""
        source = _get_module_source("backend/app/reporting/generator.py")
        assert not _contains_write_calls(source), (
            "generator.py contains file write calls — "
            "RPT-4: writing is delegated to report_storage.py"
        )
