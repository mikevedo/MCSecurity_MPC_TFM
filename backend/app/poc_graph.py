"""
poc_graph.py — LangGraph graph definition for the MCP Security Audit PoC.

Wires all agent nodes and service calls into a typed LangGraph StateGraph.
The LLM is built once in build_graph() and injected into state so all nodes
share the same instance.

Graph flow (linear, with error routing):
  START
    → interpret_request   (cis_agent: LLM → ScanRequest)
    → build_policy        (cis_agent: LLM → ReportPolicy)
    → execute_scan        (scan_service: MCP → ScanResult)
    → normalize_findings  (prowler_normalizer: pure → NormalizedFindings)
    → filter_findings     (cis_agent: pure → NormalizedFindings filtered)
    → generate_narrative  (doc_agent: LLM → narrative dict)
    → render_report       (reporting.generator: Jinja2 → report_path)
    → END

  After each node: if state["error"] is set → route to error_handler → END

Rules:
- No subprocess, mcp, or Prowler imports here
- LLM built once, injected into state
- error_handler is a sink: sets error and returns degraded state

Design reference: sdd/poc-foundation/design Section 3 (LangGraph Graph)
Spec reference:   sdd/poc-foundation/spec  — terminal-chat CHAT-2, CHAT-4, ADR-006, ADR-008
"""

from __future__ import annotations

import os
from typing import Any, Optional

from langchain_ollama import ChatOllama
from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict

from backend.app.agents.cis_agent import apply_filter, build_policy, interpret_request
from backend.app.agents.doc_agent import generate_narrative
from backend.app.normalizers.prowler_normalizer import normalize
from backend.app.poc_contracts import (
    FilterCriteria,
    NormalizedFindings,
    ReportPolicy,
    ScanRequest,
    ScanResult,
)
from backend.app.services.mcp_client import MCPClient
from backend.app.services.scan_service import ScanService


# ---------------------------------------------------------------------------
# GraphState
# ---------------------------------------------------------------------------


class GraphState(TypedDict, total=False):
    """Typed state for the LangGraph graph.

    All fields are optional (total=False) because nodes add them incrementally.
    Pydantic models are stored as values inside the TypedDict (ADR-006).
    """

    user_input: str
    llm: Any  # ChatOllama instance, injected at graph entry
    scan_request: Optional[ScanRequest]
    report_policy: Optional[ReportPolicy]
    scan_result: Optional[ScanResult]
    normalized: Optional[NormalizedFindings]
    filtered: Optional[NormalizedFindings]
    filtered_findings: Optional[NormalizedFindings]  # alias used by doc_agent
    narrative: Optional[dict]
    report_path: Optional[str]
    error: Optional[str]


# ---------------------------------------------------------------------------
# Node functions (thin wrappers that delegate to the actual implementations)
# ---------------------------------------------------------------------------

# These module-level names are the patch targets used in tests.
# Actual business logic lives in cis_agent.py, doc_agent.py, etc.


async def _interpret_request(state: GraphState) -> GraphState:
    return await interpret_request(state)  # type: ignore[arg-type]


async def _build_policy(state: GraphState) -> GraphState:
    return await build_policy(state)  # type: ignore[arg-type]


async def execute_scan(state: GraphState) -> GraphState:
    """LangGraph node: invoke ScanService to run the Prowler scan via MCP."""
    scan_request: ScanRequest | None = state.get("scan_request")
    if scan_request is None:
        return {**state, "error": "execute_scan: scan_request is not set"}  # type: ignore[return-value]

    try:
        service = ScanService(MCPClient())
        scan_result = await service.run_scan(scan_request)
    except Exception as exc:  # noqa: BLE001
        return {**state, "error": f"execute_scan failed: {exc}"}  # type: ignore[return-value]

    if scan_result.error:
        return {**state, "scan_result": scan_result, "error": scan_result.error}  # type: ignore[return-value]

    return {**state, "scan_result": scan_result}  # type: ignore[return-value]


def normalize_findings(state: GraphState) -> GraphState:
    """LangGraph node: normalize raw ScanResult → NormalizedFindings."""
    scan_result: ScanResult | None = state.get("scan_result")
    scan_request: ScanRequest | None = state.get("scan_request")

    if scan_result is None or scan_request is None:
        return {**state, "error": "normalize_findings: scan_result or scan_request missing"}  # type: ignore[return-value]

    try:
        raw_findings = scan_result.raw_payload or []
        normalized = normalize(
            raw_findings,
            scan_request,
            started_at=scan_result.started_at,
            finished_at=scan_result.finished_at,
        )
        # Update scan_result with normalized data
        updated_result = scan_result.model_copy(update={})
        return {**state, "scan_result": updated_result, "normalized": normalized}  # type: ignore[return-value]
    except Exception as exc:  # noqa: BLE001
        return {**state, "error": f"normalize_findings failed: {exc}"}  # type: ignore[return-value]


async def filter_findings(state: GraphState) -> GraphState:
    """LangGraph node: filter NormalizedFindings by ReportPolicy criteria."""
    normalized: NormalizedFindings | None = state.get("normalized")
    policy: ReportPolicy | None = state.get("report_policy")

    if normalized is None:
        return {**state, "error": "filter_findings: normalized findings are not set"}  # type: ignore[return-value]

    criteria = policy.filter if policy else FilterCriteria()
    try:
        filtered = apply_filter(normalized, criteria)
        return {**state, "filtered": filtered, "filtered_findings": filtered}  # type: ignore[return-value]
    except Exception as exc:  # noqa: BLE001
        return {**state, "error": f"filter_findings failed: {exc}"}  # type: ignore[return-value]


async def _generate_narrative(state: GraphState) -> GraphState:
    return await generate_narrative(state)  # type: ignore[arg-type]


def render_report(state: GraphState) -> GraphState:
    """
    LangGraph node: render Markdown report from filtered findings + narrative.

    Uses the Jinja2 generator to produce a Markdown string, then persists it
    via ReportStorage.  Returns state with report_path set to the written file
    path, or sets state["error"] on failure.

    Spec reference: RPT-1, RPT-4 — generator does not write; storage does.
    """
    import uuid

    from backend.app.reporting.generator import render
    from backend.app.services.report_storage import ReportStorage

    filtered: NormalizedFindings | None = state.get("filtered_findings") or state.get("filtered")
    policy: ReportPolicy | None = state.get("report_policy")
    narrative: dict | None = state.get("narrative") or {}

    if filtered is None:
        return {**state, "error": "render_report: filtered_findings not set"}  # type: ignore[return-value]

    try:
        content = render(
            findings=filtered,
            policy=policy,
            narrative=narrative,
        )
        scan_id = str(uuid.uuid4())[:8]
        storage = ReportStorage()
        report_path = storage.save_report(scan_id, content)
        return {**state, "report_path": str(report_path)}  # type: ignore[return-value]
    except Exception as exc:  # noqa: BLE001
        return {**state, "error": f"render_report failed: {exc}"}  # type: ignore[return-value]


def error_handler(state: GraphState) -> GraphState:
    """
    LangGraph sink node: handle any pipeline error gracefully.

    Preserves all already-computed state fields.  Ensures the error field is
    set so the terminal chat can display a human-readable message without a
    Python traceback (CHAT-4).
    """
    error_msg = state.get("error") or "An unknown error occurred in the pipeline."
    # Keep all existing state, just ensure error is set
    return {**state, "error": error_msg}  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Routing function
# ---------------------------------------------------------------------------


def _route_on_error(state: GraphState) -> str:
    """Return 'error_handler' if state has an error, else the next node name."""
    if state.get("error"):
        return "error_handler"
    return "continue"


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------


def build_graph(llm: Any = None):
    """
    Build and compile the LangGraph security audit pipeline.

    Args:
        llm: Optional pre-built LLM instance. If None, builds ChatOllama.

    Returns:
        CompiledStateGraph ready for ainvoke().
    """
    if llm is None:
        llm = ChatOllama(model="qwen2.5-coder:14b", format="json", temperature=0)

    # ----------------------------------------------------------------
    # LLM injection wrapper: prepend llm into state before the first node
    # ----------------------------------------------------------------
    async def inject_llm(state: GraphState) -> GraphState:
        return {**state, "llm": llm}  # type: ignore[return-value]

    builder = StateGraph(GraphState)

    # Register nodes
    builder.add_node("inject_llm", inject_llm)
    builder.add_node("interpret_request", _interpret_request)
    builder.add_node("build_policy", _build_policy)
    builder.add_node("execute_scan", execute_scan)
    builder.add_node("normalize_findings", normalize_findings)
    builder.add_node("filter_findings", filter_findings)
    builder.add_node("generate_narrative", _generate_narrative)
    builder.add_node("render_report", render_report)
    builder.add_node("error_handler", error_handler)

    # Entry edge
    builder.add_edge(START, "inject_llm")
    builder.add_edge("inject_llm", "interpret_request")

    # After each node: check for error, route to error_handler or continue
    def _make_conditional(next_node: str):
        def _route(state: GraphState) -> str:
            if state.get("error"):
                return "error_handler"
            return next_node
        return _route

    builder.add_conditional_edges(
        "interpret_request",
        _make_conditional("build_policy"),
        {"error_handler": "error_handler", "build_policy": "build_policy"},
    )
    builder.add_conditional_edges(
        "build_policy",
        _make_conditional("execute_scan"),
        {"error_handler": "error_handler", "execute_scan": "execute_scan"},
    )
    builder.add_conditional_edges(
        "execute_scan",
        _make_conditional("normalize_findings"),
        {"error_handler": "error_handler", "normalize_findings": "normalize_findings"},
    )
    builder.add_conditional_edges(
        "normalize_findings",
        _make_conditional("filter_findings"),
        {"error_handler": "error_handler", "filter_findings": "filter_findings"},
    )
    builder.add_conditional_edges(
        "filter_findings",
        _make_conditional("generate_narrative"),
        {"error_handler": "error_handler", "generate_narrative": "generate_narrative"},
    )
    builder.add_conditional_edges(
        "generate_narrative",
        _make_conditional("render_report"),
        {"error_handler": "error_handler", "render_report": "render_report"},
    )

    builder.add_edge("render_report", END)
    builder.add_edge("error_handler", END)

    return builder.compile()
