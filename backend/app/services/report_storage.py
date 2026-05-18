"""
report_storage.py — On-disk artifact persistence for the MCP Security Audit PoC.

Responsibilities:
- Write raw Prowler JSON, normalized findings, selected findings, and Markdown reports
  to their respective artifact directories.
- Ensure timestamped filenames prevent collisions between scans.
- This is the ONLY module permitted to write files for scan artifacts.

Rules enforced (from spec):
- Paths: artifacts/{kind}/{scan_id}.{ext}
- RPT-2: must NOT overwrite — scan_id (UUID) guarantees uniqueness.
- RPT-4: generator.py must NOT write files — only this module does.

Design reference: sdd/poc-foundation/design Section 7 (Services)
"""

from __future__ import annotations

import json
from pathlib import Path

from backend.app.poc_contracts import NormalizedFindings


class ReportStorage:
    """
    Writes scan artifacts to structured subdirectories under base_path.

    Directory layout:
        base_path/
            raw/          ← raw Prowler JSON lists
            normalized/   ← NormalizedFindings JSON
            selected/     ← filtered NormalizedFindings JSON
            reports/      ← rendered Markdown reports
    """

    def __init__(self, base_path: Path | str = Path("backend/app/artifacts")) -> None:
        self.base_path = Path(base_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save_raw(self, scan_id: str, data: list[dict]) -> Path:
        """
        Save the raw Prowler findings list to artifacts/raw/{scan_id}.json.

        Args:
            scan_id: Unique scan identifier (UUID4).
            data:    Raw findings list from Prowler OCSF JSON.

        Returns:
            Absolute Path to the written file.
        """
        return self._write_json(
            kind="raw",
            scan_id=scan_id,
            payload=data,
            suffix=".json",
        )

    def save_normalized(self, scan_id: str, data: NormalizedFindings) -> Path:
        """
        Save a NormalizedFindings object to artifacts/normalized/{scan_id}.json.

        Args:
            scan_id: Unique scan identifier.
            data:    Validated NormalizedFindings instance.

        Returns:
            Absolute Path to the written file.
        """
        path = self._resolve_path(kind="normalized", scan_id=scan_id, suffix=".json")
        self._ensure_dir(path.parent)
        path.write_text(data.model_dump_json(indent=2), encoding="utf-8")
        return path

    def save_selected(self, scan_id: str, data: NormalizedFindings) -> Path:
        """
        Save filtered NormalizedFindings to artifacts/selected/{scan_id}.json.

        Args:
            scan_id: Unique scan identifier.
            data:    Filtered NormalizedFindings instance.

        Returns:
            Absolute Path to the written file.
        """
        path = self._resolve_path(kind="selected", scan_id=scan_id, suffix=".json")
        self._ensure_dir(path.parent)
        path.write_text(data.model_dump_json(indent=2), encoding="utf-8")
        return path

    def save_report(self, scan_id: str, content: str) -> Path:
        """
        Save rendered Markdown content to artifacts/reports/{scan_id}.md.

        Args:
            scan_id: Unique scan identifier.
            content: Rendered Markdown string.

        Returns:
            Absolute Path to the written file.
        """
        path = self._resolve_path(kind="reports", scan_id=scan_id, suffix=".md")
        self._ensure_dir(path.parent)
        path.write_text(content, encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve_path(self, kind: str, scan_id: str, suffix: str) -> Path:
        """Compute artifact path without creating the file."""
        return self.base_path / kind / f"{scan_id}{suffix}"

    def _write_json(self, kind: str, scan_id: str, payload: object, suffix: str) -> Path:
        """Serialize payload to JSON and write to the resolved path."""
        path = self._resolve_path(kind=kind, scan_id=scan_id, suffix=suffix)
        self._ensure_dir(path.parent)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    @staticmethod
    def _ensure_dir(directory: Path) -> None:
        """Create directory tree if it does not exist."""
        directory.mkdir(parents=True, exist_ok=True)
