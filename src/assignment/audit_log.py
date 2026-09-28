"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from uuid import uuid4


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, tuple[float, str]] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store an input event and return its correlation ID."""
        correlation_id = request_id or uuid4().hex
        started_at = utc_now_iso()
        self._open[correlation_id] = (perf_counter(), started_at)
        self.logs.append(
            {
                "event": "input",
                "request_id": correlation_id,
                "user_id": user_id,
                "input": text,
                "started_at": started_at,
            }
        )
        return correlation_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store an output event, its decision, and elapsed request time."""
        correlation_id = request_id or user_id
        opened = self._open.pop(correlation_id, None)
        latency_ms = (perf_counter() - opened[0]) * 1000 if opened else None
        self.logs.append(
            {
                "event": "output",
                "request_id": correlation_id,
                "user_id": user_id,
                "output": text,
                "blocked": blocked,
                "layer": layer,
                "latency_ms": round(latency_ms, 3) if latency_ms is not None else None,
                "timestamp": utc_now_iso(),
            }
        )

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
