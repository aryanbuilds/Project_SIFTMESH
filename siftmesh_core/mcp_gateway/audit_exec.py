"""Audited tool execution (D2) - the provenance keystone.

Every typed tool runs through :func:`run_tool`: it allocates a deterministic
``TOOL-NNN`` id, stamps UTC start/end, runs the producer, writes the structured
result under the run dir (path-policed), registers the derived artifact + a
``tool_invoked`` custody event, and appends exactly one fully-populated
``ToolResult`` line to ``audit/tool_calls.jsonl`` - on success AND on failure
(criterion 5: every call is traceable). No tool bypasses this.

A recoverable failure is logged as ``status=error`` and returned (the orchestrator
decides retry). A missing backend (:class:`BackendUnavailableError`) is logged then
re-raised - it fails closed rather than yielding a fake result.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from siftmesh_core import __version__
from siftmesh_core.evidence.derived import DerivedArtifact, append_derived
from siftmesh_core.evidence.hash_utils import REHASH_FULL_BYTES, sha256_file, stat_sig
from siftmesh_core.evidence.path_policy import safe_write_path
from siftmesh_core.ledgers.custody_ledger import append_event, verify_after_access
from siftmesh_core.ledgers.tool_call_ledger import append_tool_result, read_tool_results
from siftmesh_core.mcp_gateway.backends import BackendUnavailableError
from siftmesh_core.mcp_gateway.exec_lock import run_dir_exec_lock
from siftmesh_core.mcp_gateway.tools._common import try_resolve_source
from siftmesh_core.schemas.custody import CustodyEvent
from siftmesh_core.schemas.tool_result import ToolResult, ToolStatus

ToolResultT = TypeVar("ToolResultT", bound=ToolResult)

# Sentinel keys a ``produce()`` may put in its returned payload to emit a raw
# byte/text artifact (e.g. a wrapped CLI's native JSON) alongside the structured
# rows. They travel out via the payload so the ``produce()`` signature stays
# uniform across every tool; ``run_tool`` pops them before building the result.
_RAW_OUTPUT_KEY = "_raw_output"  # value: bytes | str
_RAW_SUFFIX_KEY = "_raw_suffix"  # value: str, default "raw.json"


class RecoverableToolError(RuntimeError):
    """A recoverable tool failure (logged as status=error; orchestrator may retry)."""

    def __init__(self, message: str, *, code: str = "tool_error") -> None:
        super().__init__(message)
        self.code = code


def _next_tool_call_id(run_root: Path | str) -> str:
    """Allocate the next deterministic ``TOOL-NNN`` id from the ledger length."""
    return f"TOOL-{len(read_tool_results(run_root)) + 1:03d}"


def _write_exclusion_root(
    run_root: Path | str, evidence_root: Path | str | None
) -> Path | str | None:
    """The root to exclude from writes - the EXTERNAL original-evidence tree.

    A derived-artifact task (hth.2) resolves its source *under the run dir*, so its
    ``evidence_root`` is the run dir itself. There is then no external evidence to protect, and the
    tool must be able to write its own outputs under the run - so return None (``safe_write_path``
    still enforces run-dir containment). For a normal task (external evidence dir) it is unchanged.
    """
    if evidence_root is None:
        return None
    run_r = Path(run_root).resolve()
    ev_r = Path(evidence_root).resolve()
    return None if run_r == ev_r or run_r.is_relative_to(ev_r) else evidence_root


def _write_structured(
    run_root: Path | str,
    tool_call_id: str,
    payload: dict[str, Any],
    *,
    evidence_root: Path | str | None,
) -> str:
    """Write the structured result JSON under ``results/`` (path-policed)."""
    rel = Path("results") / f"{tool_call_id}.structured.json"
    target = safe_write_path(run_root, rel, evidence_root=evidence_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return rel.as_posix()


def _write_raw(
    run_root: Path | str,
    raw_rel: str,
    raw: bytes | str,
    *,
    evidence_root: Path | str | None,
) -> None:
    """Write a tool's raw output (a wrapped CLI's native bytes/text) under ``results/``."""
    target = safe_write_path(run_root, raw_rel, evidence_root=evidence_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(raw, bytes):
        target.write_bytes(raw)
    else:
        target.write_text(raw, encoding="utf-8")


def run_tool(
    run_root: Path | str,
    *,
    result_cls: type[ToolResultT],
    tool_name: str,
    source_artifact: str,
    source_sha256: str,
    backend: str,
    produce: Callable[[], dict[str, Any]],
    tool_version: str = __version__,
    evidence_root: Path | str | None = None,
    write_structured: bool = True,
    rehash_threshold_bytes: int = REHASH_FULL_BYTES,
) -> ToolResultT:
    """Run ``produce`` with full provenance; append one ``tool_calls.jsonl`` line.

    ``produce`` returns the structured payload (the ``result_cls`` extra fields).
    On success the payload is written + merged into the typed result; on a
    recoverable error an empty ``status=error`` result is logged and returned.

    Post-access integrity (D730): the source is pre-statted before ``produce``
    and re-verified after - full SHA-256 for files at or below
    ``rehash_threshold_bytes``, stat fast-path above it. A mismatch becomes
    ``status=error`` (``integrity_mismatch``), feeding the genuine-retry path.
    Serialized per run dir (``run_dir_exec_lock``) so concurrent live-agent ``mcp-serve``
    children sharing one run dir cannot race the ``TOOL-NNN`` / ``ALERT-NNN`` length-based
    allocators and mint a duplicate id (audit-trail integrity, criterion 5). The lock is
    per-run-dir, so parallel dispatch (separate staging dirs) is unaffected, and it changes
    no id values in a serial run (golden byte-identical).
    """
    with run_dir_exec_lock(run_root):
        return _run_tool_locked(
            run_root,
            result_cls=result_cls,
            tool_name=tool_name,
            source_artifact=source_artifact,
            source_sha256=source_sha256,
            backend=backend,
            produce=produce,
            tool_version=tool_version,
            evidence_root=evidence_root,
            write_structured=write_structured,
            rehash_threshold_bytes=rehash_threshold_bytes,
        )


def _run_tool_locked(
    run_root: Path | str,
    *,
    result_cls: type[ToolResultT],
    tool_name: str,
    source_artifact: str,
    source_sha256: str,
    backend: str,
    produce: Callable[[], dict[str, Any]],
    tool_version: str = __version__,
    evidence_root: Path | str | None = None,
    write_structured: bool = True,
    rehash_threshold_bytes: int = REHASH_FULL_BYTES,
) -> ToolResultT:
    """Provenanced tool body; always called under ``run_dir_exec_lock`` via :func:`run_tool`."""
    tool_call_id = _next_tool_call_id(run_root)
    # Post-access integrity baseline (D730): pre-stat the source BEFORE the
    # write-exclusion root is normalised, using the same trusted-roots logic as
    # the wrappers' ``resolved_source``. Unresolvable here means the wrapper
    # already failed - skip the after-check rather than double-fault.
    pre_source = try_resolve_source(evidence_root, source_artifact, run_root=run_root)
    pre_stat: tuple[int, int] | None = None
    if pre_source is not None:
        try:
            pre_stat = stat_sig(pre_source)
        except OSError:
            pre_source = None
    # Normalise the write-exclusion root: a derived task's evidence_root IS the run dir, which would
    # otherwise block the tool from writing its own outputs (hth.2). Source resolution already
    # happened in the tool wrapper; here evidence_root governs writes only.
    evidence_root = _write_exclusion_root(run_root, evidence_root)
    start = datetime.now(UTC)
    status: ToolStatus = "success"
    error_code: str | None = None
    payload: dict[str, Any] = {}
    reraise: Exception | None = None
    try:
        payload = produce()
    except BackendUnavailableError as exc:
        status, error_code, reraise = "error", "backend_unavailable", exc
    except RecoverableToolError as exc:
        status, error_code = "error", exc.code
    end = datetime.now(UTC)

    if status == "success" and pre_source is not None and pre_stat is not None:
        try:
            after_ok = verify_after_access(
                run_root,
                run_id=Path(run_root).resolve().name,
                artifact=source_artifact,
                baseline_sha256=source_sha256,
                source_path=pre_source,
                pre_size=pre_stat[0],
                pre_mtime_ns=pre_stat[1],
                full_hash_above_bytes=rehash_threshold_bytes,
                evidence_root=evidence_root,
            )
        except OSError:
            after_ok = False  # source vanished mid-parse: fail closed
        if not after_ok:
            status, error_code = "error", "integrity_mismatch"

    # A tool may emit a raw byte/text artifact (e.g. a wrapped CLI's native JSON)
    # via sentinel keys in its payload; pop them before the payload becomes result
    # fields so they never leak into the typed model.
    raw_output: bytes | str | None = None
    raw_suffix = "raw.json"
    if status == "success":
        raw_value = payload.pop(_RAW_OUTPUT_KEY, None)
        if raw_value is not None:
            raw_output = raw_value
            raw_suffix = str(payload.pop(_RAW_SUFFIX_KEY, raw_suffix))
        else:
            payload.pop(_RAW_SUFFIX_KEY, None)

    structured_path: str | None = (
        (Path("results") / f"{tool_call_id}.structured.json").as_posix()
        if status == "success" and write_structured
        else None
    )
    raw_path: str | None = (
        (Path("results") / f"{tool_call_id}.{raw_suffix}").as_posix()
        if raw_output is not None
        else None
    )

    # Provenance (base ToolResult) is what lands in audit/tool_calls.jsonl; the
    # structured payload lives in the structured_result_path file it points to.
    provenance: dict[str, Any] = {
        "tool_call_id": tool_call_id,
        "tool_name": tool_name,
        "source_artifact": source_artifact,
        "source_sha256": source_sha256,
        "start_time_utc": start,
        "end_time_utc": end,
        "status": status,
        "backend": backend,
        "tool_version": tool_version,
        "structured_result_path": structured_path,
        "raw_output_path": raw_path,
        "error_code": error_code,
    }
    result = result_cls(**provenance, **(payload if status == "success" else {}))

    if structured_path is not None:
        _write_structured(run_root, tool_call_id, payload, evidence_root=evidence_root)
    if raw_path is not None and raw_output is not None:
        _write_raw(run_root, raw_path, raw_output, evidence_root=evidence_root)

    append_tool_result(run_root, ToolResult(**provenance), evidence_root=evidence_root)

    append_event(
        run_root,
        CustodyEvent(
            event_type="tool_invoked",
            run_id=Path(run_root).resolve().name,
            artifact=source_artifact,
            source_sha256=source_sha256,
            action=tool_name,
            actor="siftmesh",
            tool_name=tool_name,
            tool_version=tool_version,
            start_time_utc=start,
            end_time_utc=end,
            result=status,
        ),
        evidence_root=evidence_root,
    )

    for derived_rel in (p for p in (structured_path, raw_path) if p is not None):
        written = safe_write_path(run_root, derived_rel, evidence_root=evidence_root)
        append_derived(
            run_root,
            DerivedArtifact(
                derived_path=derived_rel,
                source_artifact=source_artifact,
                source_sha256=source_sha256,
                tool_call_id=tool_call_id,
                derived_sha256=sha256_file(written),
            ),
            evidence_root=evidence_root,
        )

    # Indirect-injection guard (Project_SIFTAMESS-nkyo): a tool result is hostile-evidence-derived
    # and flows back into the agent context, so scan it (not only the agent's final message). The
    # single chokepoint covering BOTH the floor and the live agent. Logged-only - never gates.
    if status == "success" and payload:
        _scan_tool_result(
            run_root, tool_call_id, source_artifact, payload, evidence_root=evidence_root
        )

    if reraise is not None:
        raise reraise
    return result


def _scan_tool_result(
    run_root: Path | str,
    tool_call_id: str,
    source_artifact: str,
    payload: dict[str, Any],
    *,
    evidence_root: Path | str | None,
) -> None:
    """Scan a tool result for injection-like content; append InjectionAlert(s). Logged-only."""
    from siftmesh_core.adapters.spotlight import scan_injection
    from siftmesh_core.ledgers.injection_alerts import append_injection_alert, next_alert_id
    from siftmesh_core.schemas.injection_alert import InjectionAlert

    text = json.dumps(payload, default=str)
    for m in scan_injection(text):
        append_injection_alert(
            run_root,
            InjectionAlert(
                alert_id=next_alert_id(run_root),
                source="tool_result",
                signature=m.signature,
                snippet=m.snippet,
                detected_utc=datetime.now(UTC),
                task_id=tool_call_id,  # the tool call that surfaced it (no task ctx in this layer)
                source_artifact=source_artifact,
            ),
            evidence_root=evidence_root,
        )
