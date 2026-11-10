"""Chain-of-custody ledger (B9).

Appends validated :class:`CustodyEvent` records to ``evidence/custody_log.jsonl``
through the path policy. Construction validates the model, so a malformed event
can never reach disk (validate-before-write).

At ingest, one ``evidence_ingested`` event is recorded per artifact. The optional
``verify_unchanged`` re-hashes a single original once and records a
``source_rehash_verified`` event (detects *external* change only; the ingest hash
is the custody baseline). Per-tool-access re-hashing is Epic-D scope - it is only
meaningful once parsers actually touch artifacts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from siftmesh_core import __version__
from siftmesh_core.evidence.hash_utils import REHASH_FULL_BYTES, sha256_file, stat_sig
from siftmesh_core.evidence.path_policy import safe_write_path
from siftmesh_core.schemas.custody import CustodyEvent


def _custody_path(run_root: Path | str, evidence_root: Path | str | None = None) -> Path:
    return safe_write_path(
        run_root, Path("evidence") / "custody_log.jsonl", evidence_root=evidence_root
    )


def append_event(
    run_root: Path | str,
    event: CustodyEvent,
    *,
    evidence_root: Path | str | None = None,
) -> Path:
    """Append one validated :class:`CustodyEvent` as a JSONL line."""
    target = _custody_path(run_root, evidence_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8", newline="\n") as out:
        out.write(event.model_dump_json() + "\n")
    return target


def record_ingest(
    run_root: Path | str,
    *,
    run_id: str,
    artifact: str,
    source_sha256: str,
    start_time_utc: datetime,
    end_time_utc: datetime,
    evidence_root: Path | str | None = None,
) -> Path:
    """Record an ``evidence_ingested`` custody event for one hashed artifact."""
    event = CustodyEvent(
        event_type="evidence_ingested",
        run_id=run_id,
        artifact=artifact,
        source_sha256=source_sha256,
        action="hash",
        actor="siftmesh",
        tool_name="hash_utils",
        tool_version=__version__,
        start_time_utc=start_time_utc,
        end_time_utc=end_time_utc,
        result="ok",
    )
    return append_event(run_root, event, evidence_root=evidence_root)


def verify_unchanged(
    run_root: Path | str,
    *,
    run_id: str,
    artifact: str,
    baseline_sha256: str,
    source_path: Path | str,
    evidence_root: Path | str | None = None,
) -> bool:
    """Re-hash one original; record ``source_rehash_verified``; return matched."""
    start = datetime.now(UTC)
    actual = sha256_file(source_path)
    end = datetime.now(UTC)
    matched = actual == baseline_sha256
    event = CustodyEvent(
        event_type="source_rehash_verified",
        run_id=run_id,
        artifact=artifact,
        source_sha256=baseline_sha256,
        action="rehash",
        actor="siftmesh",
        tool_name="hash_utils",
        tool_version=__version__,
        start_time_utc=start,
        end_time_utc=end,
        result="ok" if matched else "mismatch",
    )
    append_event(run_root, event, evidence_root=evidence_root)
    return matched


def verify_after_access(
    run_root: Path | str,
    *,
    run_id: str,
    artifact: str,
    baseline_sha256: str,
    source_path: Path | str,
    pre_size: int,
    pre_mtime_ns: int,
    full_hash_above_bytes: int = REHASH_FULL_BYTES,
    evidence_root: Path | str | None = None,
) -> bool:
    """Post-access integrity check; record ``source_rehash_verified``; return matched.

    Size-aware (D730): files at or below ``full_hash_above_bytes`` always pay for a
    full SHA-256 re-read; larger files take the ``(size, mtime_ns)`` stat fast-path
    and fall back to a full re-hash only when the post-access stat differs from the
    pre-access one (``pre_size`` / ``pre_mtime_ns``). The method is recorded in the
    event ``action`` (``rehash_full`` vs ``rehash_stat``).
    """
    start = datetime.now(UTC)
    size, mtime_ns = stat_sig(source_path)
    if size <= full_hash_above_bytes or (size, mtime_ns) != (pre_size, pre_mtime_ns):
        matched = sha256_file(source_path) == baseline_sha256
        method = "full"
    else:
        matched = True
        method = "stat"
    end = datetime.now(UTC)
    event = CustodyEvent(
        event_type="source_rehash_verified",
        run_id=run_id,
        artifact=artifact,
        source_sha256=baseline_sha256,
        action=f"rehash_{method}",
        actor="siftmesh",
        tool_name="hash_utils",
        tool_version=__version__,
        start_time_utc=start,
        end_time_utc=end,
        result="ok" if matched else "mismatch",
    )
    append_event(run_root, event, evidence_root=evidence_root)
    return matched
