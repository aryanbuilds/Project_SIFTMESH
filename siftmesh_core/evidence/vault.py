"""Evidence vault integrator - the real ``init-case`` (B7).

Wires B1-B6, B8, B9 into one command: create the run dir, hash every original
(read-only, streaming, with a progress/ETA counter for large ingest), write the
manifest + ``sha256sum`` file + read-only posture + (empty) derived registry +
policy doc, record one ``evidence_ingested`` custody event per artifact, and
append orchestration events for each transition. Optional ``verify_after``
re-hashes originals once at the end (off by default; costly for huge data).
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from siftmesh_core.evidence.derived import init_registry
from siftmesh_core.evidence.hash_utils import FileFact, scan_totals, walk_files
from siftmesh_core.evidence.manifest import build_manifest, write_hashes_sha256, write_manifest
from siftmesh_core.evidence.path_policy import assert_run_outside_evidence
from siftmesh_core.evidence.policy import write_evidence_policy
from siftmesh_core.evidence.readonly import ensure_os_readonly, write_readonly_record
from siftmesh_core.ledgers.audit_log import log_event, open_orchestration_log
from siftmesh_core.ledgers.custody_ledger import record_ingest, verify_unchanged
from siftmesh_core.run_dir import RunPaths, new_run_dir


class EvidenceModifiedError(RuntimeError):
    """Raised when ``verify_after`` detects an original changed during the run."""


# Resumable-ingest checkpoint (D-eqo): lives beside ``case_runs/`` in the case
# dir so it survives an interrupted run, and dies once a run completes.
CHECKPOINT_NAME = ".siftmesh-ingest-checkpoint.jsonl"


def _make_progress_printer(total_files: int, total_bytes: int) -> Callable[[FileFact], None]:
    files_done = 0
    bytes_done = 0
    last = 0.0
    started = time.monotonic()

    def _printer(fact: FileFact) -> None:
        nonlocal files_done, bytes_done, last
        files_done += 1
        bytes_done += fact.size_bytes
        now = time.monotonic()
        if now - last < 0.3 and files_done != total_files:
            return
        last = now
        pct = (bytes_done / total_bytes * 100) if total_bytes else 100.0
        elapsed = now - started
        rate = bytes_done / elapsed if elapsed > 0 else 0.0
        eta = (total_bytes - bytes_done) / rate if rate > 0 else 0.0
        sys.stderr.write(
            f"\rhashing {files_done}/{total_files} files  {pct:5.1f}%  ETA {eta:5.0f}s"
        )
        sys.stderr.flush()

    return _printer


def init_case(
    case_dir: Path | str,
    evidence_dir: Path | str,
    *,
    run_name: str | None = None,
    verify_after: bool = False,
    show_progress: bool = False,
    brief_path: Path | str | None = None,
    objective_text: str | None = None,
    resume: bool = False,
) -> RunPaths:
    """Ingest evidence into a fresh run dir; return its :class:`RunPaths`.

    ``brief_path`` (optional) is the operator's TRUSTED incident briefing FILE; ``objective_text``
    (optional) is operator objective/steering text supplied INLINE (no file). Either - or BOTH - is
    rendered into ``context/incident_brief.md`` and recorded as manifest metadata only, never added
    to the hostile evidence ``files`` set. Passing both MERGES them (file background + inline
    steering) into one trusted objective. A brief that cannot be read fails closed
    (:class:`~siftmesh_core.intake.brief.BriefIntakeError`).
    """
    case_path = Path(case_dir)
    evidence_path = Path(evidence_dir)
    if not evidence_path.is_dir():
        raise FileNotFoundError(f"evidence path is not a directory: {evidence_path}")

    run_base = case_path / "case_runs"
    assert_run_outside_evidence(run_base, evidence_path)
    run = new_run_dir(base=run_base, run_name=run_name)
    assert_run_outside_evidence(run.root, evidence_path)

    checkpoint = case_path / CHECKPOINT_NAME
    if not resume:
        checkpoint.unlink(missing_ok=True)

    audit = open_orchestration_log(run.orchestration_events, run.run_id)
    log_event(audit, "init_case_start", case=case_path.name, evidence=str(evidence_path.resolve()))

    os_enforced, mount_note = ensure_os_readonly(evidence_path, run.root / "evidence_ro")
    active_evidence = run.root / "evidence_ro" if os_enforced else evidence_path
    enforcement = "os_bind_mount_ro" if os_enforced else "posture_only"
    log_event(audit, "evidence_mount", enforcement=enforcement, note=mount_note)

    on_progress: Callable[[FileFact], None] | None = None
    if show_progress:
        total_files, total_bytes = scan_totals(active_evidence)
        on_progress = _make_progress_printer(total_files, total_bytes)

    ingest_started = datetime.now(UTC)
    facts = walk_files(
        active_evidence, on_progress=on_progress, checkpoint_path=checkpoint if resume else None
    )
    ingest_ended = datetime.now(UTC)
    if show_progress:
        sys.stderr.write("\n")
        sys.stderr.flush()
    log_event(
        audit,
        "hashing_complete",
        file_count=len(facts),
        total_bytes=sum(f.size_bytes for f in facts),
    )

    manifest = build_manifest(
        case_id=case_path.name, run_id=run.run_id, facts=facts, created_utc=ingest_started
    )
    if brief_path is not None or objective_text is not None:
        from siftmesh_core.intake.brief import (
            ingest_brief,
            ingest_brief_and_objective,
            ingest_objective_text,
        )

        if brief_path is not None and objective_text is not None:
            brief_md, objective = ingest_brief_and_objective(
                brief_path, objective_text, run, evidence_root=active_evidence
            )
        elif brief_path is not None:
            brief_md, objective = ingest_brief(brief_path, run, evidence_root=active_evidence)
        else:
            assert objective_text is not None
            brief_md, objective = ingest_objective_text(
                objective_text, run, evidence_root=active_evidence
            )
        manifest = manifest.model_copy(
            update={
                "incident_objective": objective,
                "incident_brief_path": brief_md.resolve()
                .relative_to(run.root.resolve())
                .as_posix(),
            }
        )
        log_event(audit, "incident_brief_recorded", objective_chars=len(objective))
    write_manifest(manifest, run.root, evidence_root=active_evidence)
    write_hashes_sha256(manifest, run.root, evidence_root=active_evidence)
    log_event(audit, "manifest_written", files=len(manifest.files))

    write_readonly_record(
        active_evidence,
        run.root,
        file_count=len(facts),
        enforcement=enforcement,
        original_path=evidence_path,
    )
    init_registry(run.root, evidence_root=active_evidence)
    write_evidence_policy(
        run.root,
        case_id=case_path.name,
        run_id=run.run_id,
        evidence_root=str(active_evidence.resolve()),
        file_count=len(facts),
    )

    for fact in facts:
        record_ingest(
            run.root,
            run_id=run.run_id,
            artifact=fact.rel_path,
            source_sha256=fact.sha256,
            start_time_utc=ingest_started,
            end_time_utc=ingest_ended,
            evidence_root=active_evidence,
        )
    log_event(audit, "custody_recorded", events=len(facts))

    if verify_after:
        for fact in facts:
            if not verify_unchanged(
                run.root,
                run_id=run.run_id,
                artifact=fact.rel_path,
                baseline_sha256=fact.sha256,
                source_path=active_evidence / fact.rel_path,
                evidence_root=active_evidence,
            ):
                log_event(audit, "evidence_modified", artifact=fact.rel_path)
                raise EvidenceModifiedError(
                    f"original evidence changed during run: {fact.rel_path}"
                )
        log_event(audit, "rehash_verified", file_count=len(facts))

    checkpoint.unlink(missing_ok=True)
    log_event(audit, "init_case_done", run=run.run_id)
    return run
