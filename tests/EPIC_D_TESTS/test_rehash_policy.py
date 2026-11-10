"""D730: size-aware per-access re-hash policy - full vs stat fast-path + fail-closed."""

from __future__ import annotations

import json
import os
from pathlib import Path

from siftmesh_core.evidence.hash_utils import sha256_file
from siftmesh_core.ledgers.custody_ledger import verify_after_access
from siftmesh_core.mcp_gateway.audit_exec import run_tool
from siftmesh_core.run_dir import RunPaths, new_run_dir
from siftmesh_core.schemas.tool_result import ToolResult


def _case(
    tmp_path: Path, payload: bytes = b"unit-test-fixture-bytes"
) -> tuple[RunPaths, Path, str]:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "a.bin").write_bytes(payload)
    run = new_run_dir(base=tmp_path / "case_runs")
    return run, evidence, sha256_file(evidence / "a.bin")


def _rehash_events(run: RunPaths) -> list[dict]:
    lines = (run.root / "evidence" / "custody_log.jsonl").read_text().splitlines()
    return [json.loads(line) for line in lines if "source_rehash_verified" in line]


def _run(run: RunPaths, evidence: Path, sha: str, **kw) -> ToolResult:
    return run_tool(
        run.root,
        result_cls=ToolResult,
        tool_name="probe",
        source_artifact="a.bin",
        source_sha256=sha,
        backend="real",
        produce=lambda: {},
        evidence_root=evidence,
        **kw,
    )


def test_small_file_full_rehash_ok(tmp_path: Path) -> None:
    run, evidence, sha = _case(tmp_path)
    result = _run(run, evidence, sha)
    assert result.status == "success"
    events = _rehash_events(run)
    assert len(events) == 1
    assert events[0]["action"] == "rehash_full"
    assert events[0]["result"] == "ok"
    assert events[0]["source_sha256"] == sha


def test_large_file_stat_fastpath_ok(tmp_path: Path) -> None:
    run, evidence, sha = _case(tmp_path, payload=b"x" * 4096)
    result = _run(run, evidence, sha, rehash_threshold_bytes=16)
    assert result.status == "success"
    events = _rehash_events(run)
    assert len(events) == 1
    assert events[0]["action"] == "rehash_stat"
    assert events[0]["result"] == "ok"


def test_stat_drift_still_full_rehashes_ok(tmp_path: Path) -> None:
    run, evidence, sha = _case(tmp_path, payload=b"x" * 4096)

    def produce() -> dict:
        st = (evidence / "a.bin").stat()
        os.utime(evidence / "a.bin", (st.st_atime, st.st_mtime + 100))  # mtime-only drift
        return {}

    result = run_tool(
        run.root,
        result_cls=ToolResult,
        tool_name="probe",
        source_artifact="a.bin",
        source_sha256=sha,
        backend="real",
        produce=produce,
        evidence_root=evidence,
        rehash_threshold_bytes=16,
    )
    assert result.status == "success"
    events = _rehash_events(run)
    assert events[0]["action"] == "rehash_full"  # stat differed: paid for the full read
    assert events[0]["result"] == "ok"


def test_tamper_mid_parse_fails_closed(tmp_path: Path) -> None:
    run, evidence, sha = _case(tmp_path)

    def produce() -> dict:
        (evidence / "a.bin").write_bytes(b"tampered-mid-parse")
        return {}

    result = run_tool(
        run.root,
        result_cls=ToolResult,
        tool_name="probe",
        source_artifact="a.bin",
        source_sha256=sha,
        backend="real",
        produce=produce,
        evidence_root=evidence,
    )
    assert result.status == "error"
    assert result.error_code == "integrity_mismatch"
    assert result.structured_result_path is None  # nothing persisted from tainted parse
    events = _rehash_events(run)
    assert events[0]["result"] == "mismatch"


def test_verify_after_access_stat_path_direct(tmp_path: Path) -> None:
    run = new_run_dir(base=tmp_path / "case_runs")
    src = tmp_path / "orig.bin"
    src.write_bytes(b"evidence")
    st = src.stat()
    assert verify_after_access(
        run.root,
        run_id=run.run_id,
        artifact="orig.bin",
        baseline_sha256=sha256_file(src),
        source_path=src,
        pre_size=st.st_size,
        pre_mtime_ns=st.st_mtime_ns,
        full_hash_above_bytes=1,  # force the large-file branch on a tiny fixture
    )
    record = json.loads((run.root / "evidence" / "custody_log.jsonl").read_text())
    assert record["action"] == "rehash_stat"
