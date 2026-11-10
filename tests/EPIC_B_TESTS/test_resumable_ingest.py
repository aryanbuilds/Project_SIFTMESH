"""D-eqo: resumable / interruptible large-evidence ingest via checkpoint."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from siftmesh_core.evidence.hash_utils import load_checkpoint, sha256_file, walk_files
from siftmesh_core.evidence.vault import CHECKPOINT_NAME, init_case


def _tree(tmp_path: Path) -> Path:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "a.bin").write_bytes(b"alpha")
    (evidence / "b.bin").write_bytes(b"beta" * 100)
    (evidence / "sub").mkdir()
    (evidence / "sub" / "c.bin").write_bytes(b"gamma")
    return evidence


def _checkpoint_line(path: Path, rel: str) -> str:
    st = path.stat()
    return (
        json.dumps(
            {
                "rel_path": rel,
                "sha256": sha256_file(path),
                "size_bytes": st.st_size,
                "mtime_ns": st.st_mtime_ns,
            }
        )
        + "\n"
    )


def test_resume_reuses_unchanged_files(tmp_path: Path) -> None:
    evidence = _tree(tmp_path)
    checkpoint = tmp_path / "ckpt.jsonl"
    checkpoint.write_text(_checkpoint_line(evidence / "a.bin", "a.bin"), encoding="utf-8")

    seen: list[str] = []
    facts = walk_files(
        evidence, on_progress=lambda f: seen.append(f.rel_path), checkpoint_path=checkpoint
    )
    assert [f.rel_path for f in facts] == ["a.bin", "b.bin", "sub/c.bin"]
    assert {f.rel_path: f.sha256 for f in facts} == {
        "a.bin": sha256_file(evidence / "a.bin"),
        "b.bin": sha256_file(evidence / "b.bin"),
        "sub/c.bin": sha256_file(evidence / "sub" / "c.bin"),
    }
    assert len(checkpoint.read_text().splitlines()) == 3  # resumed + completed
    assert seen == ["a.bin", "b.bin", "sub/c.bin"]  # progress still fires for reused


def test_changed_file_rehashed_not_reused(tmp_path: Path) -> None:
    evidence = _tree(tmp_path)
    checkpoint = tmp_path / "ckpt.jsonl"
    checkpoint.write_text(_checkpoint_line(evidence / "b.bin", "b.bin"), encoding="utf-8")
    (evidence / "b.bin").write_bytes(b"beta-CHANGED" * 100)  # stat differs now

    facts = walk_files(evidence, checkpoint_path=checkpoint)
    by_rel = {f.rel_path: f for f in facts}
    assert by_rel["b.bin"].sha256 == sha256_file(evidence / "b.bin")
    assert by_rel["a.bin"].sha256 == sha256_file(evidence / "a.bin")


def test_corrupt_checkpoint_fails_closed(tmp_path: Path) -> None:
    evidence = _tree(tmp_path)
    checkpoint = tmp_path / "ckpt.jsonl"
    checkpoint.write_text('{"rel_path": "a.bin", "bogus": 1}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt ingest checkpoint"):
        walk_files(evidence, checkpoint_path=checkpoint)
    assert load_checkpoint(tmp_path / "missing.jsonl") == {}


def test_init_case_resume_and_checkpoint_cleanup(tmp_path: Path) -> None:
    evidence = _tree(tmp_path)
    case = tmp_path / "case"
    case.mkdir()
    stale = case / CHECKPOINT_NAME
    stale.write_text(_checkpoint_line(evidence / "a.bin", "a.bin"), encoding="utf-8")

    run = init_case(case, evidence, resume=True, run_name="RUN-RESUME")
    manifest = json.loads((run.root / "evidence" / "evidence_manifest.json").read_text())
    assert {f["path"] for f in manifest["files"]} == {"a.bin", "b.bin", "sub/c.bin"}
    assert not stale.exists()  # completed ingest removes its checkpoint

    stale.write_text("junk\n", encoding="utf-8")
    init_case(case, evidence, resume=False, run_name="RUN-FRESH")
    assert not stale.exists()  # fresh run clears stale residue instead of trusting it
