"""B3 (+D-7h7): read-only posture record, optional OS bind-mount enforcement."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from siftmesh_core.evidence.readonly import ensure_os_readonly, write_readonly_record
from siftmesh_core.run_dir import new_run_dir


def test_readonly_record_written(tmp_path: Path) -> None:
    evi = tmp_path / "evidence_src"
    evi.mkdir()
    (evi / "a.txt").write_text("x")
    rp = new_run_dir(base=tmp_path / "runs")
    write_readonly_record(evi, rp.root, file_count=1)

    assert rp.readonly_mounts.exists()
    data = json.loads(rp.readonly_mounts.read_text(encoding="utf-8"))
    assert data["enforcement"] == "posture_only"  # not OS-level RO-mount
    assert data["sources"][0]["access"] == "read_only"
    assert data["sources"][0]["file_count"] == 1


def test_enforcement_and_original_path_recorded(tmp_path: Path) -> None:
    evi = tmp_path / "evidence_src"
    evi.mkdir()
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    rp = new_run_dir(base=tmp_path / "runs")
    write_readonly_record(
        mirror, rp.root, file_count=2, enforcement="os_bind_mount_ro", original_path=evi
    )
    data = json.loads(rp.readonly_mounts.read_text(encoding="utf-8"))
    assert data["enforcement"] == "os_bind_mount_ro"
    assert data["sources"][0]["path"] == str(mirror.resolve())
    assert data["sources"][0]["original_path"] == str(evi.resolve())


def test_ensure_non_linux_falls_back(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    enforced, note = ensure_os_readonly(tmp_path, tmp_path / "m")
    assert enforced is False
    assert "posture_only" in note
    assert not (tmp_path / "m").exists()  # no mountpoint touched


def test_ensure_missing_mount_binary_falls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("siftmesh_core.evidence.readonly.shutil.which", lambda _: None)
    enforced, note = ensure_os_readonly(tmp_path, tmp_path / "m")
    assert enforced is False
    assert "posture_only" in note


def _bind_ok(monkeypatch: pytest.MonkeyPatch, calls: list[list[str]]) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        "siftmesh_core.evidence.readonly.shutil.which", lambda name: f"/bin/{name}"
    )

    def fake_run(argv: list[str], **_kw: Any) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("siftmesh_core.evidence.readonly.subprocess.run", fake_run)


def test_ensure_bind_mount_verified_ro(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []
    _bind_ok(monkeypatch, calls)
    dst = tmp_path / "m"
    proc = tmp_path / "mounts"
    escaped = str(dst.resolve()).replace(" ", "\\040")  # kernel escapes spaces in /proc/mounts
    proc.write_text(f"/dev/sda {escaped} ext4 ro,relatime 0 0\n", encoding="utf-8")
    enforced, note = ensure_os_readonly(tmp_path, dst, proc_mounts=proc)
    assert enforced is True
    assert "verified ro" in note
    assert [c[:2] for c in calls] == [["/bin/mount", "--bind"], ["/bin/mount", "-o"]]


def test_ensure_unverified_mount_rolls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[list[str]] = []
    _bind_ok(monkeypatch, calls)
    dst = tmp_path / "m"
    proc = tmp_path / "mounts"
    escaped = str(dst.resolve()).replace(" ", "\\040")  # kernel escapes spaces in /proc/mounts
    proc.write_text(f"/dev/sda {escaped} ext4 rw,relatime 0 0\n", encoding="utf-8")
    enforced, _note = ensure_os_readonly(tmp_path, dst, proc_mounts=proc)
    assert enforced is False
    assert any(c[1] == str(dst) and "umount" in c[0] for c in calls)


def test_ensure_mount_failure_falls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        "siftmesh_core.evidence.readonly.shutil.which", lambda name: f"/bin/{name}"
    )

    def boom(*_a: Any, **_kw: Any) -> Any:
        raise subprocess.CalledProcessError(1, ["mount"], stderr="perm denied")

    monkeypatch.setattr("siftmesh_core.evidence.readonly.subprocess.run", boom)
    enforced, note = ensure_os_readonly(tmp_path, tmp_path / "m")
    assert enforced is False
    assert "posture_only" in note
