"""Read-only posture recorder + optional OS-level enforcement (B3, D-7h7).

Records the original evidence location and the read-only posture SIFTMesh
guarantees by construction. On Linux, :func:`ensure_os_readonly` additionally
attempts a genuine read-only bind mount (``mount --bind`` + ``remount,bind,ro``,
verified via ``/proc/mounts``); anything less than a verified ``ro`` mount -
non-Linux host, missing ``mount``, no privileges - falls back to the honest
``posture_only`` record. OS enforcement is best-effort and never fails closed:
SIFTMesh must ingest even where it cannot mount.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from siftmesh_core.evidence.path_policy import safe_write_path

_POSTURE_NOTE = (
    "Records intended read-only posture: SIFTMesh opens originals read-only and "
    "never writes to a source. This is NOT OS-level RO-mount enforcement "
    "(mount -o ro / blockdev --setro), which is deferred to a later epic."
)

_MOUNT_TIMEOUT = 60


def _unescape_mount_path(field: str) -> str:
    """Decode the kernel's octal escapes (space/tab/newline/backslash) in /proc/mounts fields."""
    return (
        field.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _mountpoint_is_ro(mountpoint: Path, *, proc_mounts: Path = Path("/proc/mounts")) -> bool:
    """True when ``/proc/mounts`` shows ``mountpoint`` mounted with the ``ro`` option."""
    try:
        lines = proc_mounts.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    target = str(mountpoint.resolve())
    for line in lines:
        parts = line.split()
        if (
            len(parts) >= 4
            and _unescape_mount_path(parts[1]) == target
            and "ro" in parts[3].split(",")
        ):
            return True
    return False


def ensure_os_readonly(
    evidence_root: Path | str,
    mountpoint: Path | str,
    *,
    proc_mounts: Path = Path("/proc/mounts"),
) -> tuple[bool, str]:
    """Bind-mount ``evidence_root`` read-only at ``mountpoint``; return ``(enforced, note)``.

    Linux-only and best-effort: returns ``(False, reason)`` instead of raising
    when the host cannot do it. A ``True`` result means ``/proc/mounts`` was
    verified to show the mountpoint ``ro`` - anything else is ``posture_only``.
    """
    src = Path(evidence_root).resolve()
    dst = Path(mountpoint)
    if sys.platform != "linux":
        return False, f"non-Linux host ({sys.platform}): OS mount unavailable; posture_only"
    mount = shutil.which("mount")
    umount = shutil.which("umount")
    if mount is None:
        return False, "no 'mount' binary on PATH; posture_only"
    try:
        dst.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [mount, "--bind", str(src), str(dst)],
            capture_output=True,
            text=True,
            timeout=_MOUNT_TIMEOUT,
            check=True,
        )
        subprocess.run(
            [mount, "-o", "remount,bind,ro", str(dst)],
            capture_output=True,
            text=True,
            timeout=_MOUNT_TIMEOUT,
            check=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        return False, f"bind-mount failed ({exc}); posture_only"
    if not _mountpoint_is_ro(dst, proc_mounts=proc_mounts):
        if umount is not None:
            subprocess.run(
                [umount, str(dst)], capture_output=True, timeout=_MOUNT_TIMEOUT, check=False
            )
        return False, "mountpoint not verifiably ro in /proc/mounts; unmounted; posture_only"
    return True, f"evidence bind-mounted read-only at {dst} (verified ro via /proc/mounts)"



def write_readonly_record(
    evidence_root: Path | str,
    run_root: Path | str,
    *,
    file_count: int,
    enforcement: str = "posture_only",
    note: str | None = None,
    original_path: Path | str | None = None,
) -> Path:
    """Write ``evidence/readonly_mounts.json`` describing the read-only posture.

    ``enforcement`` is ``posture_only`` unless :func:`ensure_os_readonly` verified
    a real ``ro`` bind mount (``os_bind_mount_ro``). ``sources[0].path`` is always
    the evidence root the run actually reads; ``original_path`` records the
    pre-mount source when they differ.
    """
    evidence = Path(evidence_root).resolve()
    source: dict[str, object] = {
        "path": str(evidence),
        "access": "read_only",
        "file_count": file_count,
    }
    if original_path is not None and Path(original_path).resolve() != evidence:
        source["original_path"] = str(Path(original_path).resolve())
    record = {
        "enforcement": enforcement,
        "note": note if note is not None else _POSTURE_NOTE,
        "sources": [source],
    }
    target = safe_write_path(
        run_root, Path("evidence") / "readonly_mounts.json", evidence_root=evidence
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
