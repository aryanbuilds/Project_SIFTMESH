"""SHA-256 hashing + deterministic, symlink-loop-safe directory walk (B1).

Streaming via :func:`hashlib.file_digest` (Python 3.11+) keeps memory constant
regardless of file size - a 100GB artifact hashes in one read pass without OOM.
The walk produces a stable, sorted ordering (reproducible manifests) and guards
against symlink loops with a visited ``(st_dev, st_ino)`` set. Symlinks are not
followed: SIFTMesh hashes only the real files inside the evidence tree, never an
out-of-tree target (the MVP forensic-safe choice).
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO


@dataclass(frozen=True)
class FileFact:
    """One file's integrity facts, relative to the walked root."""

    rel_path: str  # POSIX-style relative path
    sha256: str
    size_bytes: int
    mtime_utc: datetime


# Per-access re-hash policy (D730): files at or below this size get a full
# SHA-256 re-hash after every tool access; larger files use a stat fast-path
# (size + mtime_ns) and pay for a full re-hash only when the stat differs.
# 64MB keeps the $MFT-class artifacts (hundreds of MB) off the full re-read
# path while every small artifact keeps byte-exact verification.
REHASH_FULL_BYTES: int = 64 * 1024 * 1024


def stat_sig(path: Path | str) -> tuple[int, int]:
    """Return the ``(size_bytes, mtime_ns)`` integrity fast-path signature."""
    st = Path(path).stat()
    return (st.st_size, st.st_mtime_ns)


def sha256_file(path: Path | str) -> str:
    """Return the hex SHA-256 of ``path``, streamed (constant memory)."""
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _iter_regular_files(base: Path) -> Iterator[tuple[Path, os.stat_result]]:
    """Yield ``(path, stat)`` for every real (non-symlink) regular file.

    Deterministic order (sorted dirs + files), symlinks skipped, directory
    loops guarded, unreadable entries skipped.
    """
    visited: set[tuple[int, int]] = set()
    for root, dirs, files in os.walk(base, followlinks=False):
        root_path = Path(root)
        try:
            root_stat = root_path.stat()
        except OSError:
            dirs[:] = []
            continue
        key = (root_stat.st_dev, root_stat.st_ino)
        if key in visited:  # loop guard (defense in depth alongside followlinks=False)
            dirs[:] = []
            continue
        visited.add(key)

        dirs.sort()
        for name in sorted(files):
            fpath = root_path / name
            if fpath.is_symlink():
                continue  # never follow links out of the evidence tree (MVP)
            try:
                fstat = fpath.stat()
            except OSError:
                continue
            if not fpath.is_file():
                continue
            yield fpath, fstat


def scan_totals(base: Path | str) -> tuple[int, int]:
    """Cheap stat-only pre-scan: ``(file_count, total_bytes)`` - no hashing.

    Used to drive the ingest progress/ETA counter without reading file bytes.
    """
    count = 0
    total = 0
    for _path, fstat in _iter_regular_files(Path(base)):
        count += 1
        total += fstat.st_size
    return count, total


def walk_files(
    base: Path | str,
    *,
    on_progress: Callable[[FileFact], None] | None = None,
    checkpoint_path: Path | str | None = None,
) -> list[FileFact]:
    """Walk ``base`` recursively, returning sorted :class:`FileFact`s.

    Deterministic ordering (sorted by POSIX rel_path). ``on_progress`` (if given)
    is called once per hashed file, in walk order, before the final sort.

    Resumable ingest (D-eqo): when ``checkpoint_path`` is given, completed facts
    persist as JSONL (one flushed line per file, crash-safe) and a re-run reuses
    any entry whose ``(size_bytes, mtime_ns)`` still matches - only new or
    changed files pay for a re-hash. A missing checkpoint starts fresh.
    """
    completed = load_checkpoint(checkpoint_path) if checkpoint_path is not None else {}
    with ExitStack() as stack:
        checkpoint_out: TextIO | None = (
            stack.enter_context(Path(checkpoint_path).open("a", encoding="utf-8"))
            if checkpoint_path is not None
            else None
        )
        facts = _walk_inner(base, completed, checkpoint_out, on_progress)
    facts.sort(key=lambda fact: fact.rel_path)
    return facts


def _walk_inner(
    base: Path | str,
    completed: dict[str, tuple[str, int, int]],
    checkpoint_out: TextIO | None,  # flushed per fact, crash-safe
    on_progress: Callable[[FileFact], None] | None,
) -> list[FileFact]:
    base = Path(base)
    facts: list[FileFact] = []
    for fpath, fstat in _iter_regular_files(base):
        rel = fpath.relative_to(base).as_posix()
        prior = completed.get(rel)
        if prior is not None and (fstat.st_size, fstat.st_mtime_ns) == (prior[1], prior[2]):
            fact = FileFact(
                rel_path=rel,
                sha256=prior[0],
                size_bytes=prior[1],
                mtime_utc=datetime.fromtimestamp(fstat.st_mtime, tz=UTC),
            )
        else:
            try:
                digest = sha256_file(fpath)
            except OSError:
                continue
            fact = FileFact(
                rel_path=rel,
                sha256=digest,
                size_bytes=fstat.st_size,
                mtime_utc=datetime.fromtimestamp(fstat.st_mtime, tz=UTC),
            )
            if checkpoint_out is not None:
                checkpoint_out.write(
                    json.dumps(
                        {
                            "rel_path": rel,
                            "sha256": digest,
                            "size_bytes": fstat.st_size,
                            "mtime_ns": fstat.st_mtime_ns,
                        }
                    )
                    + "\n"
                )
                checkpoint_out.flush()
        facts.append(fact)
        if on_progress is not None:
            on_progress(fact)
    return facts


def load_checkpoint(path: Path | str) -> dict[str, tuple[str, int, int]]:
    """Read a ``walk_files`` checkpoint: ``rel_path -> (sha256, size_bytes, mtime_ns)``.

    Missing file = fresh start. A corrupt line fails closed (the checkpoint is
    untrusted crash residue, not evidence - but silently skipping it would hide
    a bug, so surface it).
    """
    completed: dict[str, tuple[str, int, int]] = {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return completed
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            completed[str(record["rel_path"])] = (
                str(record["sha256"]),
                int(record["size_bytes"]),
                int(record["mtime_ns"]),
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"corrupt ingest checkpoint {path}:{lineno}: {exc}") from exc
    return completed
