"""Shared helpers for the parser tools (D5-D8).

Resolves an artifact-relative path to a real file *inside* a trusted tree (rejecting
traversal - case data is hostile, CLAUDE.md §6) and hashes the exact bytes the tool is
about to parse (a real per-access integrity hash that becomes the ``source_sha256``
provenance). Two trees are trusted: the read-only evidence root, and - for tools that
read DERIVED artifacts - the active run root (where ``extract_artifacts_from_image`` /
``decompress`` write ``evidence/extracted/…`` with run-root-relative paths).
"""

from __future__ import annotations

from pathlib import Path

from siftmesh_core.evidence.hash_utils import sha256_file


def try_resolve_source(
    evidence_root: Path | str | None,
    source_artifact: str,
    *,
    run_root: Path | str | None = None,
) -> Path | None:
    """Return the trusted real path for ``source_artifact``, or ``None``.

    Same roots logic as :func:`resolved_source` but non-raising, for the
    post-access integrity check (a missing source after a successful parse is
    reported by the caller, not raised here).
    """
    roots: list[Path] = []
    if evidence_root is not None:
        roots.append(Path(evidence_root).resolve())
    if run_root is not None:
        run_resolved = Path(run_root).resolve()
        if run_resolved not in roots:
            roots.append(run_resolved)
    for root in roots:
        path = (root / source_artifact).resolve()
        if not path.is_relative_to(root):
            continue  # escapes this root - try the next trusted root
        if path.is_file():
            return path
    return None


def resolved_source(
    evidence_root: Path | str,
    source_artifact: str,
    *,
    run_root: Path | str | None = None,
) -> tuple[Path, str]:
    """Return ``(real_path, sha256)`` for an artifact, or raise if missing/escaping.

    Resolves ``source_artifact`` under the read-only evidence root and - when ``run_root`` is given
    (derived-artifact readers) - also under the run root. The first trusted root that both
    *contains* the resolved path AND points at a real file wins; a path that escapes every root is
    rejected. Admitting the run root does not widen the boundary beyond directories SIFTMesh owns.
    """
    roots = [Path(evidence_root).resolve()]
    if run_root is not None:
        run_resolved = Path(run_root).resolve()
        if run_resolved not in roots:
            roots.append(run_resolved)
    contained = False
    for root in roots:
        path = (root / source_artifact).resolve()
        if not path.is_relative_to(root):
            continue  # escapes this root - try the next trusted root
        contained = True
        if path.is_file():
            return path, sha256_file(path)
    if not contained:
        raise ValueError(f"artifact escapes evidence root: {source_artifact!r}")
    raise FileNotFoundError(f"source artifact not found: {source_artifact}")
