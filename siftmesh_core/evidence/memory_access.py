"""Memory-image acquisition (Epic D deepening) - unpack a compressed memory capture.

SANS memory captures arrive as ``Rocba-Memory.zip`` → ``.7z`` → a raw/crash/LiME image.
Only the needed member is extracted at each stage (5hk: the largest file, preferring a
nested archive) - a huge multi-member archive is never fully extracted. The final image's
path/hash feeds the memory tool; a missing ``7z`` binary **fails closed**
(:class:`BackendUnavailableError`). Intermediate archives are removed after a successful
decompression to conserve disk.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path

from siftmesh_core.evidence.hash_utils import sha256_file
from siftmesh_core.mcp_gateway.backends import BackendUnavailableError

_DEFAULT_TIMEOUT = 3600  # seconds; multi-GB 7z decompression

# First-bytes magic → memory image format.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"PAGEDU64", "windows_crashdump64"),
    (b"PAGEDUMP", "windows_crashdump32"),
    (b"EMiL", "lime"),
)


@dataclass(frozen=True)
class MemoryImage:
    """A decompressed memory capture ready for analysis."""

    path: Path
    image_format: str
    size_bytes: int
    sha256: str


def detect_format(path: Path) -> str:
    """Identify a memory image by leading magic; default ``raw``."""
    with Path(path).open("rb") as handle:
        head = handle.read(8)
    for magic, name in _MAGIC:
        if head.startswith(magic):
            return name
    return "raw"


def _require_7z() -> str:
    for name in ("7z", "7za", "7zr"):
        found = shutil.which(name)
        if found is not None:
            return found
    raise BackendUnavailableError("'7z' not found on PATH (install 'p7zip-full'); fails closed")


# Archive suffixes preferred when choosing the single member to extract: the
# memory image usually rides inside a nested archive, not beside it.
_ARCHIVE_SUFFIXES = (".7z", ".zip", ".rar", ".tar", ".gz", ".bz2", ".xz")


def _needed_zip_member(zf: zipfile.ZipFile) -> str | None:
    """Pick the one zip member to extract, peeking at magic via streaming reads.

    A member with memory-image magic wins; else a nested archive (the image
    usually rides inside one); else the largest file. Nothing is extracted to
    choose - only first-bytes peeks - so a huge decoy is never paid for.
    """
    files = [i for i in zf.infolist() if not i.is_dir()]
    if not files:
        return None
    magics = {m for m, _ in _MAGIC}
    with_magic: list[str] = []
    for info in files:
        try:
            with zf.open(info.filename) as handle:
                head = handle.read(8)
        except (RuntimeError, zipfile.BadZipFile, OSError):
            continue
        if any(head.startswith(m) for m in magics):
            with_magic.append(info.filename)
    if with_magic:
        sizes = {i.filename: i.file_size for i in files}
        return max(with_magic, key=lambda n: sizes.get(n, 0))
    archived = [i.filename for i in files if i.filename.lower().endswith(_ARCHIVE_SUFFIXES)]
    pool = archived or [i.filename for i in files]
    sizes = {i.filename: i.file_size for i in files}
    return max(pool, key=lambda n: sizes.get(n, 0))


def _seven_zip_members(archive: Path, *, timeout: int) -> list[tuple[str, int]]:
    """List ``(member, size)`` files inside a 7z archive via ``7z l -slt`` (fixed argv)."""
    exe = _require_7z()
    proc = subprocess.run(  # fixed argv, shell=False, validated path
        [exe, "l", "-slt", str(archive)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"7z listing failed: {proc.stderr.strip() or 'non-zero exit'}")
    members: list[tuple[str, int]] = []
    path: str | None = None
    size = 0
    is_folder = False
    for line in [*proc.stdout.splitlines(), ""]:
        if not line.strip():
            if path is not None and not is_folder:
                members.append((path, size))
            path, size, is_folder = None, 0, False
        elif line.startswith("Path = "):
            path = line[len("Path = "):]
        elif line.startswith("Size = "):
            try:
                size = int(line[len("Size = "):].strip())
            except ValueError:
                size = 0
        elif line.startswith("Folder = +"):
            is_folder = True
    return members


def _extract_7z_member(
    archive: Path, member: str, dest_dir: Path, *, timeout: int
) -> None:
    """Extract one 7z member into ``dest_dir`` (fixed argv, ``shell=False``)."""
    exe = _require_7z()
    proc = subprocess.run(  # fixed argv, shell=False, validated path
        [exe, "e", "-y", f"-o{dest_dir}", str(archive), member],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"7z extraction failed: {proc.stderr.strip() or 'non-zero exit'}")


def _extract_zip_member(zf: zipfile.ZipFile, member: str, dest_dir: Path) -> Path:
    """Stream one zip member to ``dest_dir`` under its basename (zip-slip guard)."""
    dest_resolved = dest_dir.resolve()
    target = (dest_dir / Path(member.replace("\\", "/")).name).resolve()
    if not target.is_relative_to(dest_resolved):
        raise RuntimeError(f"zip member escapes dest dir: {member!r}")
    with zf.open(member) as src, target.open("wb") as dst:
        shutil.copyfileobj(src, dst)
    return target


def _largest_file(directory: Path, *, exclude: set[Path]) -> Path | None:
    candidates = [p for p in directory.rglob("*") if p.is_file() and p.resolve() not in exclude]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


def decompress(
    zip_path: Path | str, dest_dir: Path, *, timeout: int = _DEFAULT_TIMEOUT
) -> MemoryImage:
    """Unzip + 7z-decompress a memory capture into ``dest_dir``; return the image.

    ``dest_dir`` must already be a caller-validated (``safe_write_path``) directory.
    """
    zip_path = Path(zip_path)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # 1) Unzip the outer .zip (stdlib) - extract ONLY the needed member.
    extracted_members: list[Path] = []
    if zipfile.is_zipfile(zip_path):
        with zipfile.ZipFile(zip_path) as zf:
            member = _needed_zip_member(zf)
            if member is None:
                raise RuntimeError("zip archive holds no files to parse")
            extracted_members.append(_extract_zip_member(zf, member, dest_dir))
    else:
        # Not a zip - treat the input itself as the (possibly .7z) capture.
        local = dest_dir / zip_path.name
        if local.resolve() != zip_path.resolve():
            shutil.copyfile(zip_path, local)
        extracted_members.append(local)

    # 2) 7z-decompress any .7z member - extract ONLY its largest file member.
    intermediate: set[Path] = {p.resolve() for p in extracted_members}
    for archive in [p for p in extracted_members if p.suffix.lower() == ".7z"]:
        try:
            members = _seven_zip_members(archive, timeout=timeout)
        except RuntimeError:
            members = []  # unlistable: fall back to full extraction below
        needed = max(members, key=lambda m: m[1], default=None)
        if needed is None:
            exe = _require_7z()
            proc = subprocess.run(  # fixed argv, shell=False, validated path
                [exe, "x", "-y", f"-o{dest_dir}", str(archive)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"7z extraction failed: {proc.stderr.strip() or 'non-zero exit'}"
                )
        else:
            _extract_7z_member(archive, needed[0], dest_dir, timeout=timeout)
            intermediate.add((dest_dir / Path(needed[0].replace("\\", "/")).name).resolve())

    # 3) The memory image is the largest file that is not an intermediate archive.
    image = _largest_file(dest_dir, exclude=intermediate)
    if image is None:  # only archives were present (or nothing) - fall back to the largest member
        image = _largest_file(dest_dir, exclude=set())
    if image is None:
        raise RuntimeError("no memory image found after decompression")

    # 4) Tidy intermediates to conserve disk (they are our own derived temps).
    for archive in [p for p in extracted_members if p.suffix.lower() == ".7z"]:
        if archive.resolve() != image.resolve():
            archive.unlink(missing_ok=True)

    return MemoryImage(
        path=image,
        image_format=detect_format(image),
        size_bytes=image.stat().st_size,
        sha256=sha256_file(image),
    )
