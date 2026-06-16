"""Per-run-dir mutual exclusion for tool execution (audit-trail id integrity).

``run_tool`` allocates a deterministic ``TOOL-NNN`` (and, via the tool-result injection scan,
``ALERT-NNN``) from the *current* ledger length and appends. That read-modify-write is correct only
if one tool executes against a given run dir at a time. The sequential dispatch loop holds for the
in-process deterministic floor, but under a **live agent** each task's tool runs in its own
``mcp-serve`` child process, and two children can overlap on the **shared** real run dir - racing on
``len()+1`` and minting a duplicate id (observed in a real run: a duplicated ``TOOL-231`` /
``ALERT-NNN``).

This module serializes ``run_tool`` per run dir with an advisory ``flock`` on a lock file inside the
run dir, which works **across processes** (the racy case) and across threads (a fresh fd per call -
each is its own open file description, so the second ``flock`` blocks until the first releases). The
parallel-dispatch path is unaffected: it executes into **separate staging dirs**, so each gets its
own lock file and runs concurrently; the commit phase is single-threaded.

Determinism: the lock changes no id *values* in a serial run (it only enforces the ordering that
``len()+1`` already assumes), so the golden run stays byte-identical. The lock auto-releases when
the file descriptor closes - including on process death - so a crashed producer never deadlocks.

Linux is the only real target (CLAUDE: Linux-first). ``fcntl`` is guarded so the module imports on
platforms without it, where the lock degrades to a no-op.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - non-Linux dev only; Linux is the target
    fcntl = None  # type: ignore[assignment]

_LOCK_REL = Path(".idlocks") / "run_tool.lock"


@contextmanager
def run_dir_exec_lock(run_root: Path | str) -> Iterator[None]:
    """Hold an exclusive, cross-process lock for the duration of a tool execution in *run_root*."""
    if fcntl is None:  # pragma: no cover - non-Linux fallback
        yield
        return
    lock_path = Path(run_root) / _LOCK_REL
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
