"""Record the golden run: REAL ledgers + report bodies from real tools over committed fixtures.

Usage:  uv run python tests/golden/record.py --update

Produces (committed to git - the §2B "recorded-golden" regression floor):
  tests/golden/recorded_run/RUN-GOLDEN/   a complete, real run directory (ledgers + reports)
  tests/golden/bodies/                    the deterministic report BODIES (header-stripped)

The pipeline is real end-to-end (manifest -> readonly -> plan -> dispatch of the Epic-D
tools -> critique -> reports). One normalization is applied at record time: the absolute
evidence path inside ``evidence/readonly_mounts.json`` (the only absolute path a run
contains - verified) is rewritten to ``/EVIDENCE`` so the committed run is host-independent.

Re-recording refreshes ledger timestamps (real tools, real clock) - that is BY DESIGN; the
regression invariant is that rendering the COMMITTED run reproduces the COMMITTED bodies
byte-for-byte (tests/EPIC_M_TESTS/test_reports_golden.py). Re-record only after an
intentional schema/report change, then review the diff and commit both dirs together.
"""

from __future__ import annotations

import argparse
import lzma
import shutil
import sys
import tempfile
from pathlib import Path

GOLDEN_DIR = Path(__file__).resolve().parent
REPO_ROOT = GOLDEN_DIR.parents[1]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "forensic"
RECORDED_RUN = GOLDEN_DIR / "recorded_run" / "RUN-GOLDEN"
BODIES = GOLDEN_DIR / "bodies"
EVIDENCE_PLACEHOLDER = "/EVIDENCE"

# body files written: report filename -> golden body filename
MD_REPORTS = (
    "final_report.md",
    "accuracy_report.md",
    "dataset_documentation.md",
    "architecture_notes.md",
)


def _build_evidence(evidence: Path) -> None:
    evidence.mkdir(parents=True, exist_ok=True)
    shutil.copy(FIXTURES / "security_short.evtx", evidence / "Security.evtx")
    shutil.copy(FIXTURES / "prefetch_vista_cmd.pf", evidence / "CMD.EXE-89305D47.pf")
    (evidence / "NTUSER.DAT").write_bytes(
        lzma.decompress((FIXTURES / "ntuser.dat.xz").read_bytes())
    )


def record() -> None:
    from siftmesh_core.config import load_settings
    from siftmesh_core.evidence.manifest import build_manifest_from_dir, write_manifest
    from siftmesh_core.evidence.readonly import write_readonly_record
    from siftmesh_core.orchestrator.critic import critique_run
    from siftmesh_core.orchestrator.planner import generate_plan
    from siftmesh_core.orchestrator.scheduler import dispatch_run
    from siftmesh_core.reports import generate_all_reports
    from siftmesh_core.reports.loader import load_report_view
    from siftmesh_core.reports.render import split_body
    from siftmesh_core.reports.replay import render_text_replay
    from siftmesh_core.run_dir import RunPaths, new_run_dir

    tmp = Path(tempfile.mkdtemp(prefix="siftmesh-golden-"))
    evidence = tmp / "evidence"
    _build_evidence(evidence)
    run = new_run_dir(base=tmp / "case_runs")
    settings = load_settings()
    manifest = build_manifest_from_dir(evidence, case_id="golden-case", run_id=run.run_id)
    write_manifest(manifest, run.root, evidence_root=evidence)
    write_readonly_record(evidence, run.root, file_count=len(manifest.files))
    generate_plan(run, settings=settings)
    dispatch_run(run, settings=settings)
    critique_run(run, settings=settings, evidence_root=evidence)

    # Normalize the ONE absolute path a run contains (host-independence of the committed run).
    readonly = run.root / "evidence" / "readonly_mounts.json"
    readonly.write_text(
        readonly.read_text(encoding="utf-8").replace(str(evidence), EVIDENCE_PLACEHOLDER),
        encoding="utf-8",
    )

    # Refresh the committed run, then render the reports INSIDE it - RunPaths derives the
    # run_id from the directory name, so rendering in RUN-GOLDEN gives the bodies a stable
    # run_id forever (the golden test re-renders in a dir of the same name).
    if RECORDED_RUN.exists():
        shutil.rmtree(RECORDED_RUN)
    RECORDED_RUN.parent.mkdir(parents=True, exist_ok=True)
    # `.idlocks/` holds the transient per-run tool-execution lock - never part of the golden run.
    shutil.copytree(run.root, RECORDED_RUN, ignore=shutil.ignore_patterns(".idlocks"))
    recorded = RunPaths(root=RECORDED_RUN)
    generate_all_reports(recorded)

    # The report HEADERS are volatile by design (generated_utc/host/run_dir) and excluded
    # from the golden bodies - but the committed run must still be host-independent, so
    # rewrite this repo's absolute path out of the committed headers.
    for report in (RECORDED_RUN / "reports").iterdir():
        report.write_text(
            report.read_text(encoding="utf-8").replace(str(RECORDED_RUN), "<RUN>"),
            encoding="utf-8",
        )

    if BODIES.exists():
        shutil.rmtree(BODIES)
    BODIES.mkdir(parents=True)
    for name in (*MD_REPORTS, "replay.html"):  # replay.html carries the same sentinel header
        text = (RECORDED_RUN / "reports" / name).read_text(encoding="utf-8")
        (BODIES / name).write_text(split_body(text), encoding="utf-8")
    view = load_report_view(recorded)
    (BODIES / "replay.txt").write_text(render_text_replay(view), encoding="utf-8")

    leftover = sum(
        p.read_text(encoding="utf-8", errors="ignore").count(str(tmp))
        for p in RECORDED_RUN.rglob("*")
        if p.is_file()
    )
    print(f"recorded run -> {RECORDED_RUN}")
    print(f"bodies       -> {BODIES} ({len(MD_REPORTS) + 2} files)")
    print(f"abs-path leaks remaining: {leftover}")
    if leftover:
        sys.exit(f"ERROR: {leftover} absolute path(s) leaked into the recorded run")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update",
        action="store_true",
        help="actually re-record (overwrites tests/golden/recorded_run + bodies)",
    )
    args = parser.parse_args()
    if not args.update:
        sys.exit("refusing to overwrite goldens without --update (see module docstring)")
    record()
