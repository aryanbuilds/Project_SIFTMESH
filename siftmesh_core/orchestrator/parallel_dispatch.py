"""Deterministic parallel dispatch (Epic B5 / bd vd2t) - execute isolated, commit in contract order.

Naive parallelism would break the determinism guarantee (golden byte-identity + manual==auto):
``run_tool`` mints ``TOOL-NNN`` from the *current* ledger length and appends immediately, so two
concurrent tools race on ids + interleave ``tool_calls.jsonl`` by completion order. The fix is to
**decouple execution from commit**:

1. **Isolate** - each task executes into a private staging run-dir
   (``run.root/.staging/<TASK-ID>/<RUN-ID>``; named with the real run-id so custody ``run_id`` stays
   correct). Its tools mint *local* ``TOOL-001…`` with zero cross-task contention; the live agent's
   MCP server is pointed at the staging root (``SIFTMESH_RUN_ROOT``) so concurrent ``claude -p``
   subprocesses never collide.
2. **Barrier + commit-in-contract-order** - after all tasks finish, replay each task's staged
   records into the real run dir **in the contracts' sorted order**, renumbering the only
   order-dependent global ids (``TOOL-NNN`` / ``AGENT-NNN`` / ``ALERT-NNN``) through the real
   length-based allocators and remapping their references. Claim ids are task-scoped (no renumber);
   structured/raw result
   files are *renamed* not rewritten (content + ``derived_sha256`` unchanged). The committed ledgers
   are therefore **byte-identical** to a sequential run - proven by ``test_parallel_dispatch.py``.

Feature-gated OFF by default (``settings.parallel_dispatch``): a plain run stays strictly sequential
and byte-identical. Tasks with a ``derived``-origin input fall back to sequential (their inputs live
under the real run dir, not staging).
"""

from __future__ import annotations

import shutil
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from siftmesh_core.adapters import AdapterContext, ResultRef
from siftmesh_core.adapters.base import ExecutorAdapter
from siftmesh_core.config import SiftmeshSettings
from siftmesh_core.evidence.derived import append_derived, read_derived
from siftmesh_core.evidence.path_policy import safe_write_path
from siftmesh_core.ledgers.agent_calls import (
    append_agent_call,
    next_agent_call_id,
    read_agent_calls,
)
from siftmesh_core.ledgers.agent_tokens import (
    append_agent_token_usage,
    read_agent_token_usage,
)
from siftmesh_core.ledgers.claim_ledger import append_claim, read_claims, read_unsupported_claims
from siftmesh_core.ledgers.custody_ledger import append_event
from siftmesh_core.ledgers.injection_alerts import (
    append_injection_alert,
    next_alert_id,
    read_injection_alerts,
)
from siftmesh_core.ledgers.tool_call_ledger import append_tool_result, read_tool_results
from siftmesh_core.mcp_gateway.backends import BackendUnavailableError
from siftmesh_core.run_dir import RunPaths
from siftmesh_core.schemas.claim import Claim
from siftmesh_core.schemas.custody import CustodyEvent
from siftmesh_core.schemas.task import TaskContract
from siftmesh_core.schemas.task_result import TaskResult


@dataclass
class _Staged:
    """One task's parallel-execution outcome (its private staging run + any backend failure)."""

    contract: TaskContract
    profile: str
    adapter_id: str
    staging: RunPaths
    error: str | None = None  # backend_unavailable:<msg> when the adapter failed closed


def staging_run(run: RunPaths, task_id: str) -> RunPaths:
    """Per-task staging run-dir, named with the REAL run-id so custody run_id stays correct."""
    return RunPaths(root=run.root / ".staging" / task_id / run.run_id)


def has_derived_input(contract: TaskContract) -> bool:
    """True if any input is a derived artifact (resolved under the run dir, not staging)."""
    return any(getattr(a, "origin", "evidence") == "derived" for a in contract.input_artifacts)


def execute_parallel(
    plan: list[tuple[TaskContract, str, ExecutorAdapter]],
    run: RunPaths,
    *,
    evidence_root: Path,
    settings: SiftmeshSettings,
    attempt: int,
    critic_feedback: tuple[str, ...],
    incident_objective: str | None,
    max_workers: int,
) -> list[_Staged]:
    """Run each (contract, profile, adapter) into its own staging dir concurrently; return outcomes.

    The adapter writes ONLY into the staging run (ledgers, results, custody) - no shared-state
    contention. Exceptions are captured per task; nothing is committed here.
    """

    def _one(item: tuple[TaskContract, str, ExecutorAdapter]) -> _Staged:
        contract, profile, adapter = item
        staging = staging_run(run, contract.task_id)
        staging.root.mkdir(parents=True, exist_ok=True)
        ctx = AdapterContext(
            run=staging,
            evidence_root=evidence_root,
            settings=settings,
            requested_profile=profile,
            attempt=attempt,
            critic_feedback=critic_feedback,
            incident_objective=incident_objective,
        )
        adapter_id = adapter.profile_id
        try:
            adapter.run(contract, ctx)  # writes into the staging run only
            return _Staged(contract, profile, adapter_id, staging)
        except BackendUnavailableError as exc:
            return _Staged(
                contract, profile, adapter_id, staging, error=f"backend_unavailable:{exc}"
            )

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        # map() preserves input order, but commit re-orders by contract anyway (determinism).
        return list(pool.map(_one, plan))


def _renamed(rel: str | None, old_id: str, new_id: str) -> str | None:
    return rel.replace(old_id, new_id, 1) if rel else rel


def _remap_refs(claim: Claim, tool_remap: dict[str, str]) -> Claim:
    """Rewrite a claim's tool_call_id + supporting_evidence_refs through the id remap (claim_id is
    task-scoped and unchanged)."""
    new_tcid = (
        tool_remap.get(claim.tool_call_id, claim.tool_call_id) if claim.tool_call_id else None
    )
    refs = [tool_remap.get(r, r) for r in claim.supporting_evidence_refs]
    return claim.model_copy(update={"tool_call_id": new_tcid, "supporting_evidence_refs": refs})


def commit_staged_task(run: RunPaths, staged: _Staged, *, evidence_root: Path) -> ResultRef:
    """Replay one staged task's records into the real run dir, renumbering global ids.

    Called serially in contract order so the real ledgers come out byte-identical to sequential.
    """
    src = staged.staging
    tool_remap: dict[str, str] = {}

    # 1. Tool calls (staged order) - assign the real global TOOL id, rename result files (content
    #    unchanged → derived_sha256 unchanged), re-append provenance with remapped paths.
    for tr in read_tool_results(src.root):
        new_id = _next_tool_call_id(run.root)
        tool_remap[tr.tool_call_id] = new_id
        for old_rel in (tr.structured_result_path, tr.raw_output_path):
            if not old_rel:
                continue
            new_rel = _renamed(old_rel, tr.tool_call_id, new_id)
            assert new_rel is not None
            dst = safe_write_path(run.root, new_rel, evidence_root=evidence_root)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src.root / old_rel), str(dst))
        append_tool_result(
            run.root,
            tr.model_copy(
                update={
                    "tool_call_id": new_id,
                    "structured_result_path": _renamed(
                        tr.structured_result_path, tr.tool_call_id, new_id
                    ),
                    "raw_output_path": _renamed(tr.raw_output_path, tr.tool_call_id, new_id),
                }
            ),
            evidence_root=evidence_root,
        )

    # 2. Derived artifacts - remap tool_call_id + derived_path (file already moved; sha unchanged).
    for d in read_derived(src.root):
        new_id = tool_remap.get(d.tool_call_id, d.tool_call_id)
        append_derived(
            run.root,
            d.__class__(
                **{
                    **d.__dict__,
                    "tool_call_id": new_id,
                    "derived_path": _renamed(d.derived_path, d.tool_call_id, new_id),
                }
            ),
            evidence_root=evidence_root,
        )

    # 3. Custody (tool_invoked events; run_id already correct via the staging dir name; no tool id).
    for ev in _read_custody(src.root):
        append_event(run.root, ev, evidence_root=evidence_root)

    # 4. Claims (claim_ledger then unsupported) - remap evidence refs; claim_id is task-scoped.
    for c in read_claims(src.root):
        append_claim(run.root, _remap_refs(c, tool_remap), evidence_root=evidence_root)
    for c in read_unsupported_claims(src.root):
        append_claim(run.root, _remap_refs(c, tool_remap), evidence_root=evidence_root)

    # 5. Injection alerts - new global ALERT id; remap task_id when it is a tool id (the run_tool
    #    tool-result scan stamps task_id = the producing tool_call_id).
    for a in read_injection_alerts(src.root):
        append_injection_alert(
            run.root,
            a.model_copy(
                update={
                    "alert_id": next_alert_id(run.root),
                    "task_id": tool_remap.get(a.task_id, a.task_id) if a.task_id else a.task_id,
                }
            ),
            evidence_root=evidence_root,
        )

    # 6. Agent call (one per task) - new global AGENT id; capture the remap for token usage.
    agent_remap: dict[str, str] = {}
    for ac in read_agent_calls(src.root):
        new_aid = next_agent_call_id(run.root)
        agent_remap[ac.agent_call_id] = new_aid
        append_agent_call(
            run.root,
            ac.model_copy(update={"agent_call_id": new_aid}),
            evidence_root=evidence_root,
        )

    # 6b. Per-agent LLM token usage (live agents only) - remap to the committed agent_call_id.
    for tu in read_agent_token_usage(src.root):
        append_agent_token_usage(
            run.root,
            tu.model_copy(
                update={"agent_call_id": agent_remap.get(tu.agent_call_id, tu.agent_call_id)}
            ),
            evidence_root=evidence_root,
        )

    # 7. Result envelope - remap its claims' refs, write to the real results/.
    from siftmesh_core.adapters.base import write_task_result

    env = TaskResult.model_validate_json(
        (src.root / "results" / f"{staged.contract.task_id}.result.json").read_text(
            encoding="utf-8"
        )
    )
    env = env.model_copy(update={"claims": [_remap_refs(c, tool_remap) for c in env.claims]})
    return write_task_result(run, env, evidence_root=evidence_root)


def _next_tool_call_id(run_root: Path | str) -> str:
    from siftmesh_core.mcp_gateway.audit_exec import _next_tool_call_id as _n

    return _n(run_root)


def _read_custody(run_root: Path | str) -> list[CustodyEvent]:
    path = Path(run_root) / "evidence" / "custody_log.jsonl"
    if not path.is_file():
        return []
    return [
        CustodyEvent.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def cleanup_staging(run: RunPaths) -> None:
    """Remove the .staging tree after a successful commit (best-effort)."""
    staging_root = run.root / ".staging"
    if staging_root.exists():
        shutil.rmtree(staging_root, ignore_errors=True)
