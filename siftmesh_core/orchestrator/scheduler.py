"""Dispatch / collect orchestration (Epic F, F4/F5).

Service functions behind ``siftmesh dispatch`` and ``siftmesh collect``. ``dispatch``
runs each task contract through its resolved adapter (default = the deterministic
floor) sequentially, recovering the evidence root from the run's
``readonly_mounts.json``. ``collect`` validates each task's result envelope and
reports missing/malformed results without crashing. Parallelism, retries, and the
state machine are Epic G/H - this layer just executes and records.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from siftmesh_core.adapters import AdapterContext, ResultRef, get_adapter, resolve_profile
from siftmesh_core.adapters.base import DEFAULT_PROFILE, ExecutorAdapter, write_task_result
from siftmesh_core.config import SiftmeshSettings
from siftmesh_core.evidence.path_policy import assert_run_outside_evidence
from siftmesh_core.ledgers.agent_calls import append_agent_call, next_agent_call_id
from siftmesh_core.ledgers.audit_log import log_event, open_orchestration_log
from siftmesh_core.mcp_gateway.backends import BackendUnavailableError
from siftmesh_core.run_dir import RunPaths
from siftmesh_core.schemas.agent_call import AgentCall
from siftmesh_core.schemas.evidence import EvidenceManifest
from siftmesh_core.schemas.plan import InvestigationPlan
from siftmesh_core.schemas.task import TaskContract
from siftmesh_core.schemas.task_result import TaskResult
from siftmesh_core.schemas.yaml_io import read_yaml_model

# Heavy or high-volume tool-bound tasks that add nothing under a live agent (the tool does the work)
# and either time out its wrapper (image/memory) or overflow its context with thousands of tabular
# rows ($MFT / USN journal / Plaso super-timeline) - run on the deterministic floor even when a live
# agent is selected, unless the operator forces `live_extraction` (`run --all-live`). The floor has
# real claim builders for all of these, so floor-routing yields anchored claims instead of a live
# agent that cannot anchor the volume and gets quarantined. Executor tiering (scale fixes).
_HEAVY_TOOL_BOUND = frozenset(
    {
        "extract_artifacts_from_image",
        "analyze_memory",
        "parse_mft_filesystem",
        "parse_usnjrnl",
        "build_super_timeline",
    }
)


def _has_derived_input(contract: TaskContract) -> bool:
    """True if any input is a derived artifact (resolved under the run dir, not staging)."""
    return any(getattr(a, "origin", "evidence") == "derived" for a in contract.input_artifacts)


class PolicyError(RuntimeError):
    """A dispatch was refused by policy (e.g. a review-only run)."""


class CapError(RuntimeError):
    """A safety cap (CLAUDE.md §11) was exceeded."""


@dataclass(frozen=True)
class CollectRow:
    task_id: str
    status: str  # the TaskResult status, or "missing" / "malformed"
    claim_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CollectReport:
    rows: list[CollectRow]

    @property
    def missing(self) -> list[str]:
        return [r.task_id for r in self.rows if r.status == "missing"]

    @property
    def malformed(self) -> list[str]:
        return [r.task_id for r in self.rows if r.status == "malformed"]


def _incident_objective(run: RunPaths) -> str | None:
    """The operator's TRUSTED incident objective from the manifest (None if no --brief given)."""
    if not run.evidence_manifest.is_file():
        return None
    manifest = EvidenceManifest.model_validate_json(
        run.evidence_manifest.read_text(encoding="utf-8")
    )
    return manifest.incident_objective


def recover_evidence_root(run: RunPaths) -> Path:
    """Read the evidence root recorded at init-case from ``readonly_mounts.json``."""
    if not run.readonly_mounts.is_file():
        raise FileNotFoundError(
            f"no readonly_mounts.json at {run.readonly_mounts}; pass --evidence"
        )
    data = json.loads(run.readonly_mounts.read_text(encoding="utf-8"))
    return Path(data["sources"][0]["path"])


def _load_contracts(run: RunPaths, task_id: str | None) -> list[TaskContract]:
    paths = sorted(run.tasks.glob("TASK-*.yaml"))
    contracts = [read_yaml_model(TaskContract, p) for p in paths]
    if task_id is not None:
        contracts = [c for c in contracts if c.task_id == task_id]
        if not contracts:
            raise FileNotFoundError(f"no task contract {task_id} under {run.tasks}")
    return contracts


def _record_failed(
    run: RunPaths,
    contract: TaskContract,
    profile: str,
    code: str,
    evidence_root: Path,
) -> ResultRef:
    """Write an honest error TaskResult + agent_call when a dispatch fails closed."""
    now = datetime.now(UTC)
    result = TaskResult(
        task_id=contract.task_id,
        profile=profile,
        adapter=profile,
        attempt=1,
        status="error",
        started_utc=now,
        ended_utc=now,
        errors=[code],
    )
    ref = write_task_result(run, result, evidence_root=evidence_root)
    append_agent_call(
        run.root,
        AgentCall(
            agent_call_id=next_agent_call_id(run.root),
            task_id=contract.task_id,
            profile=profile,
            adapter=profile,
            backend="none",
            attempt=1,
            start_time_utc=now,
            end_time_utc=now,
            status="error",
        ),
        evidence_root=evidence_root,
    )
    return ref


def dispatch_run(
    run: RunPaths,
    *,
    settings: SiftmeshSettings,
    evidence_override: Path | str | None = None,
    task_id: str | None = None,
    agent_profile: str | None = None,
    attempt: int = 1,
    critic_feedback: tuple[str, ...] = (),
) -> list[ResultRef]:
    """Execute the run's task contracts (or one) sequentially; return their ResultRefs."""
    evidence_root = Path(evidence_override) if evidence_override else recover_evidence_root(run)
    assert_run_outside_evidence(run.root, evidence_root)

    plan = read_yaml_model(InvestigationPlan, run.investigation_plan)
    if plan.review_only:
        raise PolicyError("run is review-only; dispatch is disabled (E8)")

    contracts = _load_contracts(run, task_id)
    if len(contracts) > settings.caps.max_agent_tasks:
        n = len(contracts)
        raise CapError(
            f"{n} tasks exceeds max_agent_tasks={settings.caps.max_agent_tasks}. "
            f"A real disk image yields 200+ derived tasks - raise the cap explicitly: "
            f"`siftmesh run … --max-agent-tasks {n}` "
            f"(or export SIFTMESH_CAPS__MAX_AGENT_TASKS={n}), "
            f"or scope extraction with `extract-artifacts --keys …`."
        )

    # The operator's TRUSTED incident objective (from --brief), inlined into every agent prompt so
    # the live agent investigates TOWARD it. Manifest metadata only - not the hostile evidence set.
    incident_objective = _incident_objective(run)

    audit = open_orchestration_log(run.orchestration_events, run.run_id)

    # Deterministic parallel dispatch (B5) - opt-in, byte-identical to sequential. Skipped when any
    # task has a derived-origin input (those resolve under the run dir, not staging).
    if (
        settings.parallel_dispatch
        and len(contracts) > 1
        and settings.caps.max_parallel_tasks > 1
        and not any(_has_derived_input(c) for c in contracts)
    ):
        return _dispatch_parallel(
            run,
            contracts,
            settings=settings,
            evidence_root=evidence_root,
            agent_profile=agent_profile,
            attempt=attempt,
            critic_feedback=critic_feedback,
            incident_objective=incident_objective,
            audit=audit,
        )

    refs: list[ResultRef] = []
    for contract in contracts:
        profile = _resolve_with_tiering(contract, settings, agent_profile, audit)
        adapter = get_adapter(profile, settings=settings, run=run)
        ctx = AdapterContext(
            run=run,
            evidence_root=evidence_root,
            settings=settings,
            requested_profile=profile,
            attempt=attempt,
            critic_feedback=critic_feedback,
            incident_objective=incident_objective,
        )
        try:
            ref = adapter.run(contract, ctx)
        except BackendUnavailableError as exc:
            ref = _record_failed(
                run, contract, profile, f"backend_unavailable:{exc}", evidence_root
            )
        log_event(
            audit,
            "task_dispatched",
            task_id=contract.task_id,
            profile=profile,
            adapter=adapter.profile_id,
            status=ref.status,
        )
        refs.append(ref)
    return refs


def _resolve_with_tiering(
    contract: TaskContract,
    settings: SiftmeshSettings,
    agent_profile: str | None,
    audit: object,
) -> str:
    """Resolve a contract's profile, forcing the deterministic floor for heavy tool-bound tasks."""
    profile = resolve_profile(contract.role, settings=settings, cli_override=agent_profile)
    if (
        profile != DEFAULT_PROFILE
        and not settings.live_extraction
        and any(t in _HEAVY_TOOL_BOUND for t in contract.allowed_tools)
    ):
        log_event(
            audit,  # type: ignore[arg-type]
            "tier_floor_forced",
            task_id=contract.task_id,
            tool=",".join(contract.allowed_tools),
            reason="heavy_tool_bound",
        )
        profile = DEFAULT_PROFILE
    return profile


def _dispatch_parallel(
    run: RunPaths,
    contracts: list[TaskContract],
    *,
    settings: SiftmeshSettings,
    evidence_root: Path,
    agent_profile: str | None,
    attempt: int,
    critic_feedback: tuple[str, ...],
    incident_objective: str | None,
    audit: object,
) -> list[ResultRef]:
    """Execute tasks concurrently into per-task staging, then commit in contract order (B5)."""
    from siftmesh_core.orchestrator.parallel_dispatch import (
        cleanup_staging,
        commit_staged_task,
        execute_parallel,
    )

    # Serial pre-pass: resolve profile + adapter per contract (get_adapter logs to the real run).
    plan: list[tuple[TaskContract, str, ExecutorAdapter]] = []
    for contract in contracts:
        profile = _resolve_with_tiering(contract, settings, agent_profile, audit)
        plan.append((contract, profile, get_adapter(profile, settings=settings, run=run)))

    workers = min(settings.caps.max_parallel_tasks, len(contracts))
    log_event(audit, "parallel_dispatch_started", tasks=len(contracts), workers=workers)  # type: ignore[arg-type]
    staged = execute_parallel(
        plan,
        run,
        evidence_root=evidence_root,
        settings=settings,
        attempt=attempt,
        critic_feedback=critic_feedback,
        incident_objective=incident_objective,
        max_workers=workers,
    )

    # Serial commit in contract order → ledgers byte-identical to sequential.
    refs: list[ResultRef] = []
    for s in staged:
        if s.error is not None:
            ref = _record_failed(run, s.contract, s.profile, s.error, evidence_root)
        else:
            ref = commit_staged_task(run, s, evidence_root=evidence_root)
        log_event(
            audit,  # type: ignore[arg-type]
            "task_dispatched",
            task_id=s.contract.task_id,
            profile=s.profile,
            adapter=s.adapter_id,
            status=ref.status,
        )
        refs.append(ref)
    cleanup_staging(run)
    return refs


def collect_run(run: RunPaths, *, task_id: str | None = None) -> CollectReport:
    """Validate each task's result envelope; flag missing/malformed without crashing."""
    expected = [c.task_id for c in _load_contracts(run, task_id)]
    rows: list[CollectRow] = []
    audit = open_orchestration_log(run.orchestration_events, run.run_id)
    for tid in expected:
        path = run.result_path(tid)
        if not path.is_file():
            rows.append(CollectRow(tid, "missing"))
            log_event(audit, "result_missing", task_id=tid)
            continue
        try:
            tr = TaskResult.model_validate_json(path.read_text(encoding="utf-8"))
        except ValueError:
            rows.append(CollectRow(tid, "malformed"))
            log_event(audit, "result_malformed", task_id=tid)
            continue
        rows.append(CollectRow(tid, tr.status, [c.claim_id for c in tr.claims]))
        log_event(audit, "result_collected", task_id=tid, status=tr.status)
    return CollectReport(rows=rows)
