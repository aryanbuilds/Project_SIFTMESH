"""Executor adapter base + registry (Epic F, F1).

One uniform seam for every way a task contract can be executed - the deterministic
real-tool floor (F2), a generic shell agent (F7), or a live headless agent (F8).
The ABC's concrete ``run()`` template owns the two cross-cutting obligations
PLAN/04 attaches to F1 - "produce ``results/TASK-XXX.result.json`` and append one
``agent_calls.jsonl`` line" - and the allowed-tools guard (C2 enforcement point 5),
so a concrete adapter (which implements only ``_execute``/``available``) can never
forget them. The registry resolves an adapter by ``assigned_agent_profile`` and
falls **closed** to the deterministic floor when a profile is unknown or its
CLI/key is absent.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from siftmesh_core.config import SiftmeshSettings
from siftmesh_core.evidence.path_policy import safe_write_path
from siftmesh_core.ledgers.agent_calls import append_agent_call, next_agent_call_id
from siftmesh_core.ledgers.audit_log import log_event, open_orchestration_log
from siftmesh_core.mcp_gateway.registry import assert_tool_allowed
from siftmesh_core.run_dir import RunPaths
from siftmesh_core.schemas.agent_call import AgentCall, AgentCallStatus
from siftmesh_core.schemas.agent_profile import AgentProfile
from siftmesh_core.schemas.task import TaskContract
from siftmesh_core.schemas.task_result import TaskResult

DEFAULT_PROFILE = "deterministic_executor"


@dataclass(frozen=True)
class ResultRef:
    """What an adapter returns: where the result landed + an envelope summary."""

    task_id: str
    result_path: Path
    status: str
    attempt: int
    tool_call_ids: tuple[str, ...]
    claim_ids: tuple[str, ...]


@dataclass(frozen=True)
class AdapterContext:
    """Everything an adapter needs that is not carried by the contract itself."""

    run: RunPaths
    evidence_root: Path
    settings: SiftmeshSettings
    attempt: int = 1
    requested_profile: str | None = None  # what the dispatcher asked for (vs adapter actual)
    critic_feedback: tuple[str, ...] = field(default_factory=tuple)  # Epic G fills on retry
    incident_objective: str | None = None  # operator's TRUSTED objective (from --brief), inlined


class ExecutorAdapter(ABC):
    """Base for every executor adapter (template-method ``run``)."""

    profile_id: str = ""
    backend_label: str = ""

    def __init__(self, *, settings: SiftmeshSettings) -> None:
        self.settings = settings

    def run(self, contract: TaskContract, ctx: AdapterContext) -> ResultRef:
        """Guard tools → execute → write the result envelope → audit the agent call."""
        self._assert_allowed_tools(contract)
        start = datetime.now(UTC)
        result = self._execute(contract, ctx)
        end = datetime.now(UTC)
        ref = write_task_result(ctx.run, result, evidence_root=ctx.evidence_root)
        requested = ctx.requested_profile or self.profile_id
        fell_back = requested if requested != self.profile_id else None
        agent_call_id = next_agent_call_id(ctx.run.root)
        append_agent_call(
            ctx.run.root,
            AgentCall(
                agent_call_id=agent_call_id,
                task_id=contract.task_id,
                profile=requested,
                adapter=self.profile_id,
                backend=self.backend_label,
                attempt=ctx.attempt,
                start_time_utc=start,
                end_time_utc=end,
                status=_agent_status(result.status, fell_back=fell_back is not None),
                fell_back_from=fell_back,
            ),
            evidence_root=ctx.evidence_root,
        )
        self._record_token_usage(ctx, contract.task_id, agent_call_id, requested, end)
        return ref

    def _record_token_usage(
        self,
        ctx: AdapterContext,
        task_id: str,
        agent_call_id: str,
        profile: str,
        recorded_utc: datetime,
    ) -> None:
        """Append one ``agent_tokens.jsonl`` line when a live adapter reported LLM usage.

        The deterministic floor never sets ``_token_usage`` -> no record (golden byte-identical).
        """
        usage = getattr(self, "_token_usage", None)
        if usage is None:
            return
        from siftmesh_core.ledgers.agent_tokens import append_agent_token_usage
        from siftmesh_core.schemas.agent_token_usage import AgentTokenUsage

        append_agent_token_usage(
            ctx.run.root,
            AgentTokenUsage(
                agent_call_id=agent_call_id,
                task_id=task_id,
                profile=profile,
                model=usage.model,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                total_tokens=usage.total_tokens,
                cache_read_tokens=usage.cache_read_tokens,
                cache_creation_tokens=usage.cache_creation_tokens,
                cost_usd=usage.cost_usd,
                recorded_utc=recorded_utc,
            ),
            evidence_root=ctx.evidence_root,
        )

    @abstractmethod
    def _execute(self, contract: TaskContract, ctx: AdapterContext) -> TaskResult:
        """Run the contract and return a typed result envelope (no agent-call I/O)."""

    def available(self) -> bool:
        """Whether this adapter can run here (CLI/key present). Floor is always True."""
        return True

    def profile(self) -> AgentProfile | None:
        """This adapter's declarative profile from ``agent_profiles.yaml`` (model/tier), if any."""
        from siftmesh_core.adapters.profiles import load_profiles

        return load_profiles().get(self.profile_id)

    @staticmethod
    def _assert_allowed_tools(contract: TaskContract) -> None:
        for tool in contract.allowed_tools:
            assert_tool_allowed(tool)  # forbidden/unknown tool → ToolNotAllowedError


def _agent_status(task_status: str, *, fell_back: bool) -> AgentCallStatus:
    if fell_back:
        return "fell_back"
    if task_status in ("success", "error", "retry_required"):
        return task_status  # type: ignore[return-value]
    return "error"


def write_task_result(
    run: RunPaths, result: TaskResult, *, evidence_root: Path | str | None = None
) -> ResultRef:
    """Write ``results/TASK-XXX.result.json`` via the path policy; return a ResultRef."""
    rel = Path("results") / f"{result.task_id}.result.json"
    target = safe_write_path(run.root, rel, evidence_root=evidence_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return ResultRef(
        task_id=result.task_id,
        result_path=target,
        status=result.status,
        attempt=result.attempt,
        tool_call_ids=tuple(result.tool_call_ids),
        claim_ids=tuple(c.claim_id for c in result.claims),
    )


# --- registry --------------------------------------------------------------------
_REGISTRY: dict[str, type[ExecutorAdapter]] = {}


def register(cls: type[ExecutorAdapter]) -> type[ExecutorAdapter]:
    """Class decorator: register an adapter by its ``profile_id``."""
    if not cls.profile_id:
        raise ValueError(f"{cls.__name__} must set a non-empty profile_id")
    _REGISTRY[cls.profile_id] = cls
    return cls


def resolve_profile(
    role: str, *, settings: SiftmeshSettings, cli_override: str | None = None
) -> str:
    """The profile to attempt first for a task with this role (Epic I).

    Precedence: explicit ``--agent`` override > deterministic default (the floor) > a per-role pin
    (``role_profiles``) > the head of the preference chain (live/auto). A plain run uses the floor;
    ``--agent claude`` or ``executor_selection=live/auto`` opts into the live chain.
    """
    if cli_override:
        return cli_override
    if settings.executor_selection == "deterministic":
        return DEFAULT_PROFILE
    if role in settings.role_profiles:
        return settings.role_profiles[role]
    return settings.agent_preference[0] if settings.agent_preference else DEFAULT_PROFILE


def get_adapter(
    profile_id: str, *, settings: SiftmeshSettings, run: RunPaths | None = None
) -> ExecutorAdapter:
    """Resolve an adapter, walking the fallback chain to the first available; floor is final (I2).

    Candidate order = the requested profile, then the rest of ``settings.agent_preference``, then
    the deterministic floor (always registered + available). Each skipped (unknown/unavailable)
    candidate is audited as an ``adapter_unavailable`` orchestration event when a ``run`` is given -
    so a no-keys run records *why* it fell to the floor (e.g. claude→opencode→floor).
    """
    chain: list[str] = [profile_id]
    chain += [p for p in settings.agent_preference if p not in chain]
    if DEFAULT_PROFILE not in chain:
        chain.append(DEFAULT_PROFILE)

    for candidate in chain:
        cls = _REGISTRY.get(candidate)
        if cls is None:
            _audit_unavailable(run, candidate, "unknown_profile")
            continue
        adapter = cls(settings=settings)
        if adapter.available():
            return adapter
        _audit_unavailable(run, candidate, "cli_or_key_absent")
    return _REGISTRY[DEFAULT_PROFILE](settings=settings)  # defensive (floor is always available)


def _audit_unavailable(run: RunPaths | None, requested: str, reason: str) -> None:
    if run is None or requested == DEFAULT_PROFILE:
        return  # the floor never "falls back"; nothing to audit
    log_event(
        open_orchestration_log(run.orchestration_events, run.run_id),
        "adapter_unavailable",
        requested=requested,
        reason=reason,
        fell_back_to=DEFAULT_PROFILE,
    )
