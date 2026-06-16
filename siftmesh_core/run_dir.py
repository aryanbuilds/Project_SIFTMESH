"""Run-directory generator (A4).

Every run's state lives under one inspectable directory ``case_runs/RUN-*`` with
a fixed subtree (CLAUDE.md §5). Run IDs are UTC; creation is collision-safe so a
same-second second call never clobbers the first. ``pathlib`` only.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

RUN_SUBDIRS: tuple[str, ...] = (
    "context",
    "evidence",
    "tasks",
    "results",
    "claims",
    "audit",
    "reports",
)

RUN_ID_FORMAT = "RUN-%Y%m%d-%H%M%S"
DEFAULT_BASE = "case_runs"


@dataclass(frozen=True)
class RunPaths:
    """Typed accessor for a run directory's standard locations."""

    root: Path

    @property
    def run_id(self) -> str:
        return self.root.name

    @property
    def context(self) -> Path:
        return self.root / "context"

    @property
    def evidence(self) -> Path:
        return self.root / "evidence"

    @property
    def tasks(self) -> Path:
        return self.root / "tasks"

    @property
    def results(self) -> Path:
        return self.root / "results"

    @property
    def claims(self) -> Path:
        return self.root / "claims"

    @property
    def audit(self) -> Path:
        return self.root / "audit"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @property
    def evidence_manifest(self) -> Path:
        return self.evidence / "evidence_manifest.json"

    @property
    def hashes_sha256(self) -> Path:
        """``sha256sum -c``-compatible checksum file (B4)."""
        return self.evidence / "hashes.sha256"

    @property
    def readonly_mounts(self) -> Path:
        """Read-only *posture* record (B3). Posture-only, not OS RO-mount."""
        return self.evidence / "readonly_mounts.json"

    @property
    def derived_artifacts(self) -> Path:
        """Append-only registry of derived files → source + hash + producer (B5)."""
        return self.evidence / "derived_artifacts.json"

    @property
    def custody_log(self) -> Path:
        """Chain-of-custody ledger (B9). One CustodyEvent per line."""
        return self.evidence / "custody_log.jsonl"

    @property
    def evidence_policy(self) -> Path:
        """Generated evidence-handling policy doc (B6)."""
        return self.context / "evidence_policy.md"

    @property
    def protocol_sift_capabilities(self) -> Path:
        """Validated Protocol SIFT capability map (D11)."""
        return self.context / "protocol_sift_capabilities.json"

    @property
    def case_brief(self) -> Path:
        """Planner-written scope/objective/constraints brief (E3)."""
        return self.context / "case_brief.md"

    @property
    def context_pack(self) -> Path:
        """Deep-context pack: artifact families + per-family tool guidance (E2)."""
        return self.context / "context_pack.md"

    @property
    def incident_brief(self) -> Path:
        """Operator's TRUSTED incident briefing (the objective), rendered from ``--brief``."""
        return self.context / "incident_brief.md"

    @property
    def investigation_plan(self) -> Path:
        """Ordered investigation step graph (E4)."""
        return self.context / "investigation_plan.yaml"

    @property
    def tool_map(self) -> Path:
        """Artifact-family -> allowed typed-tool map (E5)."""
        return self.context / "tool_map.md"

    @property
    def assumptions(self) -> Path:
        """Explicit planning assumptions, e.g. timezone (E3)."""
        return self.context / "assumptions.md"

    @property
    def claim_ledger(self) -> Path:
        return self.claims / "claim_ledger.jsonl"

    @property
    def injection_alerts(self) -> Path:
        """Prompt-injection alerts (F3). One InjectionAlert per line."""
        return self.claims / "injection_alerts.jsonl"

    @property
    def unsupported_claims(self) -> Path:
        """Unsupported-claim ledger (mirrors claim_ledger's internal path)."""
        return self.claims / "unsupported_claims.jsonl"

    @property
    def contradiction_ledger(self) -> Path:
        """Contradiction records the critic detected (G3)."""
        return self.claims / "contradiction_ledger.jsonl"

    @property
    def confidence_changes(self) -> Path:
        """Audited confidence downgrades (G3). One ConfidenceChange per line."""
        return self.claims / "confidence_changes.jsonl"

    @property
    def tool_calls(self) -> Path:
        return self.audit / "tool_calls.jsonl"

    @property
    def agent_calls(self) -> Path:
        """Per-dispatch agent-call audit (F6). One AgentCall per line."""
        return self.audit / "agent_calls.jsonl"

    @property
    def agent_tokens(self) -> Path:
        """Per-live-dispatch LLM token usage. One AgentTokenUsage per line (live agents only)."""
        return self.audit / "agent_tokens.jsonl"

    @property
    def retries(self) -> Path:
        """Retry history ledger (G5). One RetryRecord per line."""
        return self.audit / "retries.jsonl"

    @property
    def critic_verdicts(self) -> Path:
        """Per-task critic verdicts (G1). One CriticVerdict per line."""
        return self.audit / "critic_verdicts.jsonl"

    @property
    def followups(self) -> Path:
        """Coverage/corroboration follow-ups the critic raised (G9). One per line."""
        return self.audit / "followups.jsonl"

    @property
    def tier2_judgements(self) -> Path:
        """Advisory Tier-2 LLM-judge verdicts (G8). Verbatim; advisory-only, never a fact."""
        return self.audit / "tier2_judgements.jsonl"

    @property
    def orchestration_events(self) -> Path:
        return self.audit / "orchestration_events.jsonl"

    @property
    def run_state(self) -> Path:
        """Durable state-machine snapshot (H1). Overwritten atomically each transition."""
        return self.root / "run_state.json"

    @property
    def token_budget(self) -> Path:
        """Budget-router routing decisions (H9). One record per line."""
        return self.audit / "token_budget.jsonl"

    def result_path(self, task_id: str) -> Path:
        """Per-task executor result envelope, ``results/TASK-XXX.result.json`` (F)."""
        return self.results / f"{task_id}.result.json"

    def subdirs(self) -> list[Path]:
        return [self.root / name for name in RUN_SUBDIRS]


def utc_run_id() -> str:
    """Return a UTC run id, e.g. ``RUN-20260605-143001``."""
    return datetime.now(UTC).strftime(RUN_ID_FORMAT)


def new_run_dir(base: Path | str = DEFAULT_BASE, run_name: str | None = None) -> RunPaths:
    """Create a fresh run directory + full subtree; return its :class:`RunPaths`.

    Collision-safe: if the chosen name already exists, a ``-NN`` suffix is added
    so a second call within the same second never clobbers the first.
    """
    base = Path(base)
    name = run_name or utc_run_id()
    root = base / name
    if root.exists():
        n = 1
        while (base / f"{name}-{n:02d}").exists():
            n += 1
        root = base / f"{name}-{n:02d}"
    # exist_ok=False is intentional: root is guaranteed fresh by the check above,
    # so a race here surfaces loudly rather than silently reusing a directory.
    root.mkdir(parents=True, exist_ok=False)
    for subdir in RUN_SUBDIRS:
        (root / subdir).mkdir(exist_ok=False)
    return RunPaths(root=root)
