"""SIFTMesh CLI entry point (Typer 0.26.x).

`app` is the console-script target referenced by `[project.scripts]`:
    siftmesh = "siftmesh_core.cli:app"
Typer instances are directly callable, so no `main()` wrapper is required.

`init-case` is real Epic B evidence-vault behavior. The remaining investigation
commands keep the frozen CLI surface until their epics wire the real workflows.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Annotated, cast

import typer

from siftmesh_core import __version__
from siftmesh_core.doctor import run_doctor
from siftmesh_core.evidence.path_policy import PathPolicyViolation
from siftmesh_core.evidence.vault import EvidenceModifiedError
from siftmesh_core.evidence.vault import init_case as vault_init_case
from siftmesh_core.intake.brief import BriefIntakeError
from siftmesh_core.mcp_gateway.backends import BackendUnavailableError
from siftmesh_core.protocol_sift import PROTOCOL_SIFT_SKILLS, detect_protocol_sift

if TYPE_CHECKING:
    from siftmesh_core.run_dir import RunPaths
    from siftmesh_core.schemas.run import GateStatus, RunMode, RunState

# Root app: no args -> show help (Click "no command" exits with code 2).
app = typer.Typer(
    no_args_is_help=True,
    help="SIFTMesh: CLI-first, evidence-safe DFIR investigation controller.",
)

# Debug sub-typers (command groups).
tasks_app = typer.Typer(no_args_is_help=True, help="Task inspection commands.")
claims_app = typer.Typer(no_args_is_help=True, help="Claim ledger inspection commands.")
audit_app = typer.Typer(no_args_is_help=True, help="Audit log inspection commands.")
app.add_typer(tasks_app, name="tasks")
app.add_typer(claims_app, name="claims")
app.add_typer(audit_app, name="audit")

# Protocol SIFT inspection (env-only). Protocol SIFT is a ~/.claude config/skill
# layer, NOT an MCP server (PLAN/09) - SIFTMesh inspects and governs it.
protocol_sift_app = typer.Typer(
    no_args_is_help=True, help="Inspect & govern the Protocol SIFT (~/.claude) layer."
)
skills_app = typer.Typer(no_args_is_help=True, help="Protocol SIFT skill inspection.")
protocol_sift_app.add_typer(skills_app, name="skills")
app.add_typer(protocol_sift_app, name="protocol-sift")

# Agent-neutral onboarding/inspection (Epic Q): which coding agents are installed + usable.
agents_app = typer.Typer(no_args_is_help=True, help="Inspect & onboard coding agent connectors.")
app.add_typer(agents_app, name="agents")

# Forensic evidence-access specialists (disk image / memory / archive). `run --auto` does these
# automatically; the group is for manual/staged use. Old top-level names kept as hidden aliases.
evidence_app = typer.Typer(no_args_is_help=True, help="Manual evidence access (disk/mem/archive).")
app.add_typer(evidence_app, name="evidence")


def _version_callback(value: bool) -> None:
    # Eager: fires during arg parsing, before subcommand dispatch and before the
    # callback body. typer.Exit() defaults to code 0.
    if value:
        print(f"siftmesh {__version__}")
        raise typer.Exit(code=0)


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = None,
    stream: Annotated[
        bool | None,
        typer.Option(
            "--stream/--no-stream",
            help="Real-time tagged log stream to stderr (default: on when attached to a terminal).",
        ),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress the real-time log stream (= --no-stream)."),
    ] = False,
) -> None:
    """App-level options. `siftmesh --version` works with no subcommand."""
    # Load provider credentials (LiteLLM judge keys) from ~/.config/siftmesh/.env into the
    # environment before any command runs. A real shell export wins (override=False). Provider
    # creds only - never SIFTMESH_* settings (those stay in TOML/env per config.py precedence).
    from siftmesh_core.secrets_env import load_secrets_into_env

    load_secrets_into_env()

    # Real-time log stream: register a stderr streamer for long-running commands so any run
    # shows tagged, per-task, %-complete logs by default. TTY-gated, so CliRunner/pipes (and
    # the golden recorder) get nothing; the TUI/mcp-serve are excluded (they own their I/O).
    from siftmesh_core.observability import install_stream_if_enabled

    install_stream_if_enabled(ctx.invoked_subcommand, stream=stream, quiet=quiet)


@app.command("init-case")
def init_case(
    case_dir: str,
    evidence: Annotated[str, typer.Option(help="Path to read-only evidence.")],
    run_name: Annotated[str | None, typer.Option(help="Override the generated RUN-* id.")] = None,
    brief: Annotated[
        str | None,
        typer.Option(
            "--brief",
            help="Incident briefing (.pptx/.docx/.pdf/.txt/.md) - the TRUSTED objective, "
            "not evidence. Can be paired with --objective for extra steering.",
        ),
    ] = None,
    objective: Annotated[
        str | None,
        typer.Option(
            "--objective",
            help='Inline TRUSTED objective/steering text (no file needed) - e.g. --objective "was '
            'host X compromised?". COMBINES with --brief when both are given (more context = '
            "better).",
        ),
    ] = None,
    verify_after: Annotated[
        bool,
        typer.Option(
            "--verify-after",
            help="Re-hash originals at end of run (off by default; costly for huge data).",
        ),
    ] = False,
    resume: Annotated[
        bool,
        typer.Option(
            "--resume",
            help="Resume an interrupted ingest: reuse checkpointed hashes for "
            "unchanged files instead of re-hashing 100+GB from scratch.",
        ),
    ] = False,
) -> None:
    """Hash + seal evidence into a new run dir (manifest, custody, policy)."""
    try:
        run = vault_init_case(
            case_dir,
            evidence,
            run_name=run_name,
            verify_after=verify_after,
            show_progress=True,
            brief_path=brief,
            objective_text=objective,
            resume=resume,
        )
    except (
        FileNotFoundError,
        NotADirectoryError,
        PathPolicyViolation,
        EvidenceModifiedError,
        BriefIntakeError,
    ) as exc:
        typer.echo(f"init-case failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"init-case complete: {run.root}")
    typer.echo(f"  run id   : {run.run_id}")
    typer.echo(f"  manifest : {run.evidence_manifest}")
    typer.echo(f"  custody  : {run.custody_log}")
    if brief is not None or objective is not None:
        typer.echo(f"  brief    : {run.incident_brief} (TRUSTED objective)")


@app.command()
def plan(
    run_dir: str,
    review_only: Annotated[
        bool,
        typer.Option("--review-only", help="Emit recommendations only; no dispatch."),
    ] = False,
) -> None:
    """Generate the deterministic investigation plan + task contracts for a run."""
    from pydantic import ValidationError

    from siftmesh_core.config import load_settings
    from siftmesh_core.orchestrator.planner import generate_plan
    from siftmesh_core.run_dir import RunPaths

    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        run = RunPaths(root=root)
        if not run.evidence_manifest.is_file():
            raise FileNotFoundError(f"no evidence manifest at {run.evidence_manifest}")
        result = generate_plan(run, settings=load_settings(), review_only=review_only)
    except (
        FileNotFoundError,
        NotADirectoryError,
        PathPolicyViolation,
        ValidationError,
    ) as exc:
        typer.echo(f"plan failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"plan complete: {result.run.root}")
    typer.echo(f"  context files : {len(result.context_files)}")
    typer.echo(f"  task contracts: {len(result.task_files)}")
    typer.echo(f"  plan          : {result.run.investigation_plan}")
    if result.review_only:
        typer.echo("  mode          : review-only (recommendations only, no dispatch)")
    elif not result.task_files:
        typer.echo("  note          : nothing to plan (manifest has no actionable artifacts)")


@app.command()
def dispatch(
    run_dir: str,
    task: Annotated[str | None, typer.Option(help="Dispatch only this TASK-ID.")] = None,
    agent_profile: Annotated[
        str | None, typer.Option("--agent-profile", help="Override the contract's agent profile.")
    ] = None,
    evidence: Annotated[
        str | None, typer.Option(help="Evidence root (else recovered from readonly_mounts.json).")
    ] = None,
) -> None:
    """Execute the run's task contracts via their adapters; write results + audit."""
    from pydantic import ValidationError

    from siftmesh_core.config import load_settings
    from siftmesh_core.mcp_gateway.backends import BackendUnavailableError
    from siftmesh_core.orchestrator.scheduler import CapError, PolicyError, dispatch_run
    from siftmesh_core.run_dir import RunPaths

    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        run = RunPaths(root=root)
        refs = dispatch_run(
            run,
            settings=load_settings(),
            evidence_override=evidence,
            task_id=task,
            agent_profile=agent_profile,
        )
    except (
        FileNotFoundError,
        NotADirectoryError,
        PathPolicyViolation,
        ValidationError,
        BackendUnavailableError,
        PolicyError,
        CapError,
    ) as exc:
        typer.echo(f"dispatch failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"dispatch complete: {len(refs)} task(s)")
    for ref in refs:
        typer.echo(f"  {ref.task_id}: {ref.status} -> {ref.result_path}")


@app.command()
def collect(
    run_dir: str,
    task: Annotated[str | None, typer.Option(help="Collect only this TASK-ID.")] = None,
) -> None:
    """Validate task result envelopes; report missing/malformed without crashing."""
    from pydantic import ValidationError

    from siftmesh_core.orchestrator.scheduler import collect_run
    from siftmesh_core.run_dir import RunPaths

    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        report = collect_run(RunPaths(root=root), task_id=task)
    except (FileNotFoundError, NotADirectoryError, PathPolicyViolation, ValidationError) as exc:
        typer.echo(f"collect failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    for row in report.rows:
        typer.echo(f"  {row.task_id}: {row.status} ({len(row.claim_ids)} claim(s))")
    if report.missing:
        typer.echo(f"  missing: {', '.join(report.missing)}", err=True)
    if report.malformed:
        typer.echo(f"  malformed: {', '.join(report.malformed)}", err=True)


@app.command()
def critique(
    run_dir: str,
    evidence: Annotated[
        str | None, typer.Option(help="Evidence root (else recovered from readonly_mounts.json).")
    ] = None,
    followups: Annotated[
        bool,
        typer.Option(
            "--followups/--no-followups",
            help="Generate follow-up tasks for unexamined manifest artifacts (G9).",
        ),
    ] = True,
) -> None:
    """Validate collected claims; emit one critic verdict per task; write ledgers."""
    from pydantic import ValidationError

    from siftmesh_core.config import load_settings
    from siftmesh_core.ledgers.claim_ledger import read_claims, read_unsupported_claims
    from siftmesh_core.ledgers.followups import read_followups
    from siftmesh_core.ledgers.jsonl_ledger import LedgerCorruptionError
    from siftmesh_core.orchestrator.critic import critique_run
    from siftmesh_core.run_dir import RunPaths

    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        run = RunPaths(root=root)
        verdicts = critique_run(
            run, settings=load_settings(), evidence_root=evidence, generate_followups=followups
        )
        followup_count = len(read_followups(run.root))
        promoted = len(read_claims(run.root))
        unsupported = len(read_unsupported_claims(run.root))
    except (
        FileNotFoundError,
        NotADirectoryError,
        PathPolicyViolation,
        ValidationError,
        LedgerCorruptionError,
    ) as exc:
        typer.echo(f"critique failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"critique complete: {len(verdicts)} verdict(s)")
    for v in verdicts:
        # The count is per-task FLAGGED claims (downgraded/unsupported/rejected/human) - not the
        # total; an "accepted (0 flagged)" task still contributed anchored claims to the ledger.
        typer.echo(f"  {v.task_id}: {v.verdict} ({len(v.affected_claim_ids)} flagged)")
    typer.echo(
        f"  claims: {promoted} promoted to findings ledger; {unsupported} unsupported "
        f"(appendix-only, never facts)"
    )
    if followup_count:
        typer.echo(f"  follow-ups : {followup_count} gap(s) raised (audit/followups.jsonl)")


@app.command()
def report(
    run_dir: str,
    tolerant: Annotated[
        bool, typer.Option("--tolerant", help="Tolerate a truncated trailing ledger line.")
    ] = False,
    expected: Annotated[
        str | None, typer.Option("--expected", help="expected_findings.md → accuracy diff mode.")
    ] = None,
) -> None:
    """Render the deterministic evidence-backed reports + replay.html for a run."""
    from pathlib import Path

    from pydantic import ValidationError

    from siftmesh_core.evidence.path_policy import PathPolicyViolation
    from siftmesh_core.ledgers.jsonl_ledger import LedgerCorruptionError
    from siftmesh_core.reports import ReportLoadError, generate_all_reports
    from siftmesh_core.run_dir import RunPaths

    root = Path(run_dir)
    if not root.is_dir():
        typer.echo(f"report failed: not a run directory: {run_dir}", err=True)
        raise typer.Exit(code=1)
    try:
        run = RunPaths(root=root)
        paths = generate_all_reports(run, strict=not tolerant, expected_findings=expected)
    except (
        FileNotFoundError,
        NotADirectoryError,
        PathPolicyViolation,
        ValidationError,
        LedgerCorruptionError,
        ReportLoadError,
    ) as exc:
        typer.echo(f"report failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"report: {len(paths)} artifact(s) written")
    for p in paths:
        typer.echo(f"  {p}")


@app.command()
def replay(
    run_dir: str,
    html: Annotated[bool, typer.Option("--html", help="Also write reports/replay.html.")] = False,
    tolerant: Annotated[
        bool, typer.Option("--tolerant", help="Tolerate a truncated trailing ledger line.")
    ] = False,
) -> None:
    """Replay the audit trail (chronological events) as a deterministic text timeline."""
    from pathlib import Path

    from pydantic import ValidationError

    from siftmesh_core.evidence.path_policy import PathPolicyViolation
    from siftmesh_core.ledgers.jsonl_ledger import LedgerCorruptionError
    from siftmesh_core.reports import (
        ReportLoadError,
        generate_replay_html,
        load_report_view,
        render_text_replay,
    )
    from siftmesh_core.run_dir import RunPaths

    root = Path(run_dir)
    if not root.is_dir():
        typer.echo(f"replay failed: not a run directory: {run_dir}", err=True)
        raise typer.Exit(code=1)
    run = RunPaths(root=root)
    try:
        view = load_report_view(run, strict=not tolerant)
        typer.echo(render_text_replay(view), nl=False)
        if html:
            path = generate_replay_html(run, view=view)
            typer.echo(f"replay.html: {path}")
    except (
        FileNotFoundError,
        NotADirectoryError,
        PathPolicyViolation,
        ValidationError,
        LedgerCorruptionError,
        ReportLoadError,
    ) as exc:
        typer.echo(f"replay failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


_RUN_MODES = ("manual", "review_only", "auto_human_loop", "auto")


def _resolve_mode(
    mode: str, *, review_only: bool, auto_human_loop: bool, auto: bool
) -> RunMode | None:
    """Resolve the engine mode from the CLAUDE §4 flags (flags win over --mode)."""
    if auto:
        return "auto"
    if auto_human_loop:
        return "auto_human_loop"
    if review_only:
        return "review_only"
    norm = mode.replace("-", "_")
    return cast("RunMode", norm) if norm in _RUN_MODES else None


# Agent-neutral selection (Epic Q): friendly --agent name → registered profile_id.
_AGENT_ALIASES = {
    "claude": "claude_headless",
    "opencode": "opencode_headless",
    "gemini": "gemini_headless",
    "codex": "codex_headless",
    "deterministic": "deterministic_executor",
    "floor": "deterministic_executor",
}


def _agent_overrides(agent: str | None) -> dict[str, object]:
    """Translate a friendly --agent choice into settings overrides (opt into the live chain).

    The chosen agent is put first; the ONLY fallback is the deterministic floor - never another live
    agent (an operator who explicitly chose the sandboxed Claude must not be silently downgraded to
    a different live agent with a different safety posture). ``deterministic`` pins the floor. An
    unknown value is a hard error (no silent passthrough that could dispatch the wrong agent).
    """
    if not agent:
        return {}
    from siftmesh_core.adapters.profiles import load_profiles

    profile = _AGENT_ALIASES.get(agent, agent)  # accept a friendly alias or a full profile_id
    if profile not in load_profiles():
        valid = ", ".join(sorted(_AGENT_ALIASES))
        raise typer.BadParameter(
            f"unknown agent '{agent}'. Choose one of: {valid} (or a profile_id). "
            "See `siftmesh agents list`."
        )
    if profile == "deterministic_executor":
        return {"executor_selection": "deterministic"}
    return {
        "executor_selection": "auto",
        "agent_preference": [profile, "deterministic_executor"],
    }


def _judge_overrides(judge: str | None) -> dict[str, object]:
    """Translate a friendly --judge choice into a settings override for the advisory Tier-2 judge.

    Accepts a bare agent (``claude|gemini|codex|opencode`` → ``cli:<agent>``), an explicit
    ``cli:<agent>`` / ``litellm:<model>`` string, or ``deterministic``/``off`` (disable the judge).
    Selecting a judge also enables the (off-by-default) Tier-2 layer for that run.
    """
    if not judge:
        return {}
    if judge in ("off", "none", "deterministic"):
        return {"llm_critic_enabled": False}
    backend = judge if ":" in judge else f"cli:{judge}"
    return {"judge": backend, "llm_critic_enabled": True}


def _parse_model_overrides(pairs: list[str] | None) -> dict[str, str]:
    """Parse repeated ``--model agent=model`` into ``{profile_id: model}`` (friendly name → id)."""
    if not pairs:
        return {}
    out: dict[str, str] = {}
    for item in pairs:
        if "=" not in item:
            raise typer.BadParameter(f"--model must be agent=model (got {item!r})")
        name, model = (s.strip() for s in item.split("=", 1))
        if not model:
            raise typer.BadParameter(f"--model {name}= needs a model id")
        profile = _AGENT_ALIASES.get(name, name)  # claude→claude_headless, or a raw profile_id
        out[profile] = model
    return out


def _claude_available(settings: object) -> bool:
    """Best-effort check of whether the live Claude agent could run here (CLI + auth present)."""
    from siftmesh_core.adapters.claude_adapter import ClaudeHeadlessAdapter

    try:
        return ClaudeHeadlessAdapter(settings=settings).available()  # type: ignore[arg-type]
    except Exception:  # never let a discoverability hint break a run
        return False


def _hint_live_agent(settings: object) -> None:
    """Loud opt-in: when no --agent was chosen but claude is available, suggest the live path."""
    if _claude_available(settings):
        typer.echo(
            "hint: the Claude live agent is available - add `--agent claude` for a live, "
            "objective-driven investigation (this run uses the deterministic floor).",
            err=True,
        )


def _space_preflight_ok(case_dir: str, evidence: str) -> bool:
    """Estimate derived-data size vs free disk; on shortfall print a portion plan and return False.

    Never blocks on its own failure (a corrupt archive → warn + proceed). Returns True to proceed.
    """
    from siftmesh_core.evidence.space import estimate_required, human_bytes, partition_plan

    try:
        est = estimate_required(evidence, run_location=case_dir)
    except (OSError, ValueError) as exc:
        typer.echo(f"  space  : estimate skipped ({exc}); proceeding", err=True)
        return True
    if est.fits:
        tag = " (some estimated)" if est.any_estimated else ""
        typer.echo(
            f"  space  : ~{human_bytes(est.needed_bytes)} derived needed{tag}; "
            f"{human_bytes(est.free_bytes)} free - OK"
        )
        return True

    typer.echo("run refused: not enough free disk for the derived data this evidence will produce.")
    typer.echo(f"  needed (incl. margin): ~{human_bytes(est.needed_bytes)}")
    typer.echo(f"  free                 : {human_bytes(est.free_bytes)}")
    for it in est.items:
        if it.derived_bytes:
            kind = "exact" if it.exact else "estimated"
            typer.echo(f"    - {it.path}: ~{human_bytes(it.derived_bytes)} derived ({kind})")
    existing = sorted(Path(case_dir).glob("case_runs/RUN-*"))
    if existing:
        typer.echo("  reclaim space by deleting old runs (or `siftmesh prune <run>`):")
        for r in existing:
            typer.echo(f"    {r}")
    budget = int(est.free_bytes / 1.2)
    portions = partition_plan([i for i in est.items if i.derived_bytes], budget)
    if len(portions) > 1:
        typer.echo(f"  or split into {len(portions)} portions that each fit, then merge:")
        for n, portion in enumerate(portions, 1):
            files = " ".join(it.path for it in portion)
            typer.echo(
                f"    portion {n}: run these in ev_p{n}/ then `siftmesh prune <run>` - {files}"
            )
        typer.echo("    finally: siftmesh merge ./case_merged --run <RUN_1> --run <RUN_2> …")
    typer.echo("  (or re-run with --force to proceed anyway)")
    return False


def _echo_run_state(run_paths: RunPaths, state: RunState) -> None:
    typer.echo(f"run: {run_paths.root}")
    typer.echo(f"  run id : {run_paths.run_id}")
    typer.echo(
        f"  state  : {state.state} "
        f"(mode={state.mode}, iteration={state.iteration}/{state.max_iterations})"
    )
    if state.state == "done":
        typer.echo("  status : complete")
        typer.echo("  report : reports/ written (auto modes) - or run `siftmesh report <run>`")
    elif state.terminal:
        typer.echo(f"  status : halted ({state.blocked_gate or 'rejected'})")
    elif state.blocked_gate:
        typer.echo(
            f"  gate   : awaiting approval -> "
            f"siftmesh approve {run_paths.root} --gate {state.blocked_gate}"
        )
    else:
        typer.echo(f"  status : paused -> siftmesh resume {run_paths.root}")


@app.command()
def run(
    case_dir: str,
    evidence: Annotated[str, typer.Option(help="Path to read-only evidence.")],
    mode: Annotated[
        str, typer.Option(help="manual | review-only | auto-human-loop | auto")
    ] = "manual",
    review_only: Annotated[
        bool, typer.Option("--review-only", help="Plan + recommendations only; no dispatch.")
    ] = False,
    auto_human_loop: Annotated[
        bool, typer.Option("--auto-human-loop", help="Run until a meaningful approval gate.")
    ] = False,
    auto: Annotated[
        bool, typer.Option("--auto", help="Run to completion; enforce caps; no gates.")
    ] = False,
    max_iterations: Annotated[
        int | None, typer.Option("--max-iterations", help="Override the self-correction cap.")
    ] = None,
    max_agent_tasks: Annotated[
        int | None,
        typer.Option(
            "--max-agent-tasks",
            help="Raise the dispatchable-task cap (real disk images yield 200+ derived tasks).",
        ),
    ] = None,
    agent: Annotated[
        str | None,
        typer.Option(
            "--agent",
            help="Opt into a live agent (the EXECUTOR): claude | gemini | codex | opencode | "
            "deterministic (see `siftmesh agents list`).",
        ),
    ] = None,
    judge: Annotated[
        str | None,
        typer.Option(
            "--judge",
            help="Advisory Tier-2 JUDGE backend: claude|gemini|codex|opencode (their CLI), or "
            "litellm:<model> (e.g. litellm:gemini/gemini-2.5-pro), or off. Enables the judge for "
            "this run; fails soft if unavailable.",
        ),
    ] = None,
    model: Annotated[
        list[str] | None,
        typer.Option(
            "--model",
            help="Per-provider model override (repeatable): --model gemini=gemini-3-pro "
            "--model codex=gpt-5.5. Overrides the profile default for this run.",
        ),
    ] = None,
    brief: Annotated[
        str | None,
        typer.Option(
            "--brief",
            help="Incident briefing (.pptx/.docx/.pdf/.txt/.md) - the TRUSTED objective the "
            "agent investigates toward. Can be paired with --objective for extra steering.",
        ),
    ] = None,
    objective: Annotated[
        str | None,
        typer.Option(
            "--objective",
            help='Inline TRUSTED objective/steering text (no file needed) - e.g. --objective "was '
            'host X compromised?". COMBINES with --brief when both are given (more context = '
            "better).",
        ),
    ] = None,
    all_live: Annotated[
        bool,
        typer.Option(
            "--all-live",
            help="Also run heavy tool-bound tasks (disk-image extraction, memory triage) on the "
            "live agent. Default tiers them to the deterministic floor (the tool does the work).",
        ),
    ] = False,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Skip the pre-flight free-disk check (which estimates derived-data size from the "
            "evidence and refuses if it won't fit).",
        ),
    ] = False,
    parallel: Annotated[
        bool | None,
        typer.Option(
            "--parallel/--no-parallel",
            help="Dispatch tasks concurrently (up to caps.max_parallel_tasks) - deterministic "
            "(byte-identical to sequential). Default: AUTO - ON when a live --agent executor is "
            "used (slow live agents shouldn't run serially), OFF for the deterministic floor. "
            "--no-parallel forces sequential.",
        ),
    ] = None,
) -> None:
    """Init → plan → dispatch → collect → critique → decide → report, via one engine."""
    from pydantic import ValidationError

    from siftmesh_core.config import load_settings
    from siftmesh_core.orchestrator.run_state_store import write_run_state
    from siftmesh_core.orchestrator.scheduler import CapError, PolicyError
    from siftmesh_core.orchestrator.state_machine import IllegalTransitionError
    from siftmesh_core.orchestrator.workflow_runner import run_engine
    from siftmesh_core.schemas.run import RunState

    resolved = _resolve_mode(
        mode, review_only=review_only, auto_human_loop=auto_human_loop, auto=auto
    )
    if resolved is None:
        typer.echo(f"run failed: unknown mode {mode!r} (use {', '.join(_RUN_MODES)})", err=True)
        raise typer.Exit(code=1)
    settings = load_settings(**{**_agent_overrides(agent), **_judge_overrides(judge)})
    model_over = _parse_model_overrides(model)
    if model_over:  # merge per-run --model over any persisted agent_models (run wins)
        settings = settings.model_copy(
            update={"agent_models": {**settings.agent_models, **model_over}}
        )
    if max_agent_tasks is not None:
        # Caps stay enforced (CLAUDE §11) - the operator just sets the ceiling explicitly.
        settings = settings.model_copy(
            update={"caps": settings.caps.model_copy(update={"max_agent_tasks": max_agent_tasks})}
        )
    if all_live:
        settings = settings.model_copy(update={"live_extraction": True})
    # Parallel dispatch is AUTO: default ON for a live AI executor (sequential live agents are slow
    # and brittle over many tasks), OFF for the deterministic floor (keeps the byte-stable default).
    # Explicit --parallel / --no-parallel win; the floor otherwise keeps its config default.
    live_executor = agent is not None and agent != "deterministic"
    if parallel is not None:
        settings = settings.model_copy(update={"parallel_dispatch": parallel})
    elif live_executor:
        settings = settings.model_copy(update={"parallel_dispatch": True})
        typer.echo(
            "note: live agent - parallel dispatch is ON (use --no-parallel for sequential)",
            err=True,
        )
    if agent is None:
        _hint_live_agent(settings)  # loud opt-in: surface the live agent when it's available
    if not force and not _space_preflight_ok(case_dir, evidence):
        raise typer.Exit(code=1)  # the gate already printed the needed/free + portion plan
    try:
        run_paths = vault_init_case(
            case_dir, evidence, show_progress=True, brief_path=brief, objective_text=objective
        )
        state = RunState(
            run_id=run_paths.run_id,
            mode=resolved,
            max_iterations=max_iterations or settings.caps.max_iterations,
        )
        write_run_state(run_paths, state)
        state = run_engine(
            run_paths,
            settings=settings,
            evidence_root=evidence,
            single_step=(resolved == "manual"),
        )
    except (
        FileNotFoundError,
        NotADirectoryError,
        PathPolicyViolation,
        EvidenceModifiedError,
        BackendUnavailableError,
        BriefIntakeError,
        ValidationError,
        PolicyError,
        CapError,
        IllegalTransitionError,
    ) as exc:
        typer.echo(f"run failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    _echo_run_state(run_paths, state)


@app.command()
def resume(run_dir: str) -> None:
    """Resume an interrupted run from its persisted RunState."""
    from pydantic import ValidationError

    from siftmesh_core.config import load_settings
    from siftmesh_core.orchestrator.run_state_store import read_run_state
    from siftmesh_core.orchestrator.scheduler import CapError, PolicyError
    from siftmesh_core.orchestrator.state_machine import IllegalTransitionError
    from siftmesh_core.orchestrator.workflow_runner import run_engine
    from siftmesh_core.run_dir import RunPaths

    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        run_paths = RunPaths(root=root)
        state = read_run_state(run_paths)
        state = run_engine(
            run_paths, settings=load_settings(), single_step=(state.mode == "manual")
        )
    except (
        FileNotFoundError,
        NotADirectoryError,
        PathPolicyViolation,
        BackendUnavailableError,
        ValidationError,
        PolicyError,
        CapError,
        IllegalTransitionError,
    ) as exc:
        typer.echo(f"resume failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    _echo_run_state(run_paths, state)


@app.command()
def status(run_dir: str) -> None:
    """Show a run's state-machine status (state, mode, gates, caps, per-task attempts)."""
    from pydantic import ValidationError

    from siftmesh_core.orchestrator.run_state_store import read_run_state
    from siftmesh_core.run_dir import RunPaths

    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        state = read_run_state(RunPaths(root=root))
    except (FileNotFoundError, NotADirectoryError, ValidationError) as exc:
        typer.echo(f"status failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"status: {root}")
    typer.echo(f"  state     : {state.state}{' (terminal)' if state.terminal else ''}")
    typer.echo(f"  mode      : {state.mode}")
    typer.echo(f"  iteration : {state.iteration}/{state.max_iterations}")
    typer.echo(f"  agent tasks completed: {state.agent_tasks_completed}")
    if state.blocked_gate:
        typer.echo(f"  blocked on gate: {state.blocked_gate}")
    if state.gates:
        typer.echo(f"  gates     : {', '.join(f'{g}={s}' for g, s in state.gates.items())}")
    for task_id, per_task in sorted(state.per_task.items()):
        typer.echo(
            f"  {task_id}: attempt {per_task.attempt}/{per_task.max_attempts} ({per_task.status})"
        )


@app.command("mcp-serve")
def mcp_serve() -> None:
    """Launch the typed forensic MCP gateway over stdio (the allowlisted forensic tools)."""
    from siftmesh_core.mcp_gateway.server import run_server

    run_server()


@evidence_app.command("extract")
def extract_artifacts(
    run_dir: str,
    evidence: Annotated[str, typer.Option(help="Evidence root (the originals dir).")],
    image: Annotated[
        str, typer.Option(help="Disk image artifact, evidence-relative (e.g. rocba-cdrive.e01).")
    ],
    keys: Annotated[
        list[str] | None,
        typer.Option(help="Artifact keys to extract (repeatable); default = all curated."),
    ] = None,
) -> None:
    """Extract Windows artifacts from a disk image into the run dir (Sleuthkit; audited)."""
    from siftmesh_core.mcp_gateway.tools.image_tools import extract_artifacts_from_image

    try:
        result = extract_artifacts_from_image(
            run_dir, image_artifact=image, evidence_root=evidence, keys=keys
        )
    except (FileNotFoundError, ValueError, PathPolicyViolation, BackendUnavailableError) as exc:
        typer.echo(f"extract-artifacts failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"extract-artifacts: status={result.status} extracted={result.extracted_count} "
        f"failed={result.failed_count} (tool_call {result.tool_call_id}, "
        f"offset {result.partition_offset})"
    )


@evidence_app.command("memory")
def analyze_memory_cmd(
    run_dir: str,
    evidence: Annotated[str, typer.Option(help="Root dir containing the memory image.")],
    memory: Annotated[str, typer.Option(help="Memory image, relative to --evidence.")],
    plugins: Annotated[
        list[str] | None, typer.Option(help="vol plugins (repeatable); default = triage set.")
    ] = None,
    symbol_dirs: Annotated[
        str | None, typer.Option(help="Writable Volatility 3 symbol cache dir.")
    ] = None,
) -> None:
    """Triage a memory image with Volatility 3 (subprocess; audited)."""
    from siftmesh_core.config import load_settings
    from siftmesh_core.mcp_gateway.tools.memory_tools import analyze_memory

    # Default the symbol cache from settings (created on use) so no manual export is needed.
    symbols = symbol_dirs or load_settings().vol_symbol_dirs
    try:
        result = analyze_memory(
            run_dir,
            memory_artifact=memory,
            evidence_root=evidence,
            plugins=plugins,
            symbol_dirs=symbols,
        )
    except (FileNotFoundError, ValueError, PathPolicyViolation, BackendUnavailableError) as exc:
        typer.echo(f"analyze-memory failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"analyze-memory: status={result.status} procs={result.process_count} "
        f"suspicious={len(result.suspicious)} (tool_call {result.tool_call_id})"
    )


@evidence_app.command("decompress")
def decompress(
    run_dir: str,
    archive: Annotated[
        str,
        typer.Option(help="Compressed memory capture, evidence-relative (e.g. Rocba-Memory.zip)."),
    ],
    evidence: Annotated[
        str | None, typer.Option(help="Evidence root (else recovered from readonly_mounts.json).")
    ] = None,
) -> None:
    """Decompress a memory archive (zip/7z) into evidence/extracted/ (derived; audited)."""
    from siftmesh_core.evidence.decompress import decompress_archive
    from siftmesh_core.orchestrator.scheduler import recover_evidence_root
    from siftmesh_core.run_dir import RunPaths

    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        run = RunPaths(root=root)
        evidence_root: Path = Path(evidence) if evidence else recover_evidence_root(run)
        outcome = decompress_archive(run, archive=archive, evidence_root=evidence_root)
    except (
        FileNotFoundError,
        NotADirectoryError,
        ValueError,
        PathPolicyViolation,
        BackendUnavailableError,
        RuntimeError,
    ) as exc:
        typer.echo(f"decompress failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"decompress complete: {outcome.derived_path}")
    typer.echo(f"  format : {outcome.image_format}")
    typer.echo(f"  size   : {outcome.size_bytes} bytes")
    typer.echo(f"  sha256 : {outcome.sha256}")
    typer.echo(f"  derived: {outcome.decomp_id} (custody: {run.custody_log})")
    typer.echo(
        f"  next   : siftmesh analyze-memory {run.root} "
        f"--evidence {run.root} --memory {outcome.derived_path}"
    )


@evidence_app.command("ingest")
def ingest_derived_cmd(
    run_dir: str,
    evidence: Annotated[
        str | None, typer.Option(help="Evidence root (else recovered from readonly_mounts.json).")
    ] = None,
) -> None:
    """Make extracted/decompressed derived artifacts plannable - one derived task each (hth.2)."""
    from pydantic import ValidationError

    from siftmesh_core.orchestrator.critic import ingest_derived
    from siftmesh_core.run_dir import RunPaths

    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        run = RunPaths(root=root)
        created = ingest_derived(run, evidence_root=evidence)
    except (FileNotFoundError, NotADirectoryError, PathPolicyViolation, ValidationError) as exc:
        typer.echo(f"ingest-derived failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"ingest-derived: {len(created)} derived task(s) created")
    for path in created:
        typer.echo(f"  {path.stem}")
    if created:
        typer.echo(f"  next: siftmesh dispatch {run.root}")


# Deprecated top-level aliases for the forensic specialists - now under `siftmesh evidence …`.
# Same functions, hidden from --help, kept so existing scripts / the RUNBOOK keep working.
app.command("extract-artifacts", hidden=True)(extract_artifacts)
app.command("analyze-memory", hidden=True)(analyze_memory_cmd)
app.command("decompress", hidden=True)(decompress)
app.command("ingest-derived", hidden=True)(ingest_derived_cmd)


@app.command()
def prune(
    run_dir: str,
    force: Annotated[
        bool, typer.Option("--force", help="Prune even if the run is not terminal.")
    ] = False,
) -> None:
    """Reclaim a completed run's bulky derived data (evidence/extracted/); keep all ledgers."""
    from siftmesh_core.evidence.prune import PrunePolicyError, prune_run
    from siftmesh_core.evidence.space import human_bytes
    from siftmesh_core.run_dir import RunPaths

    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        outcome = prune_run(RunPaths(root=root), force=force)
    except (FileNotFoundError, NotADirectoryError, PathPolicyViolation, PrunePolicyError) as exc:
        typer.echo(f"prune failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"prune complete: removed {outcome.files_removed} derived file(s), "
        f"freed {human_bytes(outcome.bytes_freed)} (ledgers + reports kept)"
    )


@app.command()
def merge(
    case_dir: str,
    run: Annotated[
        list[str] | None,
        typer.Option("--run", help="A source RUN directory (repeatable; at least two)."),
    ] = None,
    agent: Annotated[
        str | None,
        typer.Option(
            "--agent",
            help="claude → add an ADVISORY cross-run synthesis section (validated; promotes "
            "nothing). Omit for the deterministic merge only.",
        ),
    ] = None,
) -> None:
    """Merge ≥2 completed runs into one combined, provenance-tracked report (deterministic core)."""
    from siftmesh_core.config import load_settings
    from siftmesh_core.reports import ReportLoadError, merge_runs

    use_agent = agent is not None and agent not in ("deterministic", "floor")
    try:
        merge_run = merge_runs(
            case_dir, list(run or []), settings=load_settings(), agent_synthesis=use_agent
        )
    except (
        FileNotFoundError,
        NotADirectoryError,
        ValueError,
        PathPolicyViolation,
        ReportLoadError,
    ) as exc:
        typer.echo(f"merge failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"merge complete: {merge_run.root}")
    typer.echo(f"  report : {merge_run.reports / 'final_report.md'}")


@app.command()
def doctor(
    protocol_sift: Annotated[
        bool,
        typer.Option("--protocol-sift", help="Also detect the ~/.claude Protocol SIFT layer."),
    ] = False,
    agents: Annotated[
        bool,
        typer.Option(
            "--agents",
            help="Also probe the coding agents (claude/gemini/codex/opencode): "
            "which are installed + authenticated + sandboxed, and which is the live default.",
        ),
    ] = False,
    setup: Annotated[
        bool,
        typer.Option(
            "--setup",
            help="Install everything (uv sync --all-extras) + create the Volatility symbol cache, "
            "then verify. One-command setup.",
        ),
    ] = False,
) -> None:
    """Verify host + tool backends (fails closed on missing deps); --setup also installs them."""
    raise typer.Exit(code=run_doctor(protocol_sift=protocol_sift, agents=agents, setup=setup))


@app.command()
def setup(
    no_tui: Annotated[
        bool,
        typer.Option(
            "--no-tui", help="Headless: install + auto-select ready agents, no TUI screen."
        ),
    ] = False,
    scope: Annotated[
        str,
        typer.Option("--scope", help="Persist the selection to 'global' (~/.config) or 'project'."),
    ] = "global",
    yes: Annotated[
        bool, typer.Option("--yes", "-y", help="Non-interactive: accept the ready agents.")
    ] = False,
    judge: Annotated[
        str | None,
        typer.Option(
            "--judge",
            help="Also set the advisory Tier-2 judge: claude|gemini|codex|opencode|litellm:<model>"
            "|off (headless persists it; in the TUI it pre-selects the judge picker).",
        ),
    ] = None,
    model: Annotated[
        list[str] | None,
        typer.Option(
            "--model",
            help="Per-provider model to persist (repeatable): --model gemini=gemini-3-pro "
            "--model codex=gpt-5.5. In the TUI it pre-fills the per-agent model fields.",
        ),
    ] = None,
) -> None:
    """One-command onboarding: install backends, probe agents, pick agents + judge + models."""
    import importlib

    from siftmesh_core.config import load_settings, save_agent_selection
    from siftmesh_core.doctor import probe_agents, run_setup

    if scope not in ("global", "project"):
        typer.echo("setup failed: --scope must be 'global' or 'project'", err=True)
        raise typer.Exit(code=1)

    judge_over = _judge_overrides(
        judge
    )  # {} | {judge,llm_critic_enabled} | {llm_critic_enabled:False}
    model_over = _parse_model_overrides(model)
    settings = load_settings(**judge_over)
    if model_over:  # pre-fill the TUI model pickers / carry into headless persistence
        settings = settings.model_copy(
            update={"agent_models": {**settings.agent_models, **model_over}}
        )
    headless = no_tui or yes
    if not headless:
        from siftmesh_core import tui as _tui

        try:
            _tui.require_textual()
        except _tui.TextualMissingError:
            headless = True  # no Textual → fall back to the headless flow (still installs it)

    if not headless:
        from siftmesh_core import tui as _tui

        # `settings.judge` (from --judge) pre-selects the TUI judge picker; the screen persists.
        raise typer.Exit(code=_tui.launch(settings=settings, start="onboard"))

    # Headless: install everything, then auto-select the agents that are actually ready.
    if run_setup(settings) != 0:
        raise typer.Exit(code=1)
    importlib.invalidate_caches()
    cap = probe_agents(load_settings())
    ready = [
        a.profile_id
        for a in cap.agents
        if a.kind != "deterministic" and a.present and a.auth_ok and a.sandboxed
    ]
    preference = [*ready, "deterministic_executor"]
    executor = "auto" if ready else "deterministic"
    # Persist the judge too (None unless --judge was given → Tier-1 only; never auto-enabled).
    persist_judge = judge_over.get("judge")
    persist_gate = judge_over.get("llm_critic_enabled")
    path = save_agent_selection(
        executor,
        preference,
        scope=scope,  # type: ignore[arg-type]
        judge=persist_judge if isinstance(persist_judge, str) else None,
        llm_critic_enabled=persist_gate if isinstance(persist_gate, bool) else None,
        agent_models=model_over or None,
    )
    typer.echo(f"setup: saved {path}")
    typer.echo(f"  executor_selection = {executor}")
    typer.echo(f"  agent_preference   = {preference}")
    typer.echo(f"  tier-2 judge       = {persist_judge or 'Tier-1 only (use --judge to enable)'}")
    if model_over:
        typer.echo(f"  agent_models       = {model_over}")
    # Guided remediation: for every not-ready live agent, the exact data-driven next step.
    from siftmesh_core.adapters.profiles import load_profiles
    from siftmesh_core.doctor import agent_remediation
    from siftmesh_core.schemas.agent_capabilities import SAFETY_TIER_DESC, safety_tier_label

    profiles = load_profiles()
    not_ready = [a for a in cap.agents if a.kind != "deterministic" and a.profile_id not in ready]
    if not_ready:
        typer.echo("\nto enable more agents:")
        for a in not_ready:
            for hint in agent_remediation(a, profiles.get(a.profile_id)):
                typer.echo(f"  {a.profile_id} [{a.safety_tier}]: {hint}")
    typer.echo("\nsafety tiers:")
    for tier in SAFETY_TIER_DESC:
        typer.echo(f"  {safety_tier_label(tier)}")
    if not ready:
        typer.echo(
            "\nno live agent is ready - runs use the deterministic floor (T0, no keys needed)."
        )
    typer.echo(
        "\nnext: `siftmesh run ./examples/demo_case "
        "--evidence ./examples/demo_case/evidence --auto`"
    )
    raise typer.Exit(code=0)


@app.command()
def tui(
    run_dir: Annotated[
        str | None,
        typer.Argument(help="Attach to this run dir; omit for the home/run-picker."),
    ] = None,
) -> None:
    """Launch the live Textual cockpit (attach to a run, or browse/start one)."""
    from siftmesh_core import tui as _tui
    from siftmesh_core.config import load_settings

    try:
        _tui.require_textual()
    except _tui.TextualMissingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    if run_dir is not None and not Path(run_dir).is_dir():
        typer.echo(f"run directory does not exist: {run_dir}", err=True)
        raise typer.Exit(code=1)
    raise typer.Exit(code=_tui.launch(run_dir, settings=load_settings()))


@agents_app.command("list")
def agents_list() -> None:
    """List coding agents: installed? authenticated? can reach the typed tools? which is default?"""
    from rich.console import Console
    from rich.table import Table

    from siftmesh_core.config import load_settings
    from siftmesh_core.doctor import probe_agents
    from siftmesh_core.schemas.agent_capabilities import SAFETY_TIER_DESC, safety_tier_label

    cap = probe_agents(load_settings())
    table = Table(title="Coding agents", title_style="bold", expand=False, pad_edge=False)
    table.add_column("agent", style="bold", no_wrap=True)
    table.add_column("tier", no_wrap=True)
    table.add_column("present")
    table.add_column("auth")
    table.add_column("sandbox")
    table.add_column("tools")
    table.add_column("version", overflow="fold")
    _tier_color = {"T0": "green", "T1": "cyan", "T2": "yellow", "T3": "magenta"}
    _yn = lambda ok: "[green]✓[/]" if ok else "[red]✗[/]"  # noqa: E731
    for c in cap.agents:
        name = f"{c.profile_id}  [dim]← default[/]" if c.selected else c.profile_id
        table.add_row(
            name,
            f"[{_tier_color.get(c.safety_tier, 'white')}]{c.safety_tier}[/]",
            _yn(c.present),
            _yn(c.auth_ok),
            _yn(c.sandboxed),
            c.tool_reachable,
            c.version if c.present else "absent",
        )
    # width=100 so profile_ids never truncate under CliRunner (no TTY); plain text out of a pipe.
    Console(width=100).print(table)
    typer.echo(f"\nexecutor default (this config): {cap.chosen}")
    if cap.chosen == "deterministic_executor":
        typer.echo("(a plain `siftmesh run` uses the deterministic real-tool floor - tier T0)")
    if cap.live_candidate and cap.live_candidate != cap.chosen:
        typer.echo(f"live agent ready - opt in with `--agent`: {cap.live_candidate}")
    elif cap.chosen == "deterministic_executor":
        typer.echo("no live agent is ready - onboard one (`siftmesh setup`) for tier T1/T2.")
    # Advisory Tier-2 judge (separate purpose from the executor; off unless llm_critic_enabled).
    from siftmesh_core.adapters.judge import judge_ready

    settings = load_settings()
    ready, label = judge_ready(settings)
    gate = (
        "on" if settings.llm_critic_enabled else "off (set llm_critic_enabled / --judge to enable)"
    )
    state = "ready" if ready else "NOT ready"
    typer.echo(f"tier-2 judge [T3]: {label} - {state}; advisory layer {gate}")
    typer.echo("\nsafety tiers:")
    for tier in SAFETY_TIER_DESC:
        typer.echo(f"  {safety_tier_label(tier)}")
    typer.echo(
        "pick per purpose: `--agent <name>` (executor) · `--judge <name|litellm:model>` (judge)."
    )


@agents_app.command("inspect")
def agents_inspect(profile_id: str) -> None:
    """Show one agent's profile + launch recipe + governance (allowed tools are per-task)."""
    from pydantic import ValidationError

    from siftmesh_core.adapters.profiles import load_profiles
    from siftmesh_core.config import load_settings
    from siftmesh_core.doctor import probe_agents

    pid = _AGENT_ALIASES.get(profile_id, profile_id)  # accept friendly names too
    try:
        profiles = load_profiles()
    except (FileNotFoundError, ValidationError, ValueError) as exc:
        typer.echo(f"agents inspect failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    prof = profiles.get(pid)
    if prof is None:
        typer.echo(f"unknown agent profile: {profile_id} (try `siftmesh agents list`)", err=True)
        raise typer.Exit(code=1)
    from siftmesh_core.adapters.profiles import effective_model

    settings = load_settings()
    cap = {c.profile_id: c for c in probe_agents(settings).agents}.get(pid)
    eff = effective_model(settings, pid, prof.model)
    model_line = eff or "(auto / profile default)"
    if eff and eff != prof.model:
        model_line = f"{eff}  (override; profile default: {prof.model or 'auto'})"
    typer.echo(f"profile_id      : {prof.profile_id}")
    typer.echo(f"kind            : {prof.kind}")
    typer.echo(f"model           : {model_line}")
    typer.echo(f"cost/tier       : {prof.cost_class} / {prof.model_tier}")
    typer.echo(f"output_format   : {prof.output_format}")
    typer.echo(f"max_runtime_s   : {prof.max_runtime_seconds}")
    if prof.kind == "headless":
        recipe = [*prof.launch_argv, "<prompt>"]
        if eff and prof.model_flag:
            recipe += [prof.model_flag, eff]
        recipe += [*prof.extra_argv, *prof.native_tool_argv]
        typer.echo(f"launch          : {' '.join(recipe)}")
        typer.echo(
            f"native deny     : {' '.join(prof.native_tool_argv) or '(none - NOT dispatchable)'}"
        )
        typer.echo(f"auth_env        : {', '.join(prof.auth_env) or '(none)'}")
        typer.echo(f"auth_files      : {', '.join(prof.auth_files) or '(none)'}")
        typer.echo(f"mcp_strategy    : {prof.mcp_strategy}")
    if cap is not None:
        from siftmesh_core.schemas.agent_capabilities import safety_tier_label

        typer.echo(f"safety_tier     : {safety_tier_label(cap.safety_tier)}")
        typer.echo(
            f"status          : present={cap.present} auth={cap.auth_ok} "
            f"sandboxed={cap.sandboxed} tools={cap.tool_reachable}"
            f"{' (default)' if cap.selected else ''}"
        )
        from siftmesh_core.doctor import agent_remediation

        for hint in agent_remediation(cap, prof):
            typer.echo(f"  → {hint}")
    typer.echo("allowed tools   : per-task (the contract's allowed_tools); native tools denied.")


@app.command()
def retry(run_dir: str, task_id: str) -> None:
    """Re-critique one task; if DECIDE says retry, tighten its contract + re-dispatch."""
    from pydantic import ValidationError

    from siftmesh_core.config import load_settings
    from siftmesh_core.orchestrator.critic import critique_run, write_retry
    from siftmesh_core.orchestrator.decide import decide
    from siftmesh_core.orchestrator.scheduler import dispatch_run
    from siftmesh_core.run_dir import RunPaths
    from siftmesh_core.schemas.task import TaskContract
    from siftmesh_core.schemas.task_result import TaskResult
    from siftmesh_core.schemas.yaml_io import read_yaml_model

    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        run = RunPaths(root=root)
        settings = load_settings()
        result_path = run.result_path(task_id)
        if not result_path.is_file():
            raise FileNotFoundError(f"no result for {task_id} at {result_path}")
        result = TaskResult.model_validate_json(result_path.read_text(encoding="utf-8"))
        contract = read_yaml_model(TaskContract, run.tasks / f"{task_id}.yaml")
        verdicts = {
            v.task_id: v for v in critique_run(run, settings=settings, generate_followups=False)
        }
        verdict = verdicts.get(task_id)
        if verdict is None:
            raise FileNotFoundError(f"no critic verdict for {task_id}")
        decision = decide(
            verdict.verdict,
            attempt=result.attempt,
            max_attempts=contract.retry_policy.max_attempts,
            max_iterations=settings.caps.max_iterations,
        )
        if decision.action != "retry":
            typer.echo(f"retry refused for {task_id}: decide={decision.action} - {decision.reason}")
            raise typer.Exit(code=1)
        write_retry(run, contract, from_attempt=result.attempt, cause=verdict.verdict)
        refs = dispatch_run(
            run,
            settings=settings,
            task_id=task_id,
            attempt=result.attempt + 1,
            critic_feedback=tuple(verdict.reasons),
        )
    except (
        FileNotFoundError,
        NotADirectoryError,
        PathPolicyViolation,
        ValidationError,
    ) as exc:
        typer.echo(f"retry failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"retry complete: {task_id} attempt {result.attempt + 1} -> {refs[0].status}")


def _resolve_gate(run_dir: str, gate: str, *, approve: bool) -> None:
    """Record an approve/reject gate decision; on approve, resume the engine."""
    from pydantic import ValidationError

    from siftmesh_core.config import load_settings
    from siftmesh_core.orchestrator.human_gate import GATES, set_gate
    from siftmesh_core.orchestrator.scheduler import CapError, PolicyError
    from siftmesh_core.orchestrator.state_machine import IllegalTransitionError
    from siftmesh_core.orchestrator.workflow_runner import run_engine
    from siftmesh_core.run_dir import RunPaths

    verb = "approve" if approve else "reject"
    matched = next((g for g in GATES if g == gate), None)
    if matched is None:
        typer.echo(f"{verb} failed: unknown gate {gate!r} (use {', '.join(GATES)})", err=True)
        raise typer.Exit(code=1)
    try:
        root = Path(run_dir)
        if not root.is_dir():
            raise NotADirectoryError(f"run directory does not exist: {root}")
        run_paths = RunPaths(root=root)
        status: GateStatus = "approved" if approve else "rejected"
        state = set_gate(run_paths, matched, status)
        if approve:
            state = run_engine(
                run_paths, settings=load_settings(), single_step=(state.mode == "manual")
            )
    except (
        FileNotFoundError,
        NotADirectoryError,
        PathPolicyViolation,
        BackendUnavailableError,
        ValidationError,
        PolicyError,
        CapError,
        IllegalTransitionError,
    ) as exc:
        typer.echo(f"{verb} failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"{verb}d gate {gate}")
    _echo_run_state(run_paths, state)


@app.command()
def approve(
    run_dir: str,
    gate: Annotated[str, typer.Option(help="plan | dispatch | retry | report")],
) -> None:
    """Approve a blocked gate and resume the engine."""
    _resolve_gate(run_dir, gate, approve=True)


@app.command()
def reject(
    run_dir: str,
    gate: Annotated[str, typer.Option(help="plan | dispatch | retry | report")],
) -> None:
    """Reject a blocked gate; the run halts cleanly on its next entry."""
    _resolve_gate(run_dir, gate, approve=False)


def _open_run(run_dir: str) -> RunPaths:
    """Resolve an existing run dir for the read-only inspection commands (exit 1 if absent)."""
    from siftmesh_core.run_dir import RunPaths

    root = Path(run_dir)
    if not root.is_dir():
        typer.echo(f"run directory does not exist: {root}", err=True)
        raise typer.Exit(code=1)
    return RunPaths(root=root)


def _printable(text: str, *, limit: int = 80) -> str:
    """One sanitized line of hostile-evidence-derived text (control chars stripped)."""
    flat = " ".join(text.split())
    safe = "".join(ch if ch.isprintable() else "?" for ch in flat)
    return safe if len(safe) <= limit else safe[: limit - 3] + "..."


@tasks_app.command("list")
def tasks_list(run_dir: str) -> None:
    """List a run's task contracts with their result status (read-only)."""
    from pydantic import ValidationError

    from siftmesh_core.schemas.task import TaskContract
    from siftmesh_core.schemas.task_result import TaskResult
    from siftmesh_core.schemas.yaml_io import read_yaml_model

    run = _open_run(run_dir)
    paths = sorted(run.tasks.glob("TASK-*.yaml"))
    if not paths:
        typer.echo("no tasks yet (run `siftmesh plan` first)")
        return
    for path in paths:
        try:
            contract = read_yaml_model(TaskContract, path)
        except (ValidationError, OSError):
            typer.echo(f"  {path.stem}  [invalid contract]")
            continue
        result_path = run.result_path(contract.task_id)
        status = "pending"
        if result_path.is_file():
            try:
                status = TaskResult.model_validate_json(
                    result_path.read_text(encoding="utf-8")
                ).status
            except ValidationError:
                status = "malformed-result"
        typer.echo(
            f"  {contract.task_id}  role={_printable(contract.role, limit=32)}  "
            f"profile={contract.assigned_agent_profile}  status={status}"
        )
    typer.echo(f"{len(paths)} task(s)")


@tasks_app.command("show")
def tasks_show(run_dir: str, task_id: str) -> None:
    """Show one task contract (validated, then echoed)."""
    from pydantic import ValidationError

    from siftmesh_core.schemas.task import TaskContract
    from siftmesh_core.schemas.yaml_io import read_yaml_model

    run = _open_run(run_dir)
    path = run.tasks / f"{task_id}.yaml"
    if not path.is_file():
        typer.echo(f"no such task: {task_id} ({path})", err=True)
        raise typer.Exit(code=1)
    try:
        read_yaml_model(TaskContract, path)  # prove it is a valid contract before echoing
    except ValidationError as exc:
        typer.echo(f"contract fails schema validation: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    raw = path.read_text(encoding="utf-8")
    typer.echo("".join(ch if ch.isprintable() or ch == "\n" else "?" for ch in raw))


@claims_app.command("list")
def claims_list(run_dir: str) -> None:
    """List the promoted findings ledger + the unsupported count (read-only)."""
    from siftmesh_core.ledgers.claim_ledger import read_claims, read_unsupported_claims

    run = _open_run(run_dir)
    claims = read_claims(run.root)
    for c in claims:
        artifact = _printable(c.source_artifact or "-", limit=40)
        typer.echo(
            f"  {c.claim_id}  [{c.status}]  conf={c.confidence:.2f}  "
            f"{artifact}  {_printable(c.claim, limit=60)}"
        )
    unsupported = read_unsupported_claims(run.root)
    typer.echo(
        f"{len(claims)} claim(s) in the findings ledger; "
        f"{len(unsupported)} unsupported (appendix-only, never facts)"
    )


@claims_app.command("show")
def claims_show(run_dir: str, claim_id: str) -> None:
    """Show one claim (findings ledger first, then the unsupported ledger)."""
    from siftmesh_core.ledgers.claim_ledger import read_claims, read_unsupported_claims

    run = _open_run(run_dir)
    for claim in read_claims(run.root):
        if claim.claim_id == claim_id:
            typer.echo(claim.model_dump_json(indent=2))
            return
    for claim in read_unsupported_claims(run.root):
        if claim.claim_id == claim_id:
            typer.echo(claim.model_dump_json(indent=2))
            typer.echo("status: UNSUPPORTED - rejected by the critic; never a report fact")
            return
    typer.echo(f"no such claim: {claim_id}", err=True)
    raise typer.Exit(code=1)


_AUDIT_LEDGERS = (
    "events",
    "tool-calls",
    "agent-calls",
    "agent-tokens",
    "retries",
    "token-budget",
)


@audit_app.command("tail")
def audit_tail(
    run_dir: str,
    lines: Annotated[int, typer.Option("--lines", "-n", help="How many trailing lines.")] = 20,
    ledger: Annotated[
        str,
        typer.Option(
            help="events | tool-calls | agent-calls | agent-tokens | retries | token-budget"
        ),
    ] = "events",
) -> None:
    """Tail an audit ledger (raw JSONL lines, newest last; read-only)."""
    run = _open_run(run_dir)
    targets = {
        "events": run.orchestration_events,
        "tool-calls": run.tool_calls,
        "agent-calls": run.agent_calls,
        "agent-tokens": run.agent_tokens,
        "retries": run.retries,
        "token-budget": run.token_budget,
    }
    if ledger not in targets:
        choices = ", ".join(_AUDIT_LEDGERS)
        typer.echo(f"unknown ledger {ledger!r}; choose one of {choices}", err=True)
        raise typer.Exit(code=1)
    path = targets[ledger]
    if not path.is_file():
        typer.echo(f"no {ledger} recorded yet ({path})")
        return
    recorded = path.read_text(encoding="utf-8").splitlines()
    for line in recorded[-max(lines, 0) :]:
        typer.echo(line)
    typer.echo(f"-- {min(max(lines, 0), len(recorded))} of {len(recorded)} {ledger} line(s)")


@protocol_sift_app.command("inspect")
def protocol_sift_inspect(
    run_dir: Annotated[
        str | None,
        typer.Option(
            "--run-dir", help="Also write the validated capability map under this run dir."
        ),
    ] = None,
) -> None:
    """Inspect the ~/.claude Protocol SIFT layer (env-only; PLAN/09).

    With ``--run-dir``, also write ``context/protocol_sift_capabilities.json`` (D11).
    """
    status = detect_protocol_sift()
    typer.echo(f"Protocol SIFT installed : {status.protocol_sift_installed}")
    typer.echo(f"Claude Code installed   : {status.claude_code_installed}")
    typer.echo(f"settings.json present   : {status.settings_present}")
    typer.echo(f"case template present   : {status.case_template_present}")
    typer.echo(f"skills present          : {', '.join(status.skills_present) or 'none'}")
    typer.echo(f"SIFT tools present      : {', '.join(status.tools_present) or 'none'}")
    typer.echo(f"SIFT tools absent       : {', '.join(status.tools_absent) or 'none'}")
    if run_dir is not None:
        from siftmesh_core.protocol_sift import write_protocol_sift_capability_map

        try:
            path = write_protocol_sift_capability_map(run_dir)
        except (FileNotFoundError, PathPolicyViolation) as exc:
            typer.echo(f"capability map write failed: {exc}", err=True)
            raise typer.Exit(code=1) from exc
        typer.echo(f"capability map written  : {path}")


@skills_app.command("list")
def protocol_sift_skills_list() -> None:
    """List Protocol SIFT skills and whether each is present."""
    status = detect_protocol_sift()
    for skill in PROTOCOL_SIFT_SKILLS:
        mark = "x" if skill in status.skills_present else " "
        typer.echo(f"  [{mark}] {skill}")


if __name__ == "__main__":
    app()
