"""Claude Code headless adapter (Epic F, F8) - the live autonomous executor (CORE).

Thin wrapper around ``claude -p`` in non-interactive JSON mode. The agent is SANDBOXED to
SIFTMesh's typed tools: the FastMCP server is launched via ``python -m siftmesh_core.cli mcp-serve``
(NOT bare ``siftmesh`` - not on the subprocess PATH), ``--strict-mcp-config`` ignores ambient MCP
servers, ``--allowedTools`` pre-approves only the contract's ``mcp__siftmesh__*`` tools,
``--disallowedTools`` denies the built-in shell/file/web/spawn tools, and ``--permission-mode
dontAsk`` auto-denies anything else (no prompt/hang). So the agent cannot run raw shell or write
files (CLAUDE §3/§6 privilege separation). When the CLI or all auth (subscription token / OAuth
bearer / API key / logged-in CLI) is absent the adapter is unavailable and the registry falls closed
to the deterministic floor.

HARD GATES (CLAUDE §2A/§2B):
* CLI flags re-confirmed against claude v2.1.170 ``--help`` (Epic L): ``--permission-mode`` accepts
  ``dontAsk`` (of acceptEdits/auto/bypassPermissions/default/dontAsk/plan); ``--strict-mcp-config``
  ignores ambient MCP servers; ``--allowedTools`` / ``--disallowedTools`` / ``--mcp-config`` /
  ``--output-format`` present. Isolated in ``_build_claude_argv``; re-confirm on bumps.
* Live validation against real evidence is HUMAN-GATED. Unit tests mock the subprocess boundary
  only; do NOT autonomously run a live agent against evidence.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from siftmesh_core.adapters.agent_result import parse_agent_result
from siftmesh_core.adapters.base import AdapterContext, ExecutorAdapter, register
from siftmesh_core.adapters.profiles import effective_model
from siftmesh_core.adapters.prompt_builder import build_task_prompt
from siftmesh_core.adapters.sandbox import minimal_child_env, scratch_cwd
from siftmesh_core.adapters.spotlight import scan_injection
from siftmesh_core.adapters.token_usage import extract_claude_usage
from siftmesh_core.evidence.path_policy import safe_write_path
from siftmesh_core.ledgers.injection_alerts import append_injection_alert, next_alert_id
from siftmesh_core.schemas.injection_alert import InjectionAlert
from siftmesh_core.schemas.task import TaskContract
from siftmesh_core.schemas.task_result import TaskResult

_MCP_TOOL_PREFIX = "mcp__siftmesh__"
# Env vars that authenticate `claude -p`: a subscription token (claude setup-token) OR an OAuth
# bearer OR the commercial API key. Any one present => the adapter is usable (dual auth).
_AUTH_ENV = ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY")

# Built-in Claude Code tools the SANDBOXED forensic agent must NOT have. `--allowedTools` is only
# ADDITIVE (it does not exclude built-ins - confirmed via claude-code docs + issue #62608), so we
# explicitly DENY raw shell / file-write / read / web / spawn tools. Combined with
# `--permission-mode dontAsk` (auto-deny anything not explicitly allowed, no prompt, no hang) this
# constrains the agent to ONLY the typed mcp__siftmesh__* tools (CLAUDE.md §3/§6 privilege
# separation). Over-listing is harmless - denying an unknown tool name is a no-op.
_DISALLOWED_TOOLS = (
    "Bash",
    "BashOutput",
    "KillShell",
    "Edit",
    "MultiEdit",
    "Write",
    "NotebookEdit",
    "Read",
    "Glob",
    "Grep",
    "LS",
    "WebFetch",
    "WebSearch",
    "Task",
    "Agent",
    "TodoWrite",
    "Skill",
    "SlashCommand",
)

# Hook isolation (Project_SIFTAMESS-gssw): the user's ambient ~/.claude (and project) lifecycle
# HOOKS still fire during a headless `claude -p` run even with the tool sandbox - observed: a
# Protocol SIFT Stop-hook appended to <repo>/analysis/forensic_audit.log on every live run. That is
# a side-effect channel OUTSIDE the typed-tool sandbox. `disableAllHooks` is a scalar that, via
# `--settings`, overrides the user/project hooks WHILE PRESERVING subscription auth (the OAuth
# credentials in ~/.claude/.credentials.json are still read) - unlike `--bare`, which disables the
# keychain and breaks subscription auth. This TIGHTENS containment (it removes an uncontained side
# effect); every real guardrail (--permission-mode dontAsk / --disallowedTools /
# --strict-mcp-config) is unchanged. Confirmed on claude v2.1.173: `--settings <file-or-json>`
# accepts an inline JSON string. Re-confirm on version bumps.
_DISABLE_HOOKS_SETTINGS = '{"disableAllHooks": true}'


def claude_sandbox_flags(
    allowed_tools: list[str] | tuple[str, ...], *, permission_mode: str = "dontAsk"
) -> list[str]:
    """The Claude-CLI sandbox flag block (shared by the claude adapter + the headless claude_flag).

    Confirmed on claude v2.1.177: ``claude --help`` documents ``--tools <tools...>`` as *the list of
    AVAILABLE tools* ("'default' to use all tools, or specify tool names"). Passing ``--tools ""``
    (empty) therefore sets the available universe to NOTHING - it disables the typed
    ``mcp__siftmesh__*`` tools too, not just built-ins, so the agent gets zero tools, never calls a
    tool (it emits ``<invoke name="Bash">`` as plain text), and the critic rejects every empty
    result into a retry loop. NEVER pass an empty ``--tools`` on the executor path. We instead
    expose the typed tools and deny built-ins explicitly: ``--allowedTools mcp__siftmesh__*``
    pre-approves only the contract's typed tools (it is additive, not exclusive),
    ``--disallowedTools`` denies the built-in shell/file/web/spawn tools, and ``--permission-mode
    dontAsk`` auto-denies anything else (incl. new built-ins) with no prompt/hang. Wiring the typed
    tools (``--mcp-config``) WITHOUT this block would leave native tools enabled - so the two must
    never be separated.
    """
    tools = ",".join(f"{_MCP_TOOL_PREFIX}{t}" for t in allowed_tools)
    return [
        "--allowedTools",
        tools,
        "--disallowedTools",
        *_DISALLOWED_TOOLS,
        "--permission-mode",
        permission_mode,
        "--settings",
        _DISABLE_HOOKS_SETTINGS,  # gssw: no ambient hook fires during the governed run
    ]


def _claude_logged_in() -> bool:
    """True if the Claude Code CLI is already logged in (its own credential store exists).

    After ``claude setup-token`` / ``claude login`` the credentials live in
    ``~/.claude/.credentials.json`` and ``claude -p`` authenticates from there with NO env var - so
    a logged-in CLI is usable even when no ANTHROPIC_*/CLAUDE_CODE_* var is set. Existence is a
    best-effort signal; an expired token still fails closed at subprocess time (never faked).
    """
    return (Path.home() / ".claude" / ".credentials.json").is_file()


def claude_available(settings: object) -> bool:
    """True if the Claude CLI is on PATH and some auth is present (subscription/OAuth/API key)."""
    cli = getattr(settings, "claude_cli_path", "claude")
    if shutil.which(cli) is None:
        return False
    return any(os.environ.get(var) for var in _AUTH_ENV) or _claude_logged_in()


def invoke_claude_text(prompt: str, settings: object, *, timeout: int | None = None) -> str | None:
    """Tool-LESS reasoning call: ``claude -p <prompt> --output-format json`` → the agent's text.

    For ADVISORY layers (Tier-2 judge, cross-run synthesis) that reason over already-collected text
    and need NO forensic tools - so no MCP config and all built-in tools denied (sandboxed). Returns
    ``None`` on absence / timeout / error / unparseable output (callers fail soft; never fabricate).
    """
    cli = getattr(settings, "claude_cli_path", "claude")
    if shutil.which(cli) is None:
        return None
    # --strict-mcp-config WITHOUT --mcp-config => zero MCP servers (v2.1.x), closing the leak where
    # ambient claude.ai-hosted / user / project MCP servers would otherwise load into this advisory,
    # tool-less call; --tools "" denies every built-in. The advisory agent reasons over text only.
    argv = [
        cli,
        "-p",
        prompt,
        "--output-format",
        "json",
        # Fresh, non-persisted session: never resume/continue an ambient or concurrent interactive
        # session, and never write this advisory call to the on-disk session cache (see _execute).
        "--session-id",
        str(uuid.uuid4()),
        "--no-session-persistence",
        "--strict-mcp-config",
        "--tools",
        "",
        "--disallowedTools",
        *_DISALLOWED_TOOLS,
        "--permission-mode",
        getattr(settings, "claude_permission_mode", "dontAsk"),
        "--settings",
        _DISABLE_HOOKS_SETTINGS,  # gssw: advisory call must not fire ambient hooks either
    ]
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout or getattr(settings, "agent_timeout_seconds", 600),
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,  # headless: no interactive input (skip 3s stdin wait)
            env=minimal_child_env(keep=_AUTH_ENV),  # base + Claude auth only; no stray env
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    try:
        envelope = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if envelope.get("is_error", proc.returncode != 0):
        return None
    text = str(envelope.get("result", "")).strip()
    return text or None


def _build_claude_argv(
    cli_path: str,
    prompt: str,
    mcp_config: Path,
    allowed_tools: list[str],
    *,
    session_id: str | None = None,
    model: str | None = None,
    permission_mode: str = "dontAsk",
) -> list[str]:
    """Build the SANDBOXED headless ``claude -p`` argv (flags isolated here; confirmed v2.1.177).

    The agent is constrained to ONLY the contract's ``mcp__siftmesh__*`` tools:
    ``--allowedTools`` pre-approves them, ``--disallowedTools`` denies the built-in shell/file/web/
    spawn tools (``--allowedTools`` alone is additive, not exclusive), ``--permission-mode dontAsk``
    auto-denies anything else with no prompt/hang, and ``--strict-mcp-config`` ignores ambient MCP
    servers. ``--model`` (when set) pins the model. Re-confirm ``claude --help`` on version bumps.

    SESSION ISOLATION (Project_SIFTAMESS, live-run contamination fix): ``--session-id <fresh uuid>``
    pins a brand-new session so the run can never resume/continue an ambient or **concurrent
    interactive** Claude session (observed: a headless run returned an interactive transcript with a
    raw ``<invoke name="Bash">`` block + ``[Request interrupted by user]`` rather than calling the
    typed tool), and ``--no-session-persistence`` keeps this run out of the on-disk session cache.
    NOT ``--bare`` (it skips keychain reads and would break subscription auth). Confirmed on claude
    v2.1.177; re-confirm on bumps.
    """
    argv = [
        cli_path,
        "-p",
        prompt,
        "--output-format",
        "json",
        "--session-id",
        session_id or str(uuid.uuid4()),
        "--no-session-persistence",
        "--mcp-config",
        str(mcp_config),
        "--strict-mcp-config",
        *claude_sandbox_flags(allowed_tools, permission_mode=permission_mode),
    ]
    if model:
        argv += ["--model", model]
    return argv


@register
class ClaudeHeadlessAdapter(ExecutorAdapter):
    """Run the live Claude Code agent headlessly, constrained to the typed tools."""

    profile_id = "claude_headless"
    backend_label = "claude_headless"

    def available(self) -> bool:
        # CLI present AND authenticated: an auth env var (subscription token / OAuth bearer / API
        # key) OR a logged-in Claude Code CLI (its own credential store; `claude -p` uses it with no
        # env var). Fails closed when the CLI or all auth is absent -> registry walks to the floor.
        if shutil.which(self.settings.claude_cli_path) is None:
            return False
        has_env_auth = any(os.environ.get(var) for var in _AUTH_ENV)
        return has_env_auth or _claude_logged_in()

    def _execute(self, contract: TaskContract, ctx: AdapterContext) -> TaskResult:
        started = datetime.now(UTC)
        prompt = build_task_prompt(
            contract,
            run_id=ctx.run.run_id,
            critic_feedback=ctx.critic_feedback,
            incident_objective=ctx.incident_objective,
        )
        mcp_config = self._write_mcp_config(ctx)
        prof = self.profile()
        argv = _build_claude_argv(
            self.settings.claude_cli_path,
            prompt,
            mcp_config,
            contract.allowed_tools,
            session_id=str(
                uuid.uuid4()
            ),  # fresh session per dispatch (no concurrent-session bleed)
            model=effective_model(self.settings, self.profile_id, prof.model if prof else None),
            permission_mode=self.settings.claude_permission_mode,
        )
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.settings.agent_timeout_seconds,
                shell=False,
                check=False,
                cwd=scratch_cwd(
                    ctx.run, contract.task_id
                ),  # never the operator CWD (injection/escape)
                stdin=subprocess.DEVNULL,  # headless: no interactive input (skip 3s stdin wait)
                env=minimal_child_env(keep=_AUTH_ENV),  # base + Claude auth only; no stray env
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return self._error(contract, ctx, started, "agent_failed_or_timeout")
        self._write_raw(ctx, contract, proc.stdout)  # persist raw envelope for debugging
        if proc.stderr:
            self._write_stderr(ctx, contract, proc.stderr)  # MCP connect/startup errors land here
        try:
            envelope = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return self._error(contract, ctx, started, "agent_bad_json")
        result_text = str(envelope.get("result", ""))
        # Record the LLM token usage this dispatch reported (base.run() writes it to the audit
        # trail keyed to the agent_call_id). Fail-soft: None when the envelope has no usage.
        self._token_usage = extract_claude_usage(envelope)
        self._scan(ctx, contract, result_text)  # injection scan on the agent's final message
        if envelope.get("is_error", proc.returncode != 0):
            return self._error(contract, ctx, started, str(envelope.get("subtype", "agent_error")))
        # K3: capture the agent's claims from its final message. Under-anchored claims land as
        # 'unsupported' (never fabricated) so the deterministic critic drives a retry-with-feedback.
        return parse_agent_result(
            result_text,
            contract=contract,
            ctx=ctx,
            adapter_id=self.profile_id,
            started=started,
            ended=datetime.now(UTC),
        )

    def _write_mcp_config(self, ctx: AdapterContext) -> Path:
        """Write a per-run MCP config pointing at SIFTMesh's stdio FastMCP server.

        The server is launched as ``<this interpreter> -m siftmesh_core.cli mcp-serve`` - NOT bare
        ``siftmesh`` (a uv/pip console script that is not on the agent subprocess's PATH), so the
        agent can actually reach the typed tools regardless of how SIFTMesh was invoked. Roots are
        written ABSOLUTE so the run-scoped server resolves them from any cwd.
        """
        config = {
            "mcpServers": {
                "siftmesh": {
                    "command": sys.executable,
                    "args": ["-m", "siftmesh_core.cli", "mcp-serve"],
                    "env": {
                        "SIFTMESH_RUN_ROOT": str(Path(ctx.run.root).resolve()),
                        "SIFTMESH_EVIDENCE_ROOT": str(Path(ctx.evidence_root).resolve()),
                    },
                }
            }
        }
        target = safe_write_path(ctx.run.root, "context/mcp_config.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        return target

    def _write_raw(self, ctx: AdapterContext, contract: TaskContract, stdout: str) -> None:
        """Persist the agent's raw stdout envelope for debugging (no parsing, no judgment)."""
        target = safe_write_path(ctx.run.root, f"results/{contract.task_id}.agent_raw.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(stdout, encoding="utf-8")

    def _write_stderr(self, ctx: AdapterContext, contract: TaskContract, stderr: str) -> None:
        """Persist raw stderr (MCP connection/startup errors land here, not on stdout)."""
        target = safe_write_path(ctx.run.root, f"results/{contract.task_id}.agent_stderr.txt")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(stderr, encoding="utf-8")

    def _error(
        self, contract: TaskContract, ctx: AdapterContext, started: datetime, code: str
    ) -> TaskResult:
        return TaskResult(
            task_id=contract.task_id,
            profile=ctx.requested_profile or self.profile_id,
            adapter=self.profile_id,
            attempt=ctx.attempt,
            status="error",
            started_utc=started,
            ended_utc=datetime.now(UTC),
            errors=[code],
        )

    def _scan(self, ctx: AdapterContext, contract: TaskContract, text: str) -> None:
        for m in scan_injection(text):
            append_injection_alert(
                ctx.run.root,
                InjectionAlert(
                    alert_id=next_alert_id(ctx.run.root),
                    source="agent_result",
                    signature=m.signature,
                    snippet=m.snippet,
                    detected_utc=datetime.now(UTC),
                    task_id=contract.task_id,
                ),
                evidence_root=ctx.evidence_root,
            )
