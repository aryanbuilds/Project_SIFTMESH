"""Executor tiering (scale fixes): heavy tool-bound tasks (image/memory) run on the deterministic
floor even when a live agent is selected, unless `live_extraction` (`run --all-live`). Parse tasks
still honor the live chain. Fixtures only; the live adapter is never actually invoked here.
"""

from __future__ import annotations

from pathlib import Path

from siftmesh_core.adapters import resolve_profile
from siftmesh_core.config import load_settings
from siftmesh_core.orchestrator import scheduler
from siftmesh_core.schemas.task import InputArtifact, SafetyPolicy, TaskContract


def _contract(tool: str, role: str) -> TaskContract:
    return TaskContract(
        task_id="TASK-001",
        role=role,
        objective="x",
        assigned_agent_profile="deterministic_executor",
        allowed_tools=[tool],
        input_artifacts=[InputArtifact(path="img.e01", sha256="a" * 64)],
        safety_policy=SafetyPolicy(),
    )


def _live_settings(**extra: object):  # type: ignore[no-untyped-def]
    # mimic `--agent claude`: executor_selection=auto + claude head of the chain
    return load_settings(
        executor_selection="auto",
        agent_preference=["claude_headless", "deterministic_executor"],
        **extra,
    )


def test_heavy_tool_bound_covers_image_memory_and_high_volume_parsers() -> None:
    assert {
        "extract_artifacts_from_image",
        "analyze_memory",
        "parse_mft_filesystem",
        "parse_usnjrnl",
        "build_super_timeline",
    } == scheduler._HEAVY_TOOL_BOUND


def test_live_settings_would_select_live_for_a_parse_role() -> None:
    # sanity: under the live chain, a parse role resolves to the live head (so the tiering guard,
    # not resolve_profile, is what forces image/memory to the floor).
    s = _live_settings()
    assert resolve_profile("evtx_security_executor", settings=s) == "claude_headless"


def test_tiering_guard_logic_forces_floor_for_heavy_tools() -> None:
    s = _live_settings()
    for tool in ("extract_artifacts_from_image", "analyze_memory"):
        c = _contract(tool, f"{tool}_role")
        profile = resolve_profile(c.role, settings=s)
        forced = (
            profile != "deterministic_executor"
            and not s.live_extraction
            and any(t in scheduler._HEAVY_TOOL_BOUND for t in c.allowed_tools)
        )
        assert forced, f"{tool} should be tiered to the floor under a live agent"


def test_high_volume_parsers_tiered_to_floor_under_live() -> None:
    # $MFT / USN-journal / Plaso super-timeline overflow a live agent's context (it failed to anchor
    # them in a real run -> quarantined); the floor has working claim builders, so tier them down.
    s = _live_settings()
    for tool in ("parse_mft_filesystem", "parse_usnjrnl", "build_super_timeline"):
        c = _contract(tool, f"{tool}_role")
        forced = (
            resolve_profile(c.role, settings=s) != "deterministic_executor"
            and not s.live_extraction
            and any(t in scheduler._HEAVY_TOOL_BOUND for t in c.allowed_tools)
        )
        assert forced, f"{tool} should be tiered to the floor under a live agent"


def test_all_live_disables_tiering() -> None:
    s = _live_settings(live_extraction=True)
    c = _contract("analyze_memory", "memory_role")
    forced = (
        resolve_profile(c.role, settings=s) != "deterministic_executor"
        and not s.live_extraction
        and any(t in scheduler._HEAVY_TOOL_BOUND for t in c.allowed_tools)
    )
    assert not forced  # --all-live keeps heavy tasks on the live agent


def test_heavy_tool_timeout_is_generous(tmp_path: Path) -> None:
    assert load_settings().heavy_tool_timeout_seconds >= 1800  # 19 GB memory / 22 GB image need it
