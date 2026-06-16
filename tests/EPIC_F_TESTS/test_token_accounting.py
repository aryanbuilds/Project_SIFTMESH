"""Per-agent LLM token accounting: extract usage from the envelope + record it (live agents only).

Closes the audit-trail gap the judge review flagged. The deterministic floor never reports usage, so
a no-keys / golden run writes no ``agent_tokens.jsonl`` (byte-identical).
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from siftmesh_core.adapters.base import AdapterContext, ExecutorAdapter
from siftmesh_core.adapters.token_usage import LlmTokenUsage, extract_claude_usage
from siftmesh_core.config import load_settings
from siftmesh_core.ledgers.agent_calls import read_agent_calls
from siftmesh_core.ledgers.agent_tokens import read_agent_token_usage
from siftmesh_core.run_dir import RunPaths
from siftmesh_core.schemas.task import InputArtifact, SafetyPolicy, TaskContract
from siftmesh_core.schemas.task_result import TaskResult

MakeRealRun = Callable[..., tuple[RunPaths, Path]]

_FULL_ENVELOPE = {
    "type": "result",
    "is_error": False,
    "result": '{"claims": []}',
    "usage": {
        "input_tokens": 816,
        "output_tokens": 1521,
        "cache_read_input_tokens": 77008,
        "cache_creation_input_tokens": 31688,
    },
    "total_cost_usd": 0.398784,
    "modelUsage": {"claude-opus-4-8": {"costUSD": 0.397489}},
}


def test_extract_claude_usage_full() -> None:
    u = extract_claude_usage(_FULL_ENVELOPE)
    assert u is not None
    assert u.input_tokens == 816
    assert u.output_tokens == 1521
    assert u.total_tokens == 2337
    assert u.cache_read_tokens == 77008
    assert u.cache_creation_tokens == 31688
    assert u.cost_usd == 0.398784
    assert u.model == "claude-opus-4-8"


def test_extract_claude_usage_missing_and_malformed() -> None:
    assert extract_claude_usage({"result": "x", "is_error": False}) is None  # no usage
    assert extract_claude_usage({"usage": "not-a-dict"}) is None  # malformed usage
    assert extract_claude_usage("not-a-dict") is None  # not an envelope
    # partial usage: cost absent, tokens present -> recorded with total computed, cost None
    partial = extract_claude_usage({"usage": {"input_tokens": 10, "output_tokens": 5}})
    assert partial is not None
    assert partial.total_tokens == 15 and partial.cost_usd is None


class _FakeLive(ExecutorAdapter):
    """Minimal live-style adapter that reports token usage (mirrors what claude_adapter sets)."""

    profile_id = "claude_headless"
    backend_label = "claude_headless"

    def _execute(self, contract: TaskContract, ctx: AdapterContext) -> TaskResult:
        self._token_usage = LlmTokenUsage(
            model="claude-opus-4-8",
            input_tokens=816,
            output_tokens=1521,
            total_tokens=2337,
            cache_read_tokens=77008,
            cache_creation_tokens=31688,
            cost_usd=0.398784,
        )
        now = datetime.now(UTC)
        return TaskResult(
            task_id=contract.task_id,
            profile=self.profile_id,
            adapter=self.profile_id,
            attempt=1,
            status="success",
            started_utc=now,
            ended_utc=now,
        )


def _contract() -> TaskContract:
    return TaskContract(
        task_id="TASK-001",
        role="r",
        objective="o",
        assigned_agent_profile="claude_headless",
        allowed_tools=["compute_hash_manifest"],
        input_artifacts=[InputArtifact(path="x", sha256="a" * 64)],
        safety_policy=SafetyPolicy(),
    )


def test_base_run_records_token_usage_keyed_to_agent_call(tmp_path: Path) -> None:
    run = RunPaths(root=tmp_path / "RUN-20260101-000000")
    run.root.mkdir(parents=True)
    evidence = tmp_path / "ev"
    evidence.mkdir()
    ctx = AdapterContext(run=run, evidence_root=evidence, settings=load_settings())

    _FakeLive(settings=load_settings()).run(_contract(), ctx)

    calls = read_agent_calls(run.root)
    toks = read_agent_token_usage(run.root)
    assert len(calls) == 1 and len(toks) == 1
    assert toks[0].agent_call_id == calls[0].agent_call_id  # joins to the dispatch
    assert toks[0].input_tokens == 816 and toks[0].cost_usd == 0.398784
    assert toks[0].profile == "claude_headless"


def test_deterministic_run_writes_no_agent_tokens(make_real_run: MakeRealRun) -> None:
    run, _ = make_real_run(dispatch=True)  # the floor: no LLM, no token usage
    assert read_agent_token_usage(run.root) == []
    assert not run.agent_tokens.is_file()
