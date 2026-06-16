"""Per-agent LLM token-usage record (audit-trail completeness).

A live executor (e.g. Claude via ``claude_headless``) returns its token usage in the response
envelope. One :class:`AgentTokenUsage` is appended to ``audit/agent_tokens.jsonl`` per live dispatch
that exposes usage, keyed to the dispatch's ``agent_call_id`` (joins to ``agent_calls.jsonl``). The
deterministic floor runs no LLM and never emits one - so a no-keys / golden run has no such file.

Distinct from ``audit/token_budget.jsonl`` (the engine's profile-routing decisions, not LLM tokens).
Every field except the ids is optional: an agent that does not report a particular figure records it
as ``null`` rather than fabricating it.
"""

from __future__ import annotations

from siftmesh_core.schemas._base import StrictModel, UtcDateTime


class AgentTokenUsage(StrictModel):
    """LLM token usage for one live-agent dispatch (joins to AgentCall.agent_call_id)."""

    agent_call_id: str  # the AGENT-NNN this usage belongs to
    task_id: str
    profile: str  # the executor profile that produced it (e.g. claude_headless)
    model: str | None = None  # the model id the agent reported, if any
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None  # input + output when both are known
    cache_read_tokens: int | None = None  # prompt-cache reads (Claude)
    cache_creation_tokens: int | None = None  # prompt-cache creation (Claude)
    cost_usd: float | None = None  # billing cost the agent reported, if any
    recorded_utc: UtcDateTime
