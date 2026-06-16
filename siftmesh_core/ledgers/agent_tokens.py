"""Per-agent LLM token-usage ledger (audit-trail completeness).

Appends one :class:`AgentTokenUsage` per live dispatch that reports usage to
``audit/agent_tokens.jsonl``, built on the generic validate-before-write JSONL ledger. The
deterministic floor never writes here (no LLM), so a no-keys / golden run has no such file. Joins to
``agent_calls.jsonl`` on ``agent_call_id``.
"""

from __future__ import annotations

from pathlib import Path

from siftmesh_core.ledgers.jsonl_ledger import append_record, read_records
from siftmesh_core.schemas.agent_token_usage import AgentTokenUsage

_AGENT_TOKENS = Path("audit") / "agent_tokens.jsonl"


def append_agent_token_usage(
    run_root: Path | str,
    usage: AgentTokenUsage,
    *,
    evidence_root: Path | str | None = None,
) -> Path:
    """Append one token-usage record to ``audit/agent_tokens.jsonl``."""
    return append_record(run_root, _AGENT_TOKENS, usage, evidence_root=evidence_root)


def read_agent_token_usage(run_root: Path | str) -> list[AgentTokenUsage]:
    """Read all token-usage records for a run (empty list when none / no live agent)."""
    return list(read_records(Path(run_root) / _AGENT_TOKENS, AgentTokenUsage))
