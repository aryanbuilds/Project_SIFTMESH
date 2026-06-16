"""Extract LLM token usage from a live agent's response envelope (audit-trail completeness).

Fail-soft by design: a missing / malformed / unknown-shape envelope yields ``None`` (the dispatch
records no token line) rather than raising - token accounting must never break an investigation.

Today only the Claude CLI JSON envelope is parsed (the proven tool-reachable live executor); other
agents return ``None`` until their usage shape is confirmed, so the gap is honest, not faked.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class LlmTokenUsage:
    """One dispatch's LLM token usage (any field may be None when the agent did not report it)."""

    model: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    cache_read_tokens: int | None = None
    cache_creation_tokens: int | None = None
    cost_usd: float | None = None


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _as_float(value: Any) -> float | None:
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def extract_claude_usage(envelope: Any) -> LlmTokenUsage | None:
    """Pull token usage from a Claude CLI ``--output-format json`` envelope.

    The envelope carries a top-level ``usage`` dict (``input_tokens`` / ``output_tokens`` /
    ``cache_read_input_tokens`` / ``cache_creation_input_tokens``) plus ``total_cost_usd`` and an
    optional ``modelUsage`` map. Returns ``None`` when no usage is present (fail-soft).
    """
    if not isinstance(envelope, dict):
        return None
    usage = envelope.get("usage")
    if not isinstance(usage, dict):
        return None
    input_tokens = _as_int(usage.get("input_tokens"))
    output_tokens = _as_int(usage.get("output_tokens"))
    total = (
        input_tokens + output_tokens
        if input_tokens is not None and output_tokens is not None
        else None
    )

    model: str | None = None
    model_usage = envelope.get("modelUsage")
    if isinstance(model_usage, dict) and model_usage:
        first = next(iter(model_usage))
        model = first if isinstance(first, str) else None

    return LlmTokenUsage(
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total,
        cache_read_tokens=_as_int(usage.get("cache_read_input_tokens")),
        cache_creation_tokens=_as_int(usage.get("cache_creation_input_tokens")),
        cost_usd=_as_float(envelope.get("total_cost_usd")),
    )
