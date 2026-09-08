"""Output summarizer (two-tier, EnIGMA-style) to guard context length.

Tier 1: simple truncation/head-tail when output exceeds a char threshold.
Tier 2 (LM summarizer): reserved — wired in M3 alongside long tool outputs.
"""

from __future__ import annotations

from midnight.config import get_config


def simple_truncate(text: str, *, limit: int | None = None) -> str:
    """Head+tail truncation with an elision marker."""
    limit = limit or get_config().settings.max_tool_output_chars
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 2 :]
    elided = len(text) - len(head) - len(tail)
    return f"{head}\n... [{elided} chars elided] ...\n{tail}"


def summarize(text: str, *, limit: int | None = None) -> str:
    """v1 = simple truncation. LM summarizer added in M3."""
    return simple_truncate(text, limit=limit)
