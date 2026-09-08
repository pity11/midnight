"""Flag extraction and validation utilities.

Centralizes the 'trust only real tool output' rule: flags are extracted via
regex from text, never taken from an LLM's self-narration.
"""

from __future__ import annotations

import re
from typing import Optional

from midnight.config import get_config


def flag_pattern(flag_format: Optional[str] = None) -> re.Pattern[str]:
    """Compile the flag regex, preferring a per-challenge override."""
    pattern = flag_format or get_config().settings.flag_regex
    return re.compile(pattern)


def extract_flags(text: str, *, flag_format: Optional[str] = None) -> list[str]:
    """Extract all candidate flags from text, de-duplicated, order preserved."""
    if not text:
        return []
    pat = flag_pattern(flag_format)
    seen: set[str] = set()
    out: list[str] = []
    for m in pat.findall(text):
        # findall may return tuples if the regex has groups; normalize to str
        val = m if isinstance(m, str) else (m[0] if m else "")
        if val and val not in seen:
            seen.add(val)
            out.append(val)
    return out


def looks_like_flag(text: str, *, flag_format: Optional[str] = None) -> bool:
    return bool(flag_pattern(flag_format).search(text or ""))
