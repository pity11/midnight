"""Classification node + routing edge.

``classify`` uses an LLM (with structured output) to decide the challenge type;
``route`` maps that type to the matching specialist node name.
"""

from __future__ import annotations

from typing import Literal, cast

from pydantic import BaseModel, Field

from midnight.models import build_llm
from midnight.state import ChallengeType, CTFState
from midnight.utils.logging import get_logger

log = get_logger(__name__)

_SPECIALIST_NODE = {
    "pwn": "pwn_specialist",
    "reverse": "reverse_specialist",
    "web": "web_specialist",
    "crypto": "crypto_specialist",
    "misc": "misc_specialist",
    "forensics": "forensics_specialist",
    "unknown": "misc_specialist",
}


class Classification(BaseModel):
    challenge_type: Literal["pwn", "reverse", "web", "crypto", "misc", "forensics", "unknown"] = (
        Field(description="the CTF challenge category")
    )
    reason: str = Field(description="one-sentence justification")


_CLASSIFY_PROMPT = """You are a CTF triage assistant. Classify the challenge into exactly one category:
- pwn: binary exploitation, memory corruption, remote service to exploit
- reverse: reverse engineering a binary to recover logic/flag
- web: web application exploitation
- crypto: cryptography puzzles
- misc: miscellaneous, scripting, jails
- forensics: file/network/memory forensics, steganography

Challenge name: {name}
Category hint (may be empty/unreliable): {hint}
Files: {files}
Description:
{description}

Respond with the category and a one-sentence reason."""


def make_classify_node():
    """Build the classify node (LLM structured output)."""
    llm = build_llm("classify")
    structured = llm.with_structured_output(Classification)

    async def classify(state: CTFState) -> dict:
        ch = state["challenge"]
        prompt = _CLASSIFY_PROMPT.format(
            name=ch.get("name", ""),
            hint=ch.get("category_hint") or "(none)",
            files=", ".join(p.split("/")[-1] for p in (ch.get("files") or [])) or "(none)",
            description=(ch.get("description") or "")[:2000],
        )
        try:
            result: Classification = await structured.ainvoke(prompt)
            ctype, reason = result.challenge_type, result.reason
        except Exception as exc:  # noqa: BLE001
            # fall back to the platform hint, then 'unknown'
            ctype = cast(ChallengeType, ch.get("category_hint") or "unknown")
            if ctype not in _SPECIALIST_NODE:
                ctype = "unknown"
            reason = f"classifier error ({exc}); fell back to hint"
        log.info("classified %s -> %s (%s)", ch.get("id"), ctype, reason)
        return {"challenge_type": ctype, "classify_reason": reason}

    return classify


def route(state: CTFState) -> str:
    """Conditional-edge function: pick the specialist node for the type."""
    return _SPECIALIST_NODE.get(state.get("challenge_type", "unknown"), "misc_specialist")
