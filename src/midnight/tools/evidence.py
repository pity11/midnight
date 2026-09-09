"""Structured, append-only evidence memory for long-running challenge lanes."""

from __future__ import annotations

import base64
import json
import shlex
from datetime import UTC, datetime

from midnight.env.ctf_environment import CTFEnvironment
from midnight.tools.registry import register_tool
from midnight.tools.summarizer import summarize

_KINDS = {"observation", "hypothesis", "disproved", "artifact", "next_step"}
_CONFIDENCE = {"low", "medium", "high"}


@register_tool(
    name="record_evidence",
    groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"],
)
def make_record_evidence(*, env: CTFEnvironment, current_expert: str, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def record_evidence(
        kind: str,
        summary: str,
        source: str,
        confidence: str = "medium",
    ) -> str:
        """Append one durable fact, hypothesis, failure, artifact, or next step.

        ``source`` identifies the real command, file, target response, or tool
        that supports the entry. Keep ``summary`` concise and never store a
        guess as an observation.
        """
        if kind not in _KINDS:
            raise ValueError(f"kind must be one of {sorted(_KINDS)}")
        if confidence not in _CONFIDENCE:
            raise ValueError(f"confidence must be one of {sorted(_CONFIDENCE)}")
        if not summary.strip() or len(summary) > 1200:
            raise ValueError("summary must contain 1 to 1200 characters")
        if not source.strip() or len(source) > 500:
            raise ValueError("source must contain 1 to 500 characters")
        entry = {
            "schema": "midnight-evidence/v1",
            "time": datetime.now(UTC).isoformat(timespec="seconds"),
            "expert": current_expert,
            "kind": kind,
            "confidence": confidence,
            "summary": summary.strip(),
            "source": source.strip(),
        }
        encoded = base64.b64encode(
            (json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n").encode()
        ).decode()
        evidence_path = f"{env.workdir.rstrip('/')}/evidence.jsonl"
        result = await env.exec(
            f"printf %s {shlex.quote(encoded)} | base64 -d >> {shlex.quote(evidence_path)}",
            timeout=15,
        )
        if not result.ok:
            return f"[error] could not record evidence: {result.stderr}"
        return f"recorded {kind} evidence"

    return record_evidence


@register_tool(
    name="read_evidence",
    groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"],
)
def make_read_evidence(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def read_evidence(kind: str = "", limit: int = 20) -> str:
        """Read recent structured evidence from prior turns or retry lanes."""
        if kind and kind not in _KINDS:
            raise ValueError(f"kind must be empty or one of {sorted(_KINDS)}")
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        if kind:
            evidence_path = f"{env.workdir.rstrip('/')}/evidence.jsonl"
            program = (
                f"import json,pathlib; p=pathlib.Path({evidence_path!r}); "
                f"k={kind!r}; n={limit}; "
                "rows=[x for x in p.read_text(errors='replace').splitlines() "
                "if x.strip() and json.loads(x).get('kind')==k]; print('\\n'.join(rows[-n:]))"
            )
            result = await env.exec(f"python3 -c {shlex.quote(program)}", timeout=15)
        else:
            evidence_path = shlex.quote(f"{env.workdir.rstrip('/')}/evidence.jsonl")
            result = await env.exec(
                f"test -f {evidence_path} && tail -n {limit} {evidence_path} || true",
                timeout=15,
            )
        return summarize(result.stdout or result.stderr or "(no recorded evidence)")

    return read_evidence
