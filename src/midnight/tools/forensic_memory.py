"""Compact, durable evidence records for forensic tool output and retries."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from midnight.tools.summarizer import simple_truncate

if TYPE_CHECKING:
    from midnight.env.ctf_environment import CTFEnvironment

_HIGH_VALUE = re.compile(
    r"(?:\b(?:event|stream|frame|packet|process|user|account|host|source|destination|"
    r"timestamp|time|ioc|indicator|detect|alert|attack|error|fail|denied|login|"
    r"powershell|cmd\.exe|webshell|reverse.shell|persistence|mysql|dns|http|tcp|"
    r"sha256|artifact|report|path|line|offset|protocol)\b|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|\b20\d\d[-/]\d\d[-/]\d\d\b)",
    re.IGNORECASE,
)


def _compact_findings(text: str, *, limit: int = 32) -> list[str]:
    """Select bounded, de-duplicated evidence lines without an LLM call."""
    lines = [" ".join(line.strip().split()) for line in text.splitlines() if line.strip()]
    prioritized = [line for line in lines if _HIGH_VALUE.search(line)]
    candidates = [*prioritized, *lines[:12], *lines[-8:]]
    findings: list[str] = []
    seen: set[str] = set()
    for line in candidates:
        rendered = simple_truncate(line, limit=360)
        signature = rendered.casefold()
        if signature in seen:
            continue
        seen.add(signature)
        findings.append(rendered)
        if len(findings) >= limit:
            break
    return findings


def forensic_record(*, tool: str, source: str, result: Any) -> dict[str, Any]:
    """Normalize a forensic command result into a short evidence record."""
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    exit_code = getattr(result, "exit_code", "?")
    raw = stdout + (f"\n[stderr]\n{stderr}" if stderr else "")
    return {
        "schema": "midnight-forensic-evidence/v1",
        "time": datetime.now(UTC).isoformat(timespec="seconds"),
        "tool": tool,
        "source": simple_truncate(" ".join(source.split()), limit=500),
        "status": "ok" if exit_code == 0 else "error",
        "exit_code": exit_code,
        "output_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "output_chars": len(raw),
        "findings": _compact_findings(raw),
    }


async def compact_forensic_result(
    *, env: CTFEnvironment, tool: str, source: str, result: Any
) -> str:
    """Persist and return only normalized evidence, never the full tool dump."""
    record = forensic_record(tool=tool, source=source, result=result)
    encoded = base64.b64encode(
        (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode()
    ).decode()
    workdir = str(getattr(env, "workdir", "/ctf"))
    evidence_path = f"{workdir.rstrip('/')}/forensic-evidence.jsonl"
    persisted = await env.exec(
        f"printf %s {shlex.quote(encoded)} | base64 -d >> {shlex.quote(evidence_path)}",
        timeout=15,
    )
    if not getattr(persisted, "ok", False):
        record["persistence"] = "failed"
    return json.dumps(record, ensure_ascii=False, indent=2)


def render_retry_memory(raw: str, *, char_limit: int = 6000) -> str:
    """Render durable JSONL evidence as hypotheses/facts/questions for a retry."""
    buckets: dict[str, list[str]] = {
        "observations": [],
        "hypotheses": [],
        "disproved": [],
        "artifacts": [],
        "next_questions": [],
        "forensic_records": [],
        "pwn_executions": [],
    }
    seen: set[str] = set()

    def add(bucket: str, value: str) -> None:
        value = " ".join(value.split())
        if not value or value.casefold() in seen:
            return
        seen.add(value.casefold())
        buckets[bucket].append(simple_truncate(value, limit=520))

    for line in raw.splitlines():
        try:
            item = json.loads(line)
        except (TypeError, ValueError):
            continue
        schema = item.get("schema")
        if schema == "midnight-evidence/v1":
            kind = item.get("kind")
            bucket = {
                "observation": "observations",
                "hypothesis": "hypotheses",
                "disproved": "disproved",
                "artifact": "artifacts",
                "next_step": "next_questions",
            }.get(kind)
            if bucket:
                add(bucket, f"{item.get('summary', '')} [source: {item.get('source', '?')}]")
        elif schema == "midnight-forensic-evidence/v1":
            findings = item.get("findings") or []
            excerpt = "; ".join(str(value) for value in findings[:6])
            add(
                "forensic_records",
                f"{item.get('tool', '?')} on {item.get('source', '?')} "
                f"({item.get('status', '?')}, sha256={item.get('output_sha256', '?')}): {excerpt}",
            )
        elif schema == "midnight-pwn-execution/v1":
            findings = item.get("findings") or []
            excerpt = "; ".join(str(value) for value in findings[:4])
            add(
                "pwn_executions",
                f"{item.get('mode', '?')} {item.get('script', '?')} "
                f"script_sha256={item.get('script_sha256', '?')} "
                f"status={item.get('status', '?')} exit={item.get('exit_code', '?')}: "
                f"{excerpt}",
            )

    headings = (
        ("CONFIRMED OBSERVATIONS", "observations"),
        ("HYPOTHESES", "hypotheses"),
        ("EXCLUDED ROUTES", "disproved"),
        ("VERIFIED ARTIFACTS", "artifacts"),
        ("OPEN QUESTIONS / NEXT CHECKS", "next_questions"),
        ("NORMALIZED FORENSIC RECORDS", "forensic_records"),
        ("PWN EXECUTION HISTORY", "pwn_executions"),
    )
    sections = []
    for heading, bucket in headings:
        values = buckets[bucket][-8:]
        if values:
            sections.append(f"[{heading}]\n" + "\n".join(f"- {value}" for value in values))
    return simple_truncate("\n\n".join(sections), limit=char_limit) if sections else ""


async def read_retry_memory(env: CTFEnvironment) -> str:
    """Read bounded durable evidence and convert it to retry-only memory."""
    workdir = shlex.quote(str(getattr(env, "workdir", "/ctf")).rstrip("/"))
    result = await env.exec(
        "for name in evidence.jsonl forensic-evidence.jsonl pwn-executions.jsonl; do "
        f"test -f {workdir}/$name && tail -n 24 {workdir}/$name; "
        "done",
        timeout=15,
    )
    return render_retry_memory(str(getattr(result, "stdout", "") or ""))
