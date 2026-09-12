"""Compact, durable execution records for autonomous Pwn retries."""

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


_META = re.compile(
    r"^\[MIDNIGHT_EXPLOIT_META\] mode=(local|target) "
    r"script_sha256=([0-9a-f]{64})$",
    re.MULTILINE,
)
_FLAG = re.compile(r"[A-Za-z0-9_]+\{[^}\r\n]+\}")
_FAILURE = re.compile(
    r"(?:traceback|syntaxerror|exception|error|failed|failure|timeout|timed out|"
    r"segmentation fault|sigsegv|brokenpipe|eoferror|no flag|assert)",
    re.IGNORECASE,
)


def _status(exit_code: object, raw: str, *, mode: str) -> str:
    lowered = raw.lower()
    if "[midnight_duplicate_exploit]" in lowered:
        return "duplicate_blocked"
    if "syntaxerror" in lowered or "py_compile" in lowered and "error" in lowered:
        return "compile_error"
    if "segmentation fault" in lowered or "sigsegv" in lowered:
        return "crash"
    if "timeout" in lowered or exit_code == 124:
        return "timeout"
    if "brokenpipe" in lowered or "eoferror" in lowered:
        return "io_error"
    if "no flag" in lowered:
        return "no_flag"
    if mode == "local" and exit_code == 0:
        if "[midnight_local_control_ok]" in lowered:
            return "local_verified"
        return "completed_unverified"
    if mode == "target" and exit_code == 0 and _FLAG.search(raw):
        return "target_flag_observed"
    return "completed" if exit_code == 0 else "error"


def _findings(raw: str, *, limit: int = 12) -> list[str]:
    lines = [" ".join(line.split()) for line in raw.splitlines() if line.strip()]
    candidates = [line for line in lines if _FAILURE.search(line)]
    candidates.extend(lines[-6:])
    findings: list[str] = []
    seen: set[str] = set()
    for line in candidates:
        redacted = _FLAG.sub("<redacted-flag>", line)
        rendered = simple_truncate(redacted, limit=360)
        signature = rendered.casefold()
        if signature in seen:
            continue
        seen.add(signature)
        findings.append(rendered)
        if len(findings) >= limit:
            break
    return findings


def pwn_execution_record(*, script: str, mode: str, result: Any) -> dict[str, Any]:
    """Normalize one exploit run without persisting raw target output or flags."""
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    exit_code = getattr(result, "exit_code", "?")
    raw = stdout + (f"\n[stderr]\n{stderr}" if stderr else "")
    meta = _META.search(raw)
    script_sha256 = meta.group(2) if meta else "unknown"
    effective_mode = meta.group(1) if meta else mode
    return {
        "schema": "midnight-pwn-execution/v1",
        "time": datetime.now(UTC).isoformat(timespec="seconds"),
        "script": simple_truncate(" ".join(script.split()), limit=300),
        "script_sha256": script_sha256,
        "mode": effective_mode,
        "status": _status(exit_code, raw, mode=effective_mode),
        "exit_code": exit_code,
        "output_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "output_chars": len(raw),
        "findings": _findings(raw),
    }


async def persist_pwn_execution(
    *, env: CTFEnvironment, script: str, mode: str, result: Any
) -> dict[str, Any]:
    """Append one bounded Pwn execution record to retry-visible memory."""
    record = pwn_execution_record(script=script, mode=mode, result=result)
    encoded = base64.b64encode(
        (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode()
    ).decode()
    path = f"{str(getattr(env, 'workdir', '/ctf')).rstrip('/')}/pwn-executions.jsonl"
    persisted = await env.exec(
        f"printf %s {shlex.quote(encoded)} | base64 -d >> {shlex.quote(path)}",
        timeout=15,
    )
    persisted_ok = getattr(
        persisted,
        "ok",
        getattr(persisted, "exit_code", 1) == 0,
    )
    if not persisted_ok:
        record["persistence"] = "failed"
    return record
