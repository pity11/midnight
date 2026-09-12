from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import pytest

from midnight.tools.forensic_memory import forensic_record, render_retry_memory
from midnight.tools.shell import make_read_file, make_write_file


@dataclass
class _Result:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class _LocalEnv:
    def __init__(self, workdir: str) -> None:
        self.workdir = workdir

    async def exec(self, command: str, timeout: int = 120) -> _Result:
        process = await asyncio.create_subprocess_exec(
            "bash",
            "-c",
            command,
            cwd=self.workdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return _Result(
            exit_code=process.returncode or 0,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
        )


@pytest.mark.asyncio
async def test_read_file_tracks_hash_offsets_and_suppresses_covered_range(tmp_path) -> None:
    source = tmp_path / "evidence.log"
    source.write_text("alpha\nbeta\ngamma\n", encoding="utf-8")
    action = make_read_file(env=_LocalEnv(str(tmp_path)))

    first = await action.ainvoke({"path": str(source), "start_line": 2, "max_lines": 2})
    assert '"realpath"' in first
    assert '"sha256"' in first
    assert '"byte_start": 6' in first
    assert "00000002: beta" in first

    duplicate = await action.ainvoke(
        {"path": str(source), "start_line": 2, "max_lines": 2}
    )
    assert "MIDNIGHT_DUPLICATE_READ" in duplicate
    assert "00000002: beta" not in duplicate

    source.write_text("alpha\nchanged\ngamma\n", encoding="utf-8")
    changed = await action.ainvoke({"path": str(source), "start_line": 2, "max_lines": 2})
    assert "MIDNIGHT_DUPLICATE_READ" not in changed
    assert "00000002: changed" in changed


@pytest.mark.asyncio
async def test_forensic_write_requires_new_evidence_and_skips_identical_content(tmp_path) -> None:
    env = _LocalEnv(str(tmp_path))
    action = make_write_file(env=env, current_expert="forensics")
    target = tmp_path / "decoder.py"

    first = await action.ainvoke({"path": str(target), "content": "print(1)\n"})
    assert '"status": "written"' in first
    duplicate = await action.ainvoke({"path": str(target), "content": "print(1)\n"})
    assert "MIDNIGHT_DUPLICATE_WRITE" in duplicate
    blocked = await action.ainvoke({"path": str(target), "content": "print(2)\n"})
    assert "MIDNIGHT_WRITE_BLOCKED" in blocked
    assert target.read_text() == "print(1)\n"

    evidence = tmp_path / "new.log"
    evidence.write_text("new fact\n", encoding="utf-8")
    read = make_read_file(env=env)
    await read.ainvoke({"path": str(evidence)})
    revised = await action.ainvoke({"path": str(target), "content": "print(2)\n"})
    assert '"status": "written"' in revised
    assert target.read_text() == "print(2)\n"


def test_forensic_record_and_retry_memory_are_bounded_and_structured() -> None:
    result = _Result(
        exit_code=0,
        stdout="[detections]\n2026-01-01 login failed from 192.0.2.4\n" + "noise\n" * 100,
        stderr="",
    )
    record = forensic_record(tool="log_audit", source="/ctf/access.log", result=result)
    assert record["schema"] == "midnight-forensic-evidence/v1"
    assert record["status"] == "ok"
    assert len(record["findings"]) <= 32

    raw = "\n".join(
        [
            json.dumps(
                {
                    "schema": "midnight-evidence/v1",
                    "kind": "hypothesis",
                    "summary": "credential reuse",
                    "source": "line 9",
                }
            ),
            json.dumps(
                {
                    "schema": "midnight-evidence/v1",
                    "kind": "disproved",
                    "summary": "not SQL injection",
                    "source": "rule audit",
                }
            ),
            json.dumps(record),
        ]
    )
    memory = render_retry_memory(raw)
    assert "[HYPOTHESES]" in memory
    assert "[EXCLUDED ROUTES]" in memory
    assert "[NORMALIZED FORENSIC RECORDS]" in memory
    assert len(memory) <= 6000
