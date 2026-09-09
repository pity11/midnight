from __future__ import annotations

import base64
from dataclasses import dataclass

import pytest

from midnight.tools.evidence import make_read_evidence, make_record_evidence


@dataclass
class _Result:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class _Env:
    def __init__(self, results: list[_Result] | None = None) -> None:
        self.workdir = "/ctf"
        self.calls: list[tuple[str, int]] = []
        self.results = list(results or [_Result()])

    async def exec(self, command: str, timeout: int = 120) -> _Result:
        self.calls.append((command, timeout))
        return self.results.pop(0) if self.results else _Result()


@pytest.mark.asyncio
async def test_record_evidence_appends_safe_json() -> None:
    env = _Env()
    action = make_record_evidence(env=env, current_expert="pwn")
    assert (
        await action.ainvoke(
            {
                "kind": "disproved",
                "summary": "offset 72 does not control RIP; $(touch /tmp/no)",
                "source": "gdb_tool info registers",
                "confidence": "high",
            }
        )
        == "recorded disproved evidence"
    )
    command, timeout = env.calls[0]
    encoded = command.split("printf %s ", 1)[1].split(" |", 1)[0].strip("'")
    payload = base64.b64decode(encoded).decode()
    assert '"kind": "disproved"' in payload
    assert "$(touch /tmp/no)" in payload
    assert "$(touch /tmp/no)" not in command
    assert timeout == 15


@pytest.mark.asyncio
async def test_evidence_validation_fails_before_execution() -> None:
    env = _Env()
    action = make_record_evidence(env=env, current_expert="web")
    with pytest.raises(ValueError, match="kind"):
        await action.ainvoke({"kind": "guess", "summary": "x", "source": "y"})
    assert env.calls == []


@pytest.mark.asyncio
async def test_read_evidence_bounds_and_filters() -> None:
    env = _Env([_Result(stdout='{"kind":"artifact"}\n')])
    action = make_read_evidence(env=env)
    result = await action.ainvoke({"kind": "artifact", "limit": 5})
    assert '"kind":"artifact"' in result
    assert "json.loads" in env.calls[0][0]

    with pytest.raises(ValueError, match="between 1 and 100"):
        await action.ainvoke({"limit": 101})
