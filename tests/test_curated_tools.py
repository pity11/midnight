from __future__ import annotations

from dataclasses import dataclass

import pytest

from midnight.tools.category import (
    make_fenjing_ssti,
    make_one_gadget,
    make_pyinstaller_extract,
    make_stego_scan,
    make_xor_analyze,
)


@dataclass
class _Result:
    stdout: str = "ok"
    stderr: str = ""
    exit_code: int = 0


class _Env:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    async def exec(self, command: str, timeout: int = 120) -> _Result:
        self.calls.append((command, timeout))
        return _Result()


@pytest.mark.asyncio
async def test_fenjing_uses_challenge_remote_and_quotes_inputs() -> None:
    env = _Env()
    action = make_fenjing_ssti(
        env=env, state={"challenge": {"remote": "challenge:8080"}}
    )
    result = await action.ainvoke(
        {
            "url": "/render",
            "mode": "crack",
            "method": "post",
            "inputs": "name,msg",
            "command": "cat /flag",
        }
    )
    command, timeout = env.calls[0]
    assert "fenjing crack" in command
    assert "http://challenge:8080/render" in command
    assert "--inputs name,msg" in command
    assert "--exec-cmd 'cat /flag'" in command
    assert timeout == 300
    assert "[exit=0]" in result


@pytest.mark.asyncio
async def test_fenjing_rejects_unknown_mode_without_execution() -> None:
    env = _Env()
    action = make_fenjing_ssti(env=env, state={"challenge": {"remote": "x:80"}})
    with pytest.raises(ValueError, match="mode"):
        await action.ainvoke({"mode": "shell"})
    assert env.calls == []


@pytest.mark.asyncio
async def test_one_gadget_rejects_unbounded_level() -> None:
    env = _Env()
    action = make_one_gadget(env=env)
    with pytest.raises(ValueError, match="level"):
        await action.ainvoke({"libc": "libc.so.6", "level": 99})


@pytest.mark.asyncio
async def test_xor_analyze_builds_a_narrow_command() -> None:
    env = _Env()
    action = make_xor_analyze(env=env)
    await action.ainvoke(
        {
            "path": "cipher data.bin",
            "key_length": 7,
            "most_frequent_hex": "20",
            "known_plaintext": "flag{",
        }
    )
    command, timeout = env.calls[0]
    assert "--key-length 7" in command
    assert "--char 20" in command
    assert "--known-plaintext 'flag{'" in command
    assert "'cipher data.bin'" in command
    assert timeout == 180


@pytest.mark.asyncio
async def test_extract_and_stego_tools_quote_paths() -> None:
    extract_env = _Env()
    extract = make_pyinstaller_extract(env=extract_env)
    await extract.ainvoke({"binary": "packed app.exe", "info_only": True})
    assert "--info 'packed app.exe'" in extract_env.calls[0][0]

    stego_env = _Env()
    stego = make_stego_scan(env=stego_env)
    await stego.ainvoke({"path": "image file.png", "extract_channel": "1b,rgb,lsb"})
    assert "--extract 1b,rgb,lsb 'image file.png'" in stego_env.calls[0][0]
