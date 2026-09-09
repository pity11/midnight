from __future__ import annotations

import base64
from dataclasses import dataclass

import pytest

from midnight.tools.category import (
    make_android_decompile,
    make_disk_image_triage,
    make_fenjing_ssti,
    make_fmtstr_probe,
    make_fmtstr_write_scan,
    make_memory_analyze,
    make_one_gadget,
    make_pcap_triage,
    make_pyinstaller_extract,
    make_run_exploit,
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


@pytest.mark.asyncio
async def test_android_decompile_quotes_artifact_and_output() -> None:
    env = _Env()
    action = make_android_decompile(env=env)
    await action.ainvoke(
        {"artifact": "sample app.apk", "output_dir": "decoded sources", "resources": False}
    )
    command, timeout = env.calls[0]
    assert "jadx --output-dir 'decoded sources' --no-res 'sample app.apk'" in command
    assert timeout == 600


@pytest.mark.asyncio
async def test_memory_analyze_accepts_only_named_plugins() -> None:
    env = _Env()
    action = make_memory_analyze(env=env)
    await action.ainvoke(
        {"image": "memory dump.raw", "plugin": "windows.pslist", "output_dir": "vol out"}
    )
    command, timeout = env.calls[0]
    assert "vol -q -f 'memory dump.raw' -o 'vol out' windows.pslist" in command
    assert timeout == 600

    with pytest.raises(ValueError, match="plugin"):
        await action.ainvoke({"image": "memory.raw", "plugin": "windows.pslist;id"})
    assert len(env.calls) == 1


@pytest.mark.asyncio
async def test_disk_triage_validates_offset_and_quotes_image() -> None:
    env = _Env()
    action = make_disk_image_triage(env=env)
    await action.ainvoke({"image": "disk image.dd", "offset_sectors": 2048})
    command, timeout = env.calls[0]
    assert "mmls 'disk image.dd'" in command
    assert "fls -r -o 2048 'disk image.dd'" in command
    assert timeout == 300

    with pytest.raises(ValueError, match="non-negative"):
        await action.ainvoke({"image": "disk.dd", "offset_sectors": -1})


@pytest.mark.asyncio
async def test_run_exploit_binds_target_and_checks_script() -> None:
    env = _Env()
    action = make_run_exploit(
        env=env, state={"challenge": {"remote": "target-relay:31337"}}
    )
    await action.ainvoke({"script": "solve pwn.py", "mode": "target", "timeout_seconds": 90})
    command, timeout = env.calls[0]
    assert "python3 -m py_compile 'solve pwn.py'" in command
    assert "REMOTE=1 HOST=target-relay PORT=31337" in command
    assert timeout == 105

    with pytest.raises(ValueError, match="between 1 and 600"):
        await action.ainvoke({"timeout_seconds": 999})


@pytest.mark.asyncio
async def test_pcap_triage_and_follow_stream_quote_inputs() -> None:
    env = _Env()
    action = make_pcap_triage(env=env)
    await action.ainvoke({"capture": "traffic sample.pcap", "display_filter": "http.request"})
    command, timeout = env.calls[0]
    assert "capinfos 'traffic sample.pcap'" in command
    assert "-Y http.request" in command
    assert timeout == 300

    await action.ainvoke({"capture": "traffic sample.pcap", "follow_tcp_stream": 3})
    assert "follow,tcp,ascii,3" in env.calls[1][0]

    with pytest.raises(ValueError, match="non-negative"):
        await action.ainvoke({"capture": "x.pcap", "follow_tcp_stream": -2})


@pytest.mark.asyncio
async def test_fmtstr_probe_binds_target_and_bounds_indices() -> None:
    env = _Env()
    action = make_fmtstr_probe(env=env, state={"challenge": {"remote": "relay:4444"}})
    await action.ainvoke(
        {"mode": "target", "prompt": "input: ", "start_index": 4, "end_index": 12}
    )
    command, timeout = env.calls[0]
    assert "python3 -" in command
    encoded = command.split("printf %s ", 1)[1].split(" |", 1)[0]
    program = base64.b64decode(encoded).decode()
    assert "remote('relay', 4444)" in program
    assert "range(4, 13)" in program
    assert timeout == 45

    with pytest.raises(ValueError, match="within 1..100"):
        await action.ainvoke({"mode": "target", "start_index": 1, "end_index": 101})


@pytest.mark.asyncio
async def test_fmtstr_write_scan_is_target_bound_and_bounded() -> None:
    env = _Env()
    action = make_fmtstr_write_scan(
        env=env, state={"challenge": {"remote": "relay:4444"}}
    )
    await action.ainvoke(
        {"value": 0xBEEF, "mode": "remote", "start_index": 5, "end_index": 9}
    )
    command, timeout = env.calls[0]
    encoded = command.split("printf %s ", 1)[1].split(" |", 1)[0]
    program = base64.b64decode(encoded).decode()
    assert "remote('relay', 4444)" in program
    assert "range(5, 10)" in program
    assert "%{48879}c%{index}$hn" in program
    assert timeout == 180

    with pytest.raises(ValueError, match="at most 40"):
        await action.ainvoke({"value": 1, "start_index": 1, "end_index": 41})
