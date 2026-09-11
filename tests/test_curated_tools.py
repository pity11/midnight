from __future__ import annotations

import base64
from dataclasses import dataclass

import pytest

from midnight.config import get_config
from midnight.tools.advanced import (
    make_archive_extract,
    make_archive_password,
    make_hayabusa_timeline,
    make_jwt_analyze,
    make_kaitai_compile,
    make_qr_decode,
    make_rsa_attack,
    make_tinja_ssti,
    make_velocity_ssti,
)
from midnight.tools.category import (
    make_android_decompile,
    make_artifact_triage,
    make_disk_image_triage,
    make_evtx_triage,
    make_fenjing_ssti,
    make_filesystem_recover,
    make_fmtstr_probe,
    make_fmtstr_write_scan,
    make_image_compare,
    make_image_ocr,
    make_linux_ir_triage,
    make_memory_analyze,
    make_one_gadget,
    make_pcap_artifact_extract,
    make_pcap_export_objects,
    make_pcap_tls_recover,
    make_pcap_triage,
    make_pickle_build,
    make_pickle_policy_audit,
    make_pwn_crash_probe,
    make_pwn_ret2libc_target,
    make_pwn_rop_inventory,
    make_pyinstaller_extract,
    make_rsa_quickcheck,
    make_run_exploit,
    make_source_audit,
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


def test_run_exploit_is_shared_across_specialists() -> None:
    config = get_config()
    for expert in ("pwn", "reverse", "web", "crypto", "misc", "forensics"):
        assert "run_exploit" in config.tools[expert]


def test_pwn_and_pickle_deterministic_auditors_are_configured() -> None:
    config = get_config()
    assert "source_audit" in config.tools["pwn"]
    assert "pwn_crash_probe" in config.tools["pwn"]
    assert "pwn_rop_inventory" in config.tools["pwn"]
    assert "pwn_ret2libc_target" in config.tools["pwn"]
    assert "pickle_policy_audit" in config.tools["misc"]
    assert "pickle_policy_audit" in config.tools["forensics"]
    assert "pickle_build" in config.tools["misc"]


@pytest.mark.asyncio
async def test_pickle_policy_audit_checks_opcodes_and_local_validator() -> None:
    env = _Env()
    action = make_pickle_policy_audit(env=env)
    await action.ainvoke(
        {
            "source": "sandbox.py",
            "payload": "payload.pkl",
            "validator": "sandbox.py",
            "validator_function": "unpickle",
        }
    )
    command, timeout = env.calls[0]
    assert "pickletools.genops" in command
    assert "opcode 0x96 is BYTEARRAY8, not GETATTR" in command
    assert "dotted_name_resolution" in command
    assert "mapping_note" in command
    assert "version_note" in command
    assert "__globals__.__class__.get" in command
    assert "sandbox.py" in command
    assert "payload.pkl" in command
    assert timeout == 60

    with pytest.raises(ValueError, match="file or base64"):
        await action.ainvoke({"payload_format": "hex"})


@pytest.mark.asyncio
async def test_pickle_build_compiles_a_declarative_stack_program() -> None:
    env = _Env()
    action = make_pickle_build(env=env)
    operations = (
        '[{"op":"global","module":"allowed","name":"Root.mapping.get"},'
        '{"op":"string","value":"callable"},{"op":"call","count":1}]'
    )
    await action.ainvoke(
        {
            "operations_json": operations,
            "output": "payload.pkl",
            "validator": "sandbox.py",
        }
    )
    command, timeout = env.calls[0]
    assert "pickletools.dis" in command
    assert "final pickle stack depth must be 1" in command
    assert 'elif op == "call"' in command
    assert "Root.mapping.get" in command
    assert "payload.pkl" in command
    assert timeout == 60


@pytest.mark.asyncio
async def test_pwn_rop_inventory_extracts_offsets_and_gadgets() -> None:
    env = _Env()
    action = make_pwn_rop_inventory(env=env)
    await action.ainvoke(
        {"binary": "chall", "function_query": "vulnerable", "leaked_symbol": "CHOICE"}
    )
    command, timeout = env.calls[0]
    assert "candidate_saved_return_distance" in command
    assert "padding_invariant" in command
    assert "complete gadget text as semantics" in command
    assert "leaked_symbol_candidate" in command
    assert "ROPgadget" in command
    assert "PIE runtime address" in command
    assert timeout == 150

    with pytest.raises(ValueError, match="unsupported"):
        await action.ainvoke({"binary": "chall", "function_query": "x;id"})


@pytest.mark.asyncio
async def test_pwn_crash_probe_uses_batch_gdb_and_bounded_input() -> None:
    env = _Env()
    action = make_pwn_crash_probe(env=env)
    await action.ainvoke(
        {
            "binary": "chall binary",
            "menu_prefix": "3\n",
            "sentinel_offset": 400,
            "pattern_length": 512,
        }
    )
    command, timeout = env.calls[0]
    assert "gdb -q -nx -batch 'chall binary'" in command
    assert "midnight-crash-input" in command
    assert "cyclic_find" in command
    assert "sentinel=400" in command
    assert "static-fallback: runtime registers unavailable" in command
    assert "objdump -dC -Mintel" in command
    assert timeout == 40

    with pytest.raises(ValueError, match="pattern_length"):
        await action.ainvoke({"binary": "x", "pattern_length": 10})
    with pytest.raises(ValueError, match="function_query"):
        await action.ainvoke({"binary": "x", "function_query": "read; id"})


@pytest.mark.asyncio
async def test_pwn_ret2libc_target_is_bound_and_records_output() -> None:
    env = _Env()
    observed: list[str] = []
    action = make_pwn_ret2libc_target(
        env=env,
        state={"challenge": {"remote": "pwn-target:31337"}},
        observe_target_output=observed.append,
    )
    await action.ainvoke(
        {"binary": "/ctf/chall", "libc": "/ctf/libc.so.6", "offset": 88}
    )
    command, timeout = env.calls[0]
    assert "midnight-ret2libc.py" in command
    assert "--host pwn-target --port 31337" in command
    assert "--offset 88" in command
    assert timeout == 45
    assert observed == ["ok\n"]

    with pytest.raises(ValueError, match="offset"):
        await action.ainvoke(
            {"binary": "/ctf/chall", "libc": "/ctf/libc.so.6", "offset": 4}
        )


@pytest.mark.asyncio
async def test_qr_decode_uses_bounded_variants_and_verified_decoder() -> None:
    env = _Env()
    action = make_qr_decode(env=env)
    await action.ainvoke({"image": "recovered code.pbm"})
    command, timeout = env.calls[0]
    assert "'recovered code.pbm'" in command
    assert "-resize 800%" in command
    assert command.count("zbarimg") == 1
    assert timeout == 180


@pytest.mark.asyncio
async def test_archive_password_is_format_and_time_bounded() -> None:
    env = _Env()
    action = make_archive_password(env=env)
    await action.ainvoke({"archive": "evidence file.zip", "timeout_seconds": 45})
    command, timeout = env.calls[0]
    assert "timeout 45s fcrackzip" in command
    assert "'evidence file.zip'" in command
    assert "7z t" in command
    assert timeout == 75

    with pytest.raises(ValueError, match="between 10 and 300"):
        await action.ainvoke({"archive": "x.zip", "timeout_seconds": 301})


@pytest.mark.asyncio
async def test_tinja_is_target_bound_and_rate_limited() -> None:
    env = _Env()
    action = make_tinja_ssti(env=env, state={"challenge": {"remote": "web:8080"}})
    await action.ainvoke(
        {
            "url": "/render?name=test",
            "data": "name=test",
            "headers": "X-Test: one; Accept: text/html",
            "requests_per_second": 7,
        }
    )
    command, timeout = env.calls[0]
    assert "tinja url" in command
    assert "http://web:8080/render?name=test" in command
    assert "--ratelimit 7" in command
    assert timeout == 300

    with pytest.raises(ValueError, match="between 1 and 100"):
        await action.ainvoke({"requests_per_second": 101})


@pytest.mark.asyncio
async def test_velocity_ssti_is_target_bound_and_output_bounded() -> None:
    env = _Env()
    action = make_velocity_ssti(env=env, state={"challenge": {"remote": "velocity:1337"}})
    await action.ainvoke({"command": "ls /", "max_output_bytes": 256})
    command, timeout = env.calls[0]
    assert "python3 -c" in command
    assert "requests.post" in command
    assert timeout == 60

    with pytest.raises(ValueError, match="between 32 and 4096"):
        await action.ainvoke({"command": "id", "max_output_bytes": 5000})


@pytest.mark.asyncio
async def test_jwt_modes_are_narrow_and_scan_uses_target() -> None:
    env = _Env()
    action = make_jwt_analyze(env=env, state={"challenge": {"remote": "api:8000"}})
    token = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoidXNlciJ9.signature"
    await action.ainvoke({"token": token, "mode": "alg-none"})
    assert "-X a" in env.calls[0][0]

    await action.ainvoke({"token": token, "mode": "scan", "url": "/admin"})
    command, timeout = env.calls[1]
    assert "http://api:8000/admin" in command
    assert "Authorization: Bearer" in command
    assert "-M pb" in command
    assert timeout == 300

    with pytest.raises(ValueError, match="requires a local wordlist"):
        await action.ainvoke({"token": token, "mode": "crack"})


@pytest.mark.asyncio
async def test_rsa_attack_uses_offline_allowlist() -> None:
    env = _Env()
    action = make_rsa_attack(env=env)
    await action.ainvoke({"public_key": "public key.pem", "attack": "quick"})
    command, timeout = env.calls[0]
    assert "--attack wiener fermat smallq pollard_rho" in command
    assert "factordb" not in command
    assert "'public key.pem'" in command
    assert timeout == 315

    with pytest.raises(ValueError, match="offline allowlist"):
        await action.ainvoke({"public_key": "key.pem", "attack": "factordb"})


@pytest.mark.asyncio
async def test_hayabusa_resolves_paths_before_changing_directory() -> None:
    env = _Env()
    action = make_hayabusa_timeline(env=env)
    await action.ainvoke(
        {"path": "evtx logs", "output": "timeline out.csv", "directory": True}
    )
    command, timeout = env.calls[0]
    assert "src=$(realpath -- 'evtx logs')" in command
    assert "cd /opt/hayabusa" in command
    assert "dfir-timeline -d \"$src\"" in command
    assert timeout == 600


@pytest.mark.asyncio
async def test_kaitai_compile_limits_targets_and_quotes_paths() -> None:
    env = _Env()
    action = make_kaitai_compile(env=env)
    await action.ainvoke(
        {"specification": "custom protocol.ksy", "target": "python", "output_dir": "parser out"}
    )
    command, timeout = env.calls[0]
    assert "ksc -t python --outdir 'parser out' 'custom protocol.ksy'" in command
    assert timeout == 180

    with pytest.raises(ValueError, match="supported allowlist"):
        await action.ainvoke({"specification": "x.ksy", "target": "shell"})


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
async def test_rsa_quickcheck_is_offline_and_bounded() -> None:
    env = _Env()
    action = make_rsa_quickcheck(env=env)
    await action.ainvoke(
        {"n": "3233", "e": "17", "c": "2790", "p": "61", "fermat_iterations": 10}
    )
    command, timeout = env.calls[0]
    assert command.startswith("printf %s ")
    assert command.endswith(" | base64 -d | python3 -")
    assert timeout == 180

    with pytest.raises(ValueError, match="between 0 and 500000"):
        await action.ainvoke({"n": "1", "e": "3", "c": "1", "fermat_iterations": 500001})
    assert len(env.calls) == 1


@pytest.mark.asyncio
async def test_source_and_artifact_triage_quote_paths() -> None:
    source_env = _Env()
    source = make_source_audit(env=source_env)
    await source.ainvoke({"path": "source tree"})
    command, timeout = source_env.calls[0]
    assert "find 'source tree'" in command
    assert "grep -RInE" in command
    assert "--exclude=solve.py" in command
    assert "read_exact" in command
    assert timeout == 90

    artifact_env = _Env()
    artifact = make_artifact_triage(env=artifact_env)
    await artifact.ainvoke({"path": "evidence file.zip"})
    command, timeout = artifact_env.calls[0]
    assert "7z l -slt 'evidence file.zip'" in command
    assert "binwalk 'evidence file.zip'" in command
    assert timeout == 120


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
async def test_evtx_triage_validates_event_ids() -> None:
    env = _Env()
    action = make_evtx_triage(env=env)
    await action.ainvoke(
        {"path": "Security log.evtx", "output": "events out.xml", "event_ids": "4624,4688"}
    )
    command, timeout = env.calls[0]
    assert "evtx_dump 'Security log.evtx' > 'events out.xml'" in command
    assert "4624|4688" in command
    assert timeout == 600

    with pytest.raises(ValueError, match="comma-separated integers"):
        await action.ainvoke({"path": "x.evtx", "event_ids": "4624;id"})


@pytest.mark.asyncio
async def test_filesystem_recovery_requires_observed_inode() -> None:
    env = _Env()
    action = make_filesystem_recover(env=env)
    await action.ainvoke({"image": "disk image.dd", "offset_sectors": 2048})
    assert "fls -r -d -o 2048 'disk image.dd'" in env.calls[0][0]

    await action.ainvoke(
        {
            "image": "disk image.dd",
            "offset_sectors": 2048,
            "inode": "42-128-3",
            "output": "deleted file.bin",
        }
    )
    assert "icat -o 2048 'disk image.dd' 42-128-3 > 'deleted file.bin'" in env.calls[1][0]
    with pytest.raises(ValueError, match="copied from fls"):
        await action.ainvoke({"image": "disk.dd", "inode": "42;id"})


@pytest.mark.asyncio
async def test_run_exploit_binds_target_and_checks_script() -> None:
    env = _Env()
    action = make_run_exploit(
        env=env, state={"challenge": {"remote": "target-relay:31337"}}
    )
    await action.ainvoke({"script": "solve pwn.py", "mode": "target", "timeout_seconds": 90})
    command, timeout = env.calls[0]
    assert "python3 -m py_compile 'solve pwn.py'" in command
    assert "env REMOTE=1 HOST=target-relay PORT=31337 python3 'solve pwn.py'" in command
    assert "REMOTE=1 HOST=target-relay PORT=31337" in command
    assert timeout == 105

    await action.ainvoke({"script": "solve.py", "mode": "local"})
    assert "env LOCAL=1 python3 solve.py LOCAL=1" in env.calls[1][0]

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
async def test_pcap_object_export_is_protocol_bounded() -> None:
    env = _Env()
    action = make_pcap_export_objects(env=env)
    await action.ainvoke(
        {"capture": "traffic sample.pcap", "protocol": "http", "output_dir": "objects out"}
    )
    command, timeout = env.calls[0]
    assert "--export-objects 'http,objects out'" in command
    assert timeout == 300
    with pytest.raises(ValueError, match="protocol must be"):
        await action.ainvoke({"capture": "x.pcap", "protocol": "tls;id"})


@pytest.mark.asyncio
async def test_pcap_normalized_and_tls_recovery_tools_quote_paths() -> None:
    env = _Env()
    normalized = make_pcap_artifact_extract(env=env)
    await normalized.ainvoke(
        {"capture": "traffic sample.pcap", "protocol": "http", "output_dir": "safe out"}
    )
    command, timeout = env.calls[0]
    assert "'traffic sample.pcap' http 'safe out'" in command
    assert "artifact-" not in command
    assert timeout == 360
    with pytest.raises(ValueError, match="protocol must be"):
        await normalized.ainvoke({"capture": "x.pcap", "protocol": "tls;id"})

    tls = make_pcap_tls_recover(env=env)
    await tls.ainvoke({"capture": "tls sample.pcap", "output_dir": "tls out"})
    command, timeout = env.calls[1]
    assert "'tls sample.pcap' 'tls out'" in command
    assert timeout == 600


@pytest.mark.asyncio
async def test_image_ocr_quotes_source_and_bounds_work() -> None:
    env = _Env()
    action = make_image_ocr(env=env)
    await action.ainvoke({"image": "screen shot.png", "output_dir": "ocr out"})
    command, timeout = env.calls[0]
    assert "test -f 'screen shot.png'" in command
    assert "tesseract" in command
    assert timeout == 300


@pytest.mark.asyncio
async def test_archive_extract_quotes_paths_and_password() -> None:
    env = _Env()
    action = make_archive_extract(env=env)
    await action.ainvoke(
        {"archive": "host backup.zip", "output_dir": "host tree", "password": "known pass"}
    )
    command, timeout = env.calls[0]
    assert "'-pknown pass'" in command
    assert "'host backup.zip'" in command
    assert "-o'host tree'" in command
    assert timeout == 600
    with pytest.raises(ValueError, match="dedicated path"):
        await action.ainvoke({"archive": "host.zip", "output_dir": "/ctf"})
    with pytest.raises(ValueError, match="dedicated path"):
        await action.ainvoke({"archive": "host.zip", "output_dir": "../escape"})


@pytest.mark.asyncio
async def test_linux_ir_triage_quotes_root_and_report() -> None:
    env = _Env()
    action = make_linux_ir_triage(env=env)
    await action.ainvoke({"root": "host tree", "output": "ir report.json"})
    command, timeout = env.calls[0]
    assert "'host tree' 'ir report.json'" in command
    assert timeout == 600


@pytest.mark.asyncio
async def test_image_compare_quotes_inputs_and_output() -> None:
    env = _Env()
    compare = make_image_compare(env=env)
    await compare.ainvoke(
        {"left": "before image.png", "right": "after image.png", "output_dir": "diff out"}
    )
    command, timeout = env.calls[0]
    assert "'before image.png' 'after image.png' 'diff out'" in command
    assert timeout == 180


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
