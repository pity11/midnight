from __future__ import annotations

import pytest

from midnight.env.container_manager import ExecResult
from midnight.env.ctf_environment import CTFEnvironment


@pytest.mark.asyncio
async def test_challenge_file_copy_preserves_declared_subdirectories(monkeypatch):
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, timeout=None):
        calls.append(args)
        return ExecResult(0, "", "")

    monkeypatch.setattr("midnight.env.ctf_environment._run", fake_run)
    environment = CTFEnvironment(container_id="solver", workdir="/ctf")
    challenge = {
        "files": ["/host/bundle/files/glibc/libc.so.6"],
        "file_destinations": {
            "/host/bundle/files/glibc/libc.so.6": "glibc/libc.so.6"
        },
    }

    await environment.copy_challenge_files(challenge)

    assert calls[0][-1] == "mkdir -p -- /ctf/glibc"
    assert calls[1] == (
        "docker",
        "cp",
        "/host/bundle/files/glibc/libc.so.6",
        "solver:/ctf/glibc/libc.so.6",
    )


@pytest.mark.asyncio
async def test_challenge_file_copy_rejects_parent_traversal():
    environment = CTFEnvironment(container_id="solver", workdir="/ctf")
    challenge = {
        "files": ["/host/flag"],
        "file_destinations": {"/host/flag": "../flag"},
    }

    with pytest.raises(ValueError, match="unsafe challenge attachment destination"):
        await environment.copy_challenge_files(challenge)
