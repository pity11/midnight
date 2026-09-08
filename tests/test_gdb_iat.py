"""Integration test for gdb_tool IAT against the pwn image (requires Docker).

Compiles nothing here; relies on the crackme binary built into the fixture by
the build step. Drives gdb across turns and checks we can disassemble main.
"""

import asyncio
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

DOCKER = shutil.which("docker")
IMAGE = "midnight/pwn:latest"
ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "tests" / "fixtures" / "crackme_re" / "files" / "chall"


def _image_exists() -> bool:
    if not DOCKER:
        return False
    r = subprocess.run([DOCKER, "image", "inspect", IMAGE], capture_output=True)
    return r.returncode == 0


pytestmark = pytest.mark.skipif(
    not (_image_exists() and BINARY.exists()),
    reason="docker / pwn image / crackme binary not available",
)


def test_gdb_tool_disassembles():
    from midnight.env.ctf_environment import CTFEnvironment
    from midnight.tools.interactive.gdb_tool import make_gdb_tool

    name = f"ctf-gdb-test-{uuid.uuid4().hex[:8]}"
    cid = subprocess.run(
        [DOCKER, "run", "-d", "--name", name, "--cap-add", "SYS_PTRACE", IMAGE],
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert cid

    async def run():
        # copy the binary in
        subprocess.run([DOCKER, "cp", str(BINARY), f"{cid}:/ctf/chall"], check=True)
        env = CTFEnvironment(container_id=cid, workdir="/ctf")
        gdb_tool = make_gdb_tool(env=env)
        # first call loads the binary, then disassemble main
        await gdb_tool.ainvoke({"command": "file ./chall", "binary": "./chall"})
        out = await gdb_tool.ainvoke({"command": "info functions main"})
        return out

    try:
        out = asyncio.run(run())
        assert "main" in out.lower(), f"got: {out!r}"
    finally:
        subprocess.run([DOCKER, "rm", "-f", cid or name], capture_output=True)
