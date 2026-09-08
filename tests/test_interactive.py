"""Integration test for the IAT interactive session (requires Docker).

Skipped automatically when docker is unavailable. Drives an interactive
``python3`` REPL inside a throwaway container and checks multi-turn I/O works.
"""

import asyncio
import shutil
import subprocess
import uuid

import pytest

DOCKER = shutil.which("docker")
IMAGE = "midnight/misc:latest"


def _image_exists() -> bool:
    if not DOCKER:
        return False
    r = subprocess.run([DOCKER, "image", "inspect", IMAGE], capture_output=True)
    return r.returncode == 0


pytestmark = pytest.mark.skipif(
    not _image_exists(), reason="docker or midnight/misc:latest not available"
)


def test_interactive_python_repl():
    from midnight.tools.interactive.session import DockerInteractiveSession

    name = f"ctf-iat-test-{uuid.uuid4().hex[:8]}"
    cid = subprocess.run(
        [DOCKER, "run", "-d", "--name", name, IMAGE],
        capture_output=True, text=True,
    ).stdout.strip()
    assert cid, "failed to start container"

    async def run():
        sess = DockerInteractiveSession(
            launch_cmd="python3 -u -i",
            prompt=">>>",
            container_id=cid,
            workdir="/ctf",
        )
        await sess.start()
        out1 = await sess.send("print(6*7)")
        out2 = await sess.send("x = 100; print(x + 23)")
        await sess.close()
        return out1, out2

    try:
        out1, out2 = asyncio.run(run())
        assert "42" in out1, f"got: {out1!r}"
        assert "123" in out2, f"got: {out2!r}"
    finally:
        subprocess.run([DOCKER, "rm", "-f", cid or name], capture_output=True)


def test_env_open_session():
    """CTFEnvironment.open_session should return a live, usable session."""
    from midnight.env.ctf_environment import CTFEnvironment

    name = f"ctf-iat-open-{uuid.uuid4().hex[:8]}"
    cid = subprocess.run(
        [DOCKER, "run", "-d", "--name", name, IMAGE],
        capture_output=True, text=True,
    ).stdout.strip()
    assert cid

    async def run():
        env = CTFEnvironment(container_id=cid, workdir="/ctf")
        sess = await env.open_session("python3 -u -i", prompt=">>>")
        out = await sess.send("print(2**10)")
        await sess.close()
        return out

    try:
        out = asyncio.run(run())
        assert "1024" in out, f"got: {out!r}"
    finally:
        subprocess.run([DOCKER, "rm", "-f", cid or name], capture_output=True)
