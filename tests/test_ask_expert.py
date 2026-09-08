"""Integration test for M3.5 cross-expert delegation (ask_expert / run_helper).

Requires Docker + the misc image. Uses the stub model so the helper specialist
deterministically cats the workdir and finds a flag, proving the delegation
returns a result that the caller could consume.
"""

import asyncio
import os
import shutil
import subprocess
import uuid

import pytest

DOCKER = shutil.which("docker")
IMAGE = "midnight/misc:latest"

os.environ.setdefault("MIDNIGHT_MODELS_FILE", "models.stub.yaml")


def _image_exists() -> bool:
    if not DOCKER:
        return False
    return subprocess.run([DOCKER, "image", "inspect", IMAGE], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(
    not _image_exists(), reason="docker / misc image not available"
)


def test_escalation_guard_blocks_cycle_and_depth():
    from midnight.tools.ask_expert import check_escalation

    assert check_escalation(current_expert="web", target_type="pwn", depth=0, stack=[], max_depth=2).ok
    assert not check_escalation(current_expert="pwn", target_type="web", depth=1, stack=["web"], max_depth=2).ok
    assert not check_escalation(current_expert="web", target_type="pwn", depth=2, stack=[], max_depth=2).ok


def test_run_helper_solves_subtask_in_same_container():
    from midnight.env.ctf_environment import CTFEnvironment
    from midnight.graph.helper import make_run_helper
    from midnight.state import initial_state

    name = f"ctf-helper-test-{uuid.uuid4().hex[:8]}"
    cid = subprocess.run(
        [DOCKER, "run", "-d", "--name", name, IMAGE],
        capture_output=True, text=True,
    ).stdout.strip()
    assert cid

    async def run():
        # plant a flag file in the shared container
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                [DOCKER, "exec", cid, "bash", "-c", "echo 'flag{delegated_ok}' > /ctf/note.txt"],
                check=True,
            ),
        )
        env = CTFEnvironment(container_id=cid, workdir="/ctf")
        collected: list[str] = []
        st = initial_state(
            {"id": "deleg", "name": "deleg", "description": "", "files": [],
             "flag_format": r"flag\{[^}]+\}"}
        )
        run_helper = make_run_helper(base_state=st, record_flag=lambda f: collected.append(f))
        result = await run_helper(
            target_type="misc",
            subtask="Read the files in the workdir and report any flag you find.",
            env=env, depth=1, stack=["web"],
        )
        return result, collected

    try:
        result, collected = asyncio.run(run())
        assert "flag{delegated_ok}" in result or "flag{delegated_ok}" in collected, \
            f"result={result!r} collected={collected!r}"
    finally:
        subprocess.run([DOCKER, "rm", "-f", cid or name], capture_output=True)
