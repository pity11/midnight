"""Integration tests for the retry/fallback loop (requires Docker + misc image).

Uses the stub model. Two scenarios:
  1. happy path: correct flag is found and accepted on the first attempt.
  2. reject path: the decoy flag is rejected by the oracle; the graph retries
     up to max_attempts, blacklists the decoy, and finally reports failed.
"""

import asyncio
import os
import shutil
import subprocess

import pytest

os.environ.setdefault("MIDNIGHT_MODELS_FILE", "models.stub.yaml")

DOCKER = shutil.which("docker")
IMAGE = "midnight/misc:latest"
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def _image_exists() -> bool:
    if not DOCKER:
        return False
    return subprocess.run([DOCKER, "image", "inspect", IMAGE], capture_output=True).returncode == 0


pytestmark = pytest.mark.skipif(
    not _image_exists(), reason="docker / misc image not available"
)


def _run_challenge(cid: str):
    from midnight.interfaces.local_mock import LocalDirProvider, ManualSubmitter
    from midnight.graph.main_graph import build_main_graph
    from midnight.state import initial_state

    async def go():
        p = LocalDirProvider(FIXTURES)
        s = ManualSubmitter(FIXTURES)
        g = build_main_graph(provider=p, submitter=s)
        ch = await p.fetch(cid)
        return await g.ainvoke(initial_state(ch), config={"recursion_limit": 100})

    return asyncio.run(go())


def test_happy_path_solves_first_attempt():
    final = _run_challenge("sanity_misc")
    assert final.get("status") == "solved"
    assert final.get("flag") == "flag{hello_midnight}"
    assert final.get("attempt") == 1  # no retry needed


def test_reject_path_retries_then_fails():
    final = _run_challenge("retry_reject")
    # oracle rejects the decoy every time; loop exhausts and reports failure
    assert final.get("status") == "failed"
    assert "flag{decoy_wrong}" in (final.get("rejected_flags") or [])
    # attempts should have hit the configured cap
    from midnight.config import get_config
    assert final.get("attempt") == get_config().settings.max_attempts
