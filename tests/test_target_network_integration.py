"""Docker integration test for fixed-destination target-only egress."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import uuid

import pytest

from midnight.env.container_manager import ContainerManager
from midnight.env.ctf_environment import CTFEnvironment

DOCKER = shutil.which("docker")


def _docker_ready() -> bool:
    if not DOCKER:
        return False
    return subprocess.run([DOCKER, "info"], capture_output=True, check=False).returncode == 0


pytestmark = pytest.mark.skipif(not _docker_ready(), reason="Docker daemon not available")


def test_target_only_relay_allows_declared_target_and_blocks_other_egress():
    suffix = uuid.uuid4().hex[:10]
    target_name = f"midnight-integration-target-{suffix}"
    target_id = subprocess.check_output(
        [
            DOCKER,
            "run",
            "-d",
            "--name",
            target_name,
            "--network",
            "bridge",
            "python:3.12-slim",
            "python",
            "-m",
            "http.server",
            "8000",
        ],
        text=True,
    ).strip()
    target_ip = subprocess.check_output(
        [
            DOCKER,
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            target_id,
        ],
        text=True,
    ).strip()

    async def exercise() -> None:
        manager = ContainerManager(run_id=f"relay-test-{suffix}")
        try:
            relay = await manager.prepare_target_relay(f"{target_ip}:8000")
            solver_id = await manager.create(
                "misc",
                f"midnight-integration-solver-{suffix}",
                network_policy="target_only",
            )
            environment = CTFEnvironment(
                container_id=solver_id,
                workdir="/ctf",
                manager=manager,
            )
            allowed = await environment.exec(
                "python3 -c \"import urllib.request; "
                f"print(urllib.request.urlopen('http://{relay}', timeout=5).status)\""
            )
            blocked = await environment.exec(
                "python3 -c \"import socket; "
                "socket.create_connection(('1.1.1.1', 80), timeout=3)\""
            )
            assert allowed.ok
            assert not blocked.ok
        finally:
            await manager.cleanup_all()

    try:
        asyncio.run(exercise())
    finally:
        subprocess.run([DOCKER, "rm", "-f", target_id], capture_output=True, check=False)
