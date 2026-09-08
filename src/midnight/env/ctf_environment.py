"""Single-challenge runtime environment, bound to one container.

Provides exec / copy / interactive-session primitives used by tools:
- exec / copy_in / copy_out run docker CLI commands against this container.
- open_session opens a non-blocking pexpect-driven interactive session (IAT).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from midnight.env.container_manager import ContainerManager, ExecResult, _run

if TYPE_CHECKING:
    from midnight.tools.interactive.session import InteractiveSession


@dataclass
class CTFEnvironment:
    """Wraps a running container for one challenge."""

    container_id: str
    workdir: str = "/ctf"
    manager: ContainerManager | None = None

    async def exec(self, cmd: str, timeout: int = 120) -> ExecResult:
        """Run a shell command inside the container."""
        return await _run(
            "docker",
            "exec",
            "-w",
            self.workdir,
            self.container_id,
            "bash",
            "-c",
            cmd,
            timeout=timeout,
        )

    async def copy_in(self, src: str, dst: str) -> ExecResult:
        return await _run("docker", "cp", src, f"{self.container_id}:{dst}")

    async def copy_out(self, src: str, dst: str) -> ExecResult:
        return await _run("docker", "cp", f"{self.container_id}:{src}", dst)

    async def open_session(self, cmd: str, *, prompt: str = "") -> InteractiveSession:
        """Open a non-blocking interactive session running ``cmd`` in this container.

        ``prompt`` is an optional marker string used to detect command completion
        faster than the idle-timeout heuristic. The returned session is already
        started and ready for send/read.
        """
        from midnight.tools.interactive.session import DockerInteractiveSession

        sess = DockerInteractiveSession(
            launch_cmd=cmd,
            prompt=prompt,
            container_id=self.container_id,
            workdir=self.workdir,
        )
        await sess.start()
        return sess

    async def close(self) -> None:
        if self.manager is not None:
            await self.manager.stop(self.container_id)
        else:
            await _run("docker", "rm", "-f", self.container_id)
