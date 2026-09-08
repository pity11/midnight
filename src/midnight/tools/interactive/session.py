"""Interactive session base + a Docker-backed implementation (IAT).

Wraps a long-lived, non-blocking terminal program (gdb, nc, r2 -d ...) running
*inside a challenge container* via ``docker exec -i``, driven by pexpect. The
session lets an agent send commands and read incremental output across multiple
turns — essential for pwn/reverse where a single shell command is not enough.

Design (borrowing EnIGMA's Interactive Agent Tools):
- non-blocking: ``send`` writes then reads until idle/prompt/timeout, so the
  agent can interleave other actions.
- prompt-aware: subclasses may declare a ``prompt`` marker to detect command
  completion faster than waiting for the idle timeout.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InteractiveSession:
    """Base class for non-blocking interactive terminal sessions."""

    launch_cmd: str = ""
    prompt: str = ""

    async def start(self) -> None:
        raise NotImplementedError

    async def send(self, data: str, *, timeout: float = 10.0) -> str:
        raise NotImplementedError

    async def read(self, *, timeout: float = 10.0) -> str:
        raise NotImplementedError

    async def interrupt(self) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        raise NotImplementedError


@dataclass
class DockerInteractiveSession(InteractiveSession):
    """A pexpect-driven ``docker exec -i`` session inside a container.

    pexpect is synchronous, so blocking reads run in a thread executor to keep
    the asyncio event loop responsive (important for concurrent solving).
    """

    container_id: str = ""
    workdir: str = "/ctf"
    idle_timeout: float = 0.4   # seconds of silence treated as "command done"
    _child: object = field(default=None, repr=False)

    async def start(self) -> None:
        import pexpect

        # -i keeps stdin open; run the target program with a login-ish bash so
        # PATH/tools resolve. The program itself is whatever launch_cmd says.
        full = f"cd {self.workdir} && {self.launch_cmd}"
        spawn_cmd = f"docker exec -i {self.container_id} bash -lc {full!r}"
        loop = asyncio.get_running_loop()
        self._child = await loop.run_in_executor(
            None,
            lambda: pexpect.spawn(spawn_cmd, encoding="utf-8", timeout=30, echo=False),
        )
        # drain any banner output
        await self.read(timeout=2.0)

    async def _drain(self, timeout: float) -> str:
        """Read until prompt match, idle gap, or timeout (runs in executor)."""
        import pexpect

        child = self._child
        if child is None:
            return "[session not started]"

        def _read() -> str:
            buf: list[str] = []
            deadline = asyncio.get_event_loop().time if False else None  # noqa
            import time as _t

            end = _t.time() + timeout
            while _t.time() < end:
                try:
                    chunk = child.read_nonblocking(size=4096, timeout=self.idle_timeout)
                    if chunk:
                        buf.append(chunk)
                        if self.prompt and self.prompt in "".join(buf)[-len(self.prompt) - 8:]:
                            break
                except pexpect.TIMEOUT:
                    if buf:  # got something then went idle -> command done
                        break
                except pexpect.EOF:
                    break
            return "".join(buf)

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _read)

    async def send(self, data: str, *, timeout: float = 10.0) -> str:
        if self._child is None:
            await self.start()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: self._child.sendline(data))
        return await self._drain(timeout)

    async def read(self, *, timeout: float = 10.0) -> str:
        return await self._drain(timeout)

    async def interrupt(self) -> None:
        if self._child is not None:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, lambda: self._child.sendcontrol("c"))

    async def close(self) -> None:
        if self._child is not None:
            loop = asyncio.get_running_loop()
            child = self._child
            self._child = None
            await loop.run_in_executor(None, lambda: child.close(force=True))
