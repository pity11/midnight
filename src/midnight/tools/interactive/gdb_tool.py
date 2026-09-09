"""gdb interactive tool (IAT) for pwn/reverse experts.

Opens a single long-lived gdb session inside the challenge container and lets
the agent drive it across turns: set breakpoints, run, inspect registers/stack,
disassemble. The session is held in the factory closure so repeated tool calls
within one specialist run share the same gdb process.
"""

from __future__ import annotations

from midnight.env.ctf_environment import CTFEnvironment
from midnight.tools.interactive.session import DockerInteractiveSession
from midnight.tools.registry import register_tool
from midnight.tools.summarizer import summarize


@register_tool(name="gdb_tool", groups=["pwn", "reverse"])
def make_gdb_tool(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    state: dict[str, DockerInteractiveSession | None] = {"session": None}

    async def _ensure(binary: str | None) -> DockerInteractiveSession:
        if state["session"] is None:
            launch = "gdb -q" + (f" {binary}" if binary else "")
            sess = DockerInteractiveSession(
                launch_cmd=launch,
                prompt="(gdb)",
                container_id=env.container_id,
                workdir=env.workdir,
            )
            await sess.start()
            state["session"] = sess
        session = state["session"]
        assert session is not None
        return session

    @tool
    async def gdb_tool(command: str, binary: str = "", reset: bool = False) -> str:
        """Drive an interactive gdb session inside the container.

        On the first call, pass ``binary`` to load it (e.g. binary="./chall").
        Then send gdb commands one per call: e.g. "break main", "run",
        "info registers", "x/20gx $rsp", "disassemble main", "continue".
        Returns gdb's output for that command. Returns real output only.
        """
        if reset and state["session"] is not None:
            await state["session"].close()
            state["session"] = None
        sess = await _ensure(binary or None)
        try:
            out = await sess.send(command, timeout=20.0)
        except (EOFError, OSError):
            # PTYs occasionally disappear under emulation. A single automatic
            # restart is cheaper and more reliable than letting the model grind
            # on a poisoned session.
            await sess.close()
            state["session"] = None
            sess = await _ensure(binary or None)
            try:
                out = await sess.send(command, timeout=20.0)
            except (EOFError, OSError) as retry_exc:
                return (
                    f"[gdb session failed after one restart: {retry_exc}] "
                    "Use reset=true, batch gdb through run_shell, or static objdump."
                )
        return summarize(out) if out.strip() else "(no output)"

    return gdb_tool
