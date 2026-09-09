"""Remote connection tool (IAT) for pwn/web experts.

Wraps an interactive connection to a challenge server (``nc host port``) inside
the container, so the agent can do multi-turn I/O with a live service: read a
prompt, send a payload, read the response, etc. The connection persists across
tool calls within one specialist run.
"""

from __future__ import annotations

from midnight.env.ctf_environment import CTFEnvironment
from midnight.state import CTFState
from midnight.tools.interactive.session import DockerInteractiveSession
from midnight.tools.registry import register_tool
from midnight.tools.summarizer import summarize


@register_tool(name="connect_tool", groups=["pwn", "web"])
def make_connect_tool(
    *, env: CTFEnvironment, state: CTFState | None = None, observe_target_output=None, **_
) -> object:
    from langchain_core.tools import tool

    sessions: dict[str, DockerInteractiveSession] = {}

    # default target from the challenge's "remote" field, if any
    default_remote = None
    if state is not None:
        default_remote = (state.get("challenge") or {}).get("remote")

    async def _ensure(target: str) -> DockerInteractiveSession:
        if target not in sessions:
            host, _, port = target.partition(":")
            sess = DockerInteractiveSession(
                launch_cmd=f"nc {host} {port}" if port else f"nc {host}",
                prompt="",
                container_id=env.container_id,
                workdir=env.workdir,
            )
            await sess.start()
            sessions[target] = sess
        return sessions[target]

    @tool
    async def connect_tool(data: str = "", remote: str = "", reset: bool = False) -> str:
        """Interact with the challenge server over a persistent netcat connection.

        ``remote`` is "host:port" (defaults to the challenge's remote). ``data``
        is a line sent to the service; leave it empty to just read pending
        output. Returns whatever the service sent back (real bytes only).
        """
        target = remote or default_remote
        if not target:
            return "[no remote target: pass remote='host:port']"
        if reset and target in sessions:
            await sessions.pop(target).close()
        sess = await _ensure(target)
        try:
            if data:
                out = await sess.send(data, timeout=15.0)
            else:
                out = await sess.read(timeout=10.0)
        except (EOFError, OSError):
            await sess.close()
            sessions.pop(target, None)
            return (
                "[connection session ended; it has been reset] Retry once with "
                "the complete protocol or use a pwntools script for binary payloads."
            )
        if observe_target_output is not None:
            observe_target_output(out)
        return summarize(out) if out.strip() else "(no output)"

    return connect_tool
