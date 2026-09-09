"""General tools shared by all specialists: run_shell, file ops, submit_flag.

Each tool is a *factory* registered under the registry; the factory binds the
tool to a specific challenge's CTFEnvironment (and a state accessor for things
like recording candidate flags).
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable

from midnight.env.ctf_environment import CTFEnvironment
from midnight.tools.registry import register_tool
from midnight.tools.summarizer import summarize
from midnight.utils.flag import extract_flags


@register_tool(name="run_shell", groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"])
def make_run_shell(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    observations: dict[str, tuple[str, int]] = {}

    @tool
    async def run_shell(command: str) -> str:
        """Run a bash command inside the challenge container and return its output.

        Output is the combined stdout/stderr. Long output is summarized to
        protect context length. Only the real output is returned — never invent
        command results.
        """
        res = await env.exec(command)
        body = res.stdout
        if res.stderr:
            body += f"\n[stderr]\n{res.stderr}"
        body += f"\n[exit={res.exit_code}]"
        rendered = summarize(body)
        signature = re.sub(r"\s+", " ", command.strip())
        output_hash = hashlib.sha256(rendered.encode()).hexdigest()
        old_hash, old_count = observations.get(signature, ("", 0))
        count = old_count + 1 if old_hash == output_hash else 1
        observations[signature] = (output_hash, count)
        if count >= 2:
            rendered += (
                "\n[MIDNIGHT_STAGNATION] This exact command produced the same "
                f"observation {count} times. Do not run it again. Record the failed "
                "assumption and change phase, hypothesis, input, or tool."
            )
        return rendered

    return run_shell


@register_tool(name="read_file", groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"])
def make_read_file(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def read_file(path: str) -> str:
        """Read a text file inside the challenge container."""
        res = await env.exec(f"cat -- {path!r}")
        return summarize(res.stdout if res.ok else f"[error] {res.stderr}")

    return read_file


@register_tool(name="write_file", groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"])
def make_write_file(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def write_file(path: str, content: str) -> str:
        """Write text content to a file inside the challenge container."""
        # use a heredoc-safe approach via base64 to avoid quoting issues
        import base64

        b64 = base64.b64encode(content.encode()).decode()
        res = await env.exec(f"echo {b64} | base64 -d > {path!r}")
        return "ok" if res.ok else f"[error] {res.stderr}"

    return write_file


@register_tool(name="list_dir", groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"])
def make_list_dir(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def list_dir(path: str = ".") -> str:
        """List directory contents inside the challenge container."""
        res = await env.exec(f"ls -la -- {path!r}")
        return summarize(res.stdout if res.ok else f"[error] {res.stderr}")

    return list_dir


@register_tool(name="summarize_output", groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"])
def make_summarize_output(**_) -> object:
    from langchain_core.tools import tool

    @tool
    def summarize_output(text: str) -> str:
        """Summarize/condense a long piece of text to fit the context window."""
        return summarize(text)

    return summarize_output


@register_tool(name="submit_flag", groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"])
def make_submit_flag(
    *,
    record_flag: Callable[[str], None],
    flag_format: str | None = None,
    state=None,
    **_,
) -> object:
    from langchain_core.tools import tool

    @tool
    def submit_flag(candidate: str, source: str = "unknown") -> str:
        """Report a candidate flag found in real tool output.

        The candidate is validated against the flag format and recorded; final
        verification/submission happens in the verify/submit nodes.
        """
        challenge = (state or {}).get("challenge") or {}
        if (challenge.get("targets") or challenge.get("remote")) and source != "target":
            return (
                "rejected: this challenge has a target; candidate provenance must be "
                "source='target' and the value must appear in target output"
            )
        flags = extract_flags(candidate, flag_format=flag_format)
        if not flags:
            return "rejected: does not match the expected flag format"
        for f in flags:
            record_flag(f)
        return f"recorded candidate flag(s): {', '.join(flags)}"

    return submit_flag
