"""Category-specific (M2) tools that wrap one-shot container commands.

These differ from IAT (interactive) tools: each call runs a command and returns
its output. They are registered for the experts that need them (see
config/tools.yaml). r2_interact is the one stateful exception and uses an IAT
session.
"""

from __future__ import annotations

import shlex

from midnight.env.ctf_environment import CTFEnvironment
from midnight.tools.interactive.session import DockerInteractiveSession
from midnight.tools.registry import register_tool
from midnight.tools.summarizer import summarize


@register_tool(name="binary_triage", groups=["pwn", "reverse"])
def make_binary_triage(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def binary_triage(binary: str) -> str:
        """Collect compact first-pass evidence for an ELF or packed binary.

        Reports type, protections, sections, imports/symbols, high-value strings,
        and packer markers in one deterministic call. It does not modify input.
        """
        path = shlex.quote(binary)
        pwntools_probe = shlex.quote(
            f"from pwn import ELF; print(ELF({binary!r}, checksec=False).checksec())"
        )
        command = (
            f"file {path}; "
            f"python3 -c {pwntools_probe} "
            f"2>/dev/null || true; "
            f"readelf -SW {path} 2>/dev/null | head -45; "
            f"echo '[imports-symbols]'; "
            f"(nm -an {path} 2>/dev/null; objdump -T {path} 2>/dev/null) | "
            "grep -Ei ' main$|win|flag|system|exec|read|write|gets|scanf|printf|puts|malloc|free' | head -80; "
            f"echo '[strings]'; strings -a -n 5 {path} | "
            "grep -Ei 'flag|correct|wrong|password|usage|/bin/sh|UPX|packed' | head -80"
        )
        res = await env.exec(command, timeout=120)
        body = res.stdout
        if res.stderr:
            body += f"\n[stderr]\n{res.stderr}"
        return summarize(body or "(no triage output)")

    return binary_triage


@register_tool(name="upx_unpack", groups=["reverse"])
def make_upx_unpack(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def upx_unpack(binary: str, output: str = "unpacked") -> str:
        """Test and unpack a standard UPX binary into a writable output file.

        The original attachment is preserved. Returns UPX output followed by
        file information for the unpacked artifact.
        """
        src = shlex.quote(binary)
        dst = shlex.quote(output)
        command = (
            "command -v upx >/dev/null || { echo '[error] upx is not installed'; exit 127; }; "
            f"cp -- {src} {dst}.packed-copy && chmod u+w {dst}.packed-copy; "
            f"upx -t {dst}.packed-copy && upx -d -o {dst} {dst}.packed-copy && "
            f"chmod +x {dst} && file {dst}"
        )
        res = await env.exec(command, timeout=120)
        body = res.stdout
        if res.stderr:
            body += f"\n[stderr]\n{res.stderr}"
        body += f"\n[exit={res.exit_code}]"
        return summarize(body)

    return upx_unpack


@register_tool(name="pickle_disassemble", groups=["misc", "forensics"])
def make_pickle_disassemble(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def pickle_disassemble(path: str) -> str:
        """Disassemble pickle bytes without loading or executing the payload."""
        program = shlex.quote(
            f"import pickletools; pickletools.dis(open({path!r}, 'rb').read())"
        )
        res = await env.exec(
            f"python3 -c {program}",
            timeout=30,
        )
        body = res.stdout
        if res.stderr:
            body += f"\n[stderr]\n{res.stderr}"
        body += f"\n[exit={res.exit_code}]"
        return summarize(body)

    return pickle_disassemble


@register_tool(name="checksec", groups=["pwn"])
def make_checksec(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def checksec(binary: str) -> str:
        """Show binary protections (RELRO/Canary/NX/PIE) for a binary path.

        Uses pwntools' checksec; falls back to readelf-based heuristics.
        """
        res = await env.exec(
            f'python3 -c "from pwn import ELF; e=ELF({binary!r}); print(e.checksec())" '
            f"2>/dev/null || checksec --file={binary} 2>/dev/null || "
            f"(echo '[fallback]'; readelf -lW {binary} | grep -E 'GNU_STACK|GNU_RELRO')"
        )
        return summarize(res.stdout or res.stderr or "(no output)")

    return checksec


@register_tool(name="rop_gadget", groups=["pwn"])
def make_rop_gadget(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def rop_gadget(binary: str, query: str = "") -> str:
        """Find ROP gadgets in a binary (ROPgadget). Optional ``query`` greps
        the result, e.g. query='pop rdi'.
        """
        cmd = f"ROPgadget --binary {binary}"
        if query:
            cmd += f" | grep -i -- {query!r}"
        res = await env.exec(cmd, timeout=120)
        return summarize(res.stdout or res.stderr or "(no gadgets)")

    return rop_gadget


@register_tool(name="r2_interact", groups=["reverse", "pwn"])
def make_r2_interact(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    state: dict[str, DockerInteractiveSession | None] = {"session": None}

    async def _ensure(binary: str | None) -> DockerInteractiveSession:
        if state["session"] is None:
            # -q0 prints a NUL then enters interactive; analysis commands like aaa work.
            sess = DockerInteractiveSession(
                launch_cmd="r2" + (f" {binary}" if binary else " -"),
                prompt="[0x",
                container_id=env.container_id,
                workdir=env.workdir,
            )
            await sess.start()
            state["session"] = sess
        session = state["session"]
        assert session is not None
        return session

    @tool
    async def r2_interact(command: str, binary: str = "") -> str:
        """Drive an interactive radare2 session. Pass ``binary`` on first call.

        Then send r2 commands: "aaa" (analyze), "afl" (list funcs),
        "pdf @ main" (disasm main), "iz" (strings), "s sym.main" (seek).
        Falls back to a hint if radare2 is not installed in the image.
        """
        if state["session"] is None:
            probe = await env.exec("command -v r2 || command -v radare2 || true")
            if not probe.stdout.strip():
                return (
                    "[radare2 not installed in this image; use run_shell with "
                    "objdump -d / strings / nm, or gdb_tool for disassembly]"
                )
        sess = await _ensure(binary or None)
        out = await sess.send(command, timeout=60.0)
        return summarize(out) if out.strip() else "(no output)"

    return r2_interact


@register_tool(name="ghidra_headless", groups=["reverse"])
def make_ghidra_headless(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def ghidra_headless(binary: str) -> str:
        """Run Ghidra headless analysis and dump decompiled C for a binary.

        Requires ghidra to be installed in the image; if absent, returns a hint
        to use r2_interact's decompiler (pdc) instead.
        """
        check = await env.exec("command -v analyzeHeadless || true")
        if not check.stdout.strip():
            return "[ghidra not installed in image; use r2_interact 'pdc @ main' for decompilation]"
        res = await env.exec(
            "rm -rf /tmp/ghp && mkdir -p /tmp/ghp && "
            f"analyzeHeadless /tmp/ghp proj -import {binary} "
            "-postScript DecompileScript.java -deleteProject 2>&1 | tail -200",
            timeout=600,
        )
        return summarize(res.stdout or res.stderr or "(no output)")

    return ghidra_headless


@register_tool(name="http_request", groups=["web"])
def make_http_request(*, env: CTFEnvironment, state=None, **_) -> object:
    from langchain_core.tools import tool

    default_remote = None
    if state is not None:
        default_remote = (state.get("challenge") or {}).get("remote")

    @tool
    async def http_request(
        url: str = "",
        method: str = "GET",
        data: str = "",
        headers: str = "",
    ) -> str:
        """Make an HTTP request from inside the container (curl).

        ``url`` may be a full URL or path (prefixed with the challenge remote).
        ``headers`` is a ';'-separated list like 'A: 1; B: 2'. Returns response
        headers + body.
        """
        target = url
        if url.startswith("/") and default_remote:
            target = f"http://{default_remote}{url}"
        parts = ["curl", "-sS", "-i", "-X", method]
        for h in filter(None, (h.strip() for h in headers.split(";"))):
            parts += ["-H", f"{h!r}"]
        if data:
            parts += ["--data", f"{data!r}"]
        parts.append(f"{target!r}")
        res = await env.exec(" ".join(parts), timeout=30)
        return summarize(res.stdout or res.stderr or "(no response)")

    return http_request
