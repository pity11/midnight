"""Category-specific (M2) tools that wrap one-shot container commands.

These differ from IAT (interactive) tools: each call runs a command and returns
its output. They are registered for the experts that need them (see
config/tools.yaml). r2_interact is the one stateful exception and uses an IAT
session.
"""

from __future__ import annotations

import base64
import re
import shlex
from urllib.parse import urlsplit

from midnight.env.ctf_environment import CTFEnvironment
from midnight.tools.interactive.session import DockerInteractiveSession
from midnight.tools.registry import register_tool
from midnight.tools.summarizer import summarize


def _result_text(result: object) -> str:
    """Format one-shot command output consistently for the model."""
    stdout = getattr(result, "stdout", "")
    stderr = getattr(result, "stderr", "")
    exit_code = getattr(result, "exit_code", "?")
    body = stdout
    if stderr:
        body += f"\n[stderr]\n{stderr}"
    body += f"\n[exit={exit_code}]"
    return summarize(body or "(no output)")


def _challenge_url(url: str, remote: str | None) -> str:
    """Resolve a URL against the evaluator-provided challenge endpoint."""
    value = url.strip()
    if not value:
        if not remote:
            raise ValueError("url is required because the challenge has no remote endpoint")
        return remote if "://" in remote else f"http://{remote}"
    if value.startswith("/"):
        if not remote:
            raise ValueError("relative url requires a challenge remote endpoint")
        base = remote if "://" in remote else f"http://{remote}"
        return base.rstrip("/") + value
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("url must be an HTTP(S) URL or an absolute path")
    return value


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


@register_tool(name="pwninit_setup", groups=["pwn"])
def make_pwninit_setup(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def pwninit_setup(
        binary: str,
        libc: str = "",
        linker: str = "",
        output_template: str = "",
    ) -> str:
        """Prepare a libc-based pwn challenge with pwninit.

        Patches a copy of the binary for the supplied libc/linker and creates a
        pwntools solve stub. With benchmark internet disabled, supply ``linker``
        when the matching loader is present in the challenge bundle.
        """
        parts = ["pwninit", "--bin", binary]
        if libc:
            parts += ["--libc", libc]
        if linker:
            parts += ["--ld", linker]
        if output_template:
            parts += ["--template-path", output_template]
        command = "command -v pwninit >/dev/null || exit 127; " + " ".join(
            shlex.quote(part) for part in parts
        )
        return _result_text(await env.exec(command, timeout=180))

    return pwninit_setup


@register_tool(name="one_gadget", groups=["pwn"])
def make_one_gadget(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def one_gadget(libc: str, level: int = 0, near: str = "") -> str:
        """Find one-gadget offsets and their register/stack constraints in libc.

        ``level`` controls how many lower-probability candidates are shown.
        ``near`` may name functions such as 'exit,main' to rank nearby gadgets.
        """
        if level < 0 or level > 3:
            raise ValueError("level must be between 0 and 3")
        parts = ["one_gadget", "--level", str(level)]
        if near:
            parts += ["--near", near]
        parts.append(libc)
        command = "command -v one_gadget >/dev/null || exit 127; " + " ".join(
            shlex.quote(part) for part in parts
        )
        return _result_text(await env.exec(command, timeout=180))

    return one_gadget


@register_tool(name="run_exploit", groups=["pwn"])
def make_run_exploit(*, env: CTFEnvironment, state=None, **_) -> object:
    from langchain_core.tools import tool

    remote = str(((state or {}).get("challenge") or {}).get("remote") or "")

    @tool
    async def run_exploit(
        script: str = "solve.py", mode: str = "local", timeout_seconds: int = 120
    ) -> str:
        """Syntax-check and run a pwntools solve script locally or on the target.

        The script should support pwntools-style ``LOCAL=1`` and
        ``REMOTE=1 HOST=<host> PORT=<port>`` arguments. Target mode is bound to
        the evaluator-provided endpoint; the model cannot select another host.
        """
        if mode not in {"local", "target"}:
            raise ValueError("mode must be local or target")
        if timeout_seconds < 1 or timeout_seconds > 600:
            raise ValueError("timeout_seconds must be between 1 and 600")
        args = ["python3", script]
        if mode == "local":
            args.append("LOCAL=1")
        else:
            if not remote or ":" not in remote:
                raise ValueError("target mode requires an evaluator-provided host:port")
            host, raw_port = remote.rsplit(":", 1)
            if not host or not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
                raise ValueError("the evaluator-provided target is not host:port")
            args += ["REMOTE=1", f"HOST={host}", f"PORT={raw_port}"]
        quoted_script = shlex.quote(script)
        command = (
            f"python3 -m py_compile {quoted_script} && "
            f"timeout {timeout_seconds}s "
            + " ".join(shlex.quote(part) for part in args)
        )
        return _result_text(await env.exec(command, timeout=timeout_seconds + 15))

    return run_exploit


@register_tool(name="fmtstr_probe", groups=["pwn"])
def make_fmtstr_probe(*, env: CTFEnvironment, state=None, **_) -> object:
    from langchain_core.tools import tool

    remote = str(((state or {}).get("challenge") or {}).get("remote") or "")

    @tool
    async def fmtstr_probe(
        mode: str = "local",
        binary: str = "",
        prompt: str = "",
        start_index: int = 1,
        end_index: int = 40,
    ) -> str:
        """Send one bounded positional format-string leak probe.

        The payload begins with ``AAAABBBB`` and prints indexed pointers between
        ``start_index`` and ``end_index``. Use the marker value and surrounding
        pointers to determine the controlled argument index and address classes.
        Target mode is bound to the evaluator-provided endpoint.
        """
        if mode not in {"local", "target"}:
            raise ValueError("mode must be local or target")
        if start_index < 1 or end_index < start_index or end_index > 100:
            raise ValueError("format-string index range must be within 1..100")
        host = ""
        port = 0
        if mode == "local":
            if not binary:
                raise ValueError("local mode requires a binary")
        else:
            if not remote or ":" not in remote:
                raise ValueError("target mode requires an evaluator-provided host:port")
            host, raw_port = remote.rsplit(":", 1)
            if not host or not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
                raise ValueError("the evaluator-provided target is not host:port")
            port = int(raw_port)
        program = f"""from pwn import *
context.log_level = 'error'
io = process({binary!r}) if {mode!r} == 'local' else remote({host!r}, {port})
if {prompt!r}:
    io.recvuntil({prompt!r}.encode())
payload = b'AAAABBBB|' + b'|'.join(f'%{{i}}$p'.encode() for i in range({start_index}, {end_index + 1})) + b'|END'
io.sendline(payload)
data = io.recvrepeat(2)
print(data.decode(errors='replace'))
print('[payload_hex]', payload.hex())
io.close()
"""
        encoded = base64.b64encode(program.encode()).decode()
        command = f"printf %s {encoded} | base64 -d | python3 -"
        return _result_text(await env.exec(command, timeout=45))

    return fmtstr_probe


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


@register_tool(name="pyinstaller_extract", groups=["reverse"])
def make_pyinstaller_extract(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def pyinstaller_extract(binary: str, info_only: bool = False) -> str:
        """Inspect or extract a PyInstaller-built ELF/PE executable.

        Extraction creates ``<binary>_extracted`` and recovers its bundled PYZ
        bytecode without needing the original Python interpreter version.
        """
        parts = ["pyinstxtractor-ng"]
        if info_only:
            parts.append("--info")
        parts.append(binary)
        command = "command -v pyinstxtractor-ng >/dev/null || exit 127; " + " ".join(
            shlex.quote(part) for part in parts
        )
        return _result_text(await env.exec(command, timeout=180))

    return pyinstaller_extract


@register_tool(name="android_decompile", groups=["reverse"])
def make_android_decompile(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def android_decompile(
        artifact: str, output_dir: str = "jadx_out", resources: bool = True
    ) -> str:
        """Decompile an APK or DEX artifact with JADX into a writable directory.

        Returns a compact file inventory and high-value strings after the
        decompiler finishes. Disable ``resources`` for a faster source-only run.
        """
        parts = ["jadx", "--output-dir", output_dir]
        if not resources:
            parts.append("--no-res")
        parts.append(artifact)
        command = (
            "command -v jadx >/dev/null || exit 127; "
            + " ".join(shlex.quote(part) for part in parts)
            + "; status=$?; "
            + f"find {shlex.quote(output_dir)} -type f | head -80; "
            + f"grep -RIE 'flag|secret|password|token|native' {shlex.quote(output_dir)} "
            + "2>/dev/null | head -100; exit $status"
        )
        return _result_text(await env.exec(command, timeout=600))

    return android_decompile


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


@register_tool(name="fenjing_ssti", groups=["web"])
def make_fenjing_ssti(*, env: CTFEnvironment, state=None, **_) -> object:
    from langchain_core.tools import tool

    remote = None
    if state is not None:
        remote = (state.get("challenge") or {}).get("remote")

    @tool
    async def fenjing_ssti(
        url: str = "",
        mode: str = "scan",
        method: str = "GET",
        inputs: str = "",
        command: str = "id",
        json_data: str = "",
        json_key: str = "",
    ) -> str:
        """Run Fenjing against a CTF Jinja2 SSTI endpoint.

        Modes: ``scan`` discovers forms/parameters, ``crack`` targets named
        comma-separated ``inputs``, and ``crack-json`` targets ``json_key`` in
        ``json_data``. Fenjing fingerprints the filter and generates a bypass.
        """
        if mode not in {"scan", "crack", "crack-json"}:
            raise ValueError("mode must be scan, crack, or crack-json")
        method = method.upper()
        if method not in {"GET", "POST"}:
            raise ValueError("method must be GET or POST")
        target = _challenge_url(url, remote)
        parts = ["fenjing", mode, "--url", target, "--detect-mode", "fast"]
        if mode == "crack":
            if not inputs.strip():
                raise ValueError("crack mode requires comma-separated inputs")
            parts += ["--method", method, "--inputs", inputs]
        elif mode == "crack-json":
            if not json_data or not json_key:
                raise ValueError("crack-json requires json_data and json_key")
            parts += ["--json-data", json_data, "--key", json_key]
        if command:
            parts += ["--exec-cmd", command]
        shell_command = "command -v fenjing >/dev/null || exit 127; " + " ".join(
            shlex.quote(part) for part in parts
        )
        return _result_text(await env.exec(shell_command, timeout=300))

    return fenjing_ssti


@register_tool(name="xor_analyze", groups=["crypto"])
def make_xor_analyze(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def xor_analyze(
        path: str,
        key_length: int = 0,
        most_frequent_hex: str = "",
        known_plaintext: str = "",
        hex_input: bool = False,
        max_key_length: int = 65,
    ) -> str:
        """Analyze a repeating-key XOR ciphertext and write candidates to xortool_out.

        Use a likely frequent byte (20 for text, 00 for binaries), a known flag
        prefix, or a suspected key length to reduce candidate noise.
        """
        if key_length < 0 or max_key_length < 1 or max_key_length > 4096:
            raise ValueError("invalid key length")
        parts = ["xortool"]
        if hex_input:
            parts.append("--hex")
        if key_length:
            parts += ["--key-length", str(key_length)]
        else:
            parts += ["--max-keylen", str(max_key_length)]
        if most_frequent_hex:
            parts += ["--char", most_frequent_hex]
        if known_plaintext:
            parts += ["--known-plaintext", known_plaintext, "--filter-output"]
        parts.append(path)
        command = "command -v xortool >/dev/null || exit 127; " + " ".join(
            shlex.quote(part) for part in parts
        )
        return _result_text(await env.exec(command, timeout=180))

    return xor_analyze


@register_tool(name="stego_scan", groups=["misc", "forensics"])
def make_stego_scan(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def stego_scan(
        path: str, extract_channel: str = "", scan_all: bool = False
    ) -> str:
        """Detect PNG/BMP LSB data with zsteg and optionally extract one channel.

        ``extract_channel`` is a zsteg channel descriptor such as
        ``1b,rgb,lsb``. Set ``scan_all`` only when the shorter default scan does
        not find useful evidence because it can produce a large result set.
        """
        parts = ["zsteg"]
        if extract_channel:
            parts += ["--extract", extract_channel]
        elif scan_all:
            parts.append("--all")
        parts.append(path)
        command = "command -v zsteg >/dev/null || exit 127; " + " ".join(
            shlex.quote(part) for part in parts
        )
        return _result_text(await env.exec(command, timeout=180))

    return stego_scan


@register_tool(name="memory_analyze", groups=["forensics"])
def make_memory_analyze(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def memory_analyze(
        image: str, plugin: str = "windows.info", output_dir: str = "volatility_out"
    ) -> str:
        """Run one named Volatility 3 plugin against a memory image.

        Start with an OS information plugin, then use process, network, command
        line, file, registry, or malware plugins supported by the image profile.
        Extracted artifacts are written under ``output_dir``.
        """
        if not re.fullmatch(r"[A-Za-z0-9_.]+", plugin):
            raise ValueError("plugin must be a Volatility dotted plugin name")
        parts = ["vol", "-q", "-f", image, "-o", output_dir, plugin]
        command = (
            "command -v vol >/dev/null || exit 127; mkdir -p -- "
            + shlex.quote(output_dir)
            + "; "
            + " ".join(shlex.quote(part) for part in parts)
        )
        return _result_text(await env.exec(command, timeout=600))

    return memory_analyze


@register_tool(name="disk_image_triage", groups=["forensics"])
def make_disk_image_triage(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def disk_image_triage(image: str, offset_sectors: int = 0) -> str:
        """Inspect a disk image partition table and list filesystem entries.

        ``offset_sectors`` selects a partition start reported by mmls. A zero
        offset performs partition discovery and a best-effort root listing.
        """
        if offset_sectors < 0:
            raise ValueError("offset_sectors must be non-negative")
        path = shlex.quote(image)
        command = f"mmls {path}; echo '[filesystem-root]'; fls -r -o {offset_sectors} {path} | head -200"
        return _result_text(await env.exec(command, timeout=300))

    return disk_image_triage


@register_tool(name="pcap_triage", groups=["forensics"])
def make_pcap_triage(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def pcap_triage(
        capture: str, display_filter: str = "", follow_tcp_stream: int = -1
    ) -> str:
        """Summarize a PCAP/PCAPNG or follow one TCP stream with tshark.

        With no stream selected, reports capture metadata, protocol hierarchy,
        conversations, DNS names and common plaintext request fields. Set
        ``follow_tcp_stream`` to an observed index for its ASCII transcript.
        ``display_filter`` narrows packet-derived fields.
        """
        if follow_tcp_stream < -1:
            raise ValueError("follow_tcp_stream must be -1 or a non-negative index")
        path = shlex.quote(capture)
        if follow_tcp_stream >= 0:
            command = (
                f"tshark -r {path} -q -z "
                + shlex.quote(f"follow,tcp,ascii,{follow_tcp_stream}")
            )
        else:
            filter_part = f" -Y {shlex.quote(display_filter)}" if display_filter else ""
            command = (
                f"capinfos {path}; echo '[protocols]'; tshark -r {path} -q -z io,phs; "
                f"echo '[conversations]'; tshark -r {path} -q -z conv,tcp; "
                f"echo '[high-value-fields]'; tshark -r {path}{filter_part} -T fields "
                "-e tcp.stream -e ip.src -e ip.dst -e dns.qry.name -e http.request.method "
                "-e http.host -e http.request.uri -e ftp.request.command -e ftp.request.arg "
                "2>/dev/null | head -240"
            )
        return _result_text(await env.exec(command, timeout=300))

    return pcap_triage
