"""General tools shared by all specialists: run_shell, file ops, submit_flag.

Each tool is a *factory* registered under the registry; the factory binds the
tool to a specific challenge's CTFEnvironment (and a state accessor for things
like recording candidate flags).
"""

from __future__ import annotations

import base64
import hashlib
import re
import shlex
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

    program = r'''import hashlib
import json
import pathlib
import sys

requested, start_raw, count_raw, workspace_raw = sys.argv[1:]
start = int(start_raw)
count = int(count_raw)
workspace = pathlib.Path(workspace_raw).resolve()
path = pathlib.Path(requested)
if not path.is_absolute():
    path = workspace / path
path = path.resolve()
if not path.is_relative_to(workspace) or not path.is_file():
    raise SystemExit('path must resolve to a file inside the challenge workspace')
digest_builder = hashlib.sha256()
selected = []
total_lines = 0
offset = 0
byte_start = None
byte_end = None
with path.open('rb') as source:
    for number, line in enumerate(source, 1):
        digest_builder.update(line)
        total_lines = number
        if number == start:
            byte_start = offset
        if start <= number < start + count:
            selected.append((number, line))
            byte_end = offset + len(line)
        offset += len(line)
digest = digest_builder.hexdigest()
start_index = min(start - 1, total_lines)
end_index = min(start_index + count, total_lines)
if byte_start is None:
    byte_start = offset
if byte_end is None:
    byte_end = byte_start
meta_dir = workspace / '.midnight'
meta_dir.mkdir(exist_ok=True)
ledger = meta_dir / 'read-ledger.jsonl'
prior = []
if ledger.is_file():
    for row in ledger.read_text(errors='replace').splitlines()[-256:]:
        try:
            prior.append(json.loads(row))
        except ValueError:
            pass
duplicate = any(
    item.get('realpath') == str(path) and item.get('sha256') == digest
    and int(item.get('start_line', 0)) <= start
    and int(item.get('end_line', -1)) >= end_index
    for item in prior
)
meta = {
    'schema': 'midnight-file-read/v1', 'realpath': str(path), 'sha256': digest,
    'size': offset, 'total_lines': total_lines, 'start_line': start,
    'end_line': end_index, 'byte_start': byte_start, 'byte_end': byte_end,
}
print(json.dumps(meta, ensure_ascii=False, sort_keys=True))
if duplicate:
    print('[MIDNIGHT_DUPLICATE_READ] This unchanged byte/line range was already returned. '
          'Read an uncovered range by changing start_line, inspect a derived artifact, or use '
          'summarize_output on material already in context. No file content is repeated.')
else:
    with ledger.open('a', encoding='utf-8') as output:
        output.write(json.dumps(meta, ensure_ascii=False, sort_keys=True) + '\n')
    for number, line in selected:
        clipped = line[:4096]
        rendered = clipped.decode('utf-8', errors='replace').rstrip()
        suffix = f' ... [line truncated; {len(line)} bytes total]' if len(line) > len(clipped) else ''
        print(f'{number:08d}: {rendered}{suffix}')
'''

    @tool
    async def read_file(path: str, start_line: int = 1, max_lines: int = 160) -> str:
        """Read a bounded text range and report its real path, hash, lines, and byte offsets.

        Re-reading a covered range of an unchanged file returns only a duplicate-read
        warning. Move ``start_line`` to an uncovered range instead.
        """
        if start_line < 1:
            raise ValueError("start_line must be positive")
        if max_lines < 1 or max_lines > 400:
            raise ValueError("max_lines must be between 1 and 400")
        encoded = base64.b64encode(program.encode()).decode()
        command = (
            f"python3 -c \"import base64;exec(base64.b64decode('{encoded}'))\" "
            f"{shlex.quote(path)} {start_line} {max_lines} {shlex.quote(env.workdir)}"
        )
        res = await env.exec(command, timeout=60)
        return summarize(res.stdout if res.ok else f"[error] {res.stderr}")

    return read_file


@register_tool(name="write_file", groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"])
def make_write_file(*, env: CTFEnvironment, current_expert: str = "", **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def write_file(path: str, content: str) -> str:
        """Write text content, suppressing unchanged or evidence-free forensic rewrites."""
        # use a heredoc-safe approach via base64 to avoid quoting issues
        b64 = base64.b64encode(content.encode()).decode()
        program = r'''import hashlib
import json
import pathlib
import sys

requested, encoded, workspace_raw, expert = sys.argv[1:]
workspace = pathlib.Path(workspace_raw).resolve()
path = pathlib.Path(requested)
if not path.is_absolute():
    path = workspace / path
path = path.resolve()
if not path.is_relative_to(workspace) or path == workspace:
    raise SystemExit('path must resolve inside the challenge workspace')
data = __import__('base64').b64decode(encoded)
new_hash = hashlib.sha256(data).hexdigest()
old_hash = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else ''
meta_dir = workspace / '.midnight'
meta_dir.mkdir(exist_ok=True)
write_ledger = meta_dir / 'write-ledger.jsonl'
read_ledger = meta_dir / 'read-ledger.jsonl'
evidence = workspace / 'forensic-evidence.jsonl'
manual_evidence = workspace / 'evidence.jsonl'
evidence_fingerprint = hashlib.sha256(
    ((read_ledger.read_text(errors='replace') if read_ledger.is_file() else '') +
     (evidence.read_text(errors='replace') if evidence.is_file() else '') +
     (manual_evidence.read_text(errors='replace') if manual_evidence.is_file() else '')).encode()
).hexdigest()
prior = []
if write_ledger.is_file():
    for row in write_ledger.read_text(errors='replace').splitlines()[-128:]:
        try:
            prior.append(json.loads(row))
        except ValueError:
            pass
last = next((item for item in reversed(prior) if item.get('realpath') == str(path)), None)
if old_hash == new_hash:
    print(f'[MIDNIGHT_DUPLICATE_WRITE] unchanged; no write performed; realpath={path}; sha256={new_hash}')
    raise SystemExit(0)
if expert == 'forensics' and last and last.get('evidence_fingerprint') == evidence_fingerprint:
    print('[MIDNIGHT_WRITE_BLOCKED] No new read range or structured forensic evidence exists '
          'since the previous write to this path. Gather new evidence before revising it.')
    raise SystemExit(0)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_bytes(data)
entry = {'realpath': str(path), 'sha256': new_hash, 'previous_sha256': old_hash,
         'evidence_fingerprint': evidence_fingerprint, 'size': len(data)}
with write_ledger.open('a', encoding='utf-8') as output:
    output.write(json.dumps(entry, sort_keys=True) + '\n')
print(json.dumps({'status': 'written', **entry}, sort_keys=True))
'''
        encoded_program = base64.b64encode(program.encode()).decode()
        command = (
            f"python3 -c \"import base64;exec(base64.b64decode('{encoded_program}'))\" "
            f"{shlex.quote(path)} {shlex.quote(b64)} {shlex.quote(env.workdir)} "
            f"{shlex.quote(current_expert)}"
        )
        res = await env.exec(command, timeout=60)
        return summarize(res.stdout if res.ok else f"[error] {res.stderr}")

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
    observed_target_flags: set[str] | None = None,
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
        if (challenge.get("targets") or challenge.get("remote")) and any(
            flag not in (observed_target_flags or set()) for flag in flags
        ):
            return "rejected: candidate was not observed verbatim in target tool output"
        for f in flags:
            record_flag(f)
        return f"recorded candidate flag(s): {', '.join(flags)}"

    return submit_flag
