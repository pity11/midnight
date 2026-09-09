"""Small procedural playbooks selected from observable challenge evidence.

These entries deliberately describe reusable methods rather than benchmark
instances.  Keeping the catalog in code makes it reviewable and prevents a
retrieval system from accidentally indexing evaluator-only solutions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Playbook:
    key: str
    category: str
    signals: tuple[str, ...]
    objective: str
    steps: tuple[str, ...]
    traps: tuple[str, ...]
    completion: str


PLAYBOOKS: tuple[Playbook, ...] = (
    Playbook(
        "web-source-first",
        "web",
        ("source", "http", "flask", "php", "api", "javascript", "dockerfile"),
        "Map the application data flow from controllable input to a flag-bearing sink.",
        (
            "Fetch the root response, headers, robots.txt, linked scripts, and exposed API descriptions.",
            "Read supplied source and deployment files; list routes, parameters, trust boundaries, and flag location.",
            "Choose one source-supported primitive such as injection, traversal, request forgery, deserialization, or auth bypass.",
            "Prove the primitive with a harmless observable, then build a reproducible request script.",
            "Exercise the challenge target and preserve the exact request/response that contains the flag.",
        ),
        (
            "Avoid broad scanner loops when source already identifies the parser and sink.",
            "Distinguish transport errors and application rejection from a disproved vulnerability hypothesis.",
        ),
        "A minimal request script reproduces the complete flag-bearing response.",
    ),
    Playbook(
        "pwn-format-string-write",
        "pwn",
        ("format string", "printf", "%n", "%hn", "fmtstr"),
        "Turn a controlled printf format string into a verified write, then exercise the real target.",
        (
            "Run checksec and locate the uncontrolled printf call and the value that gates success.",
            "Find the stack argument index with a short positional leak probe; record it in solve.py.",
            "Use the smallest write primitive that fits the target value (%hhn/%hn before %n).",
            "Verify the changed value or success branch locally once, with the exact payload bytes.",
            "Immediately switch solve.py to the supplied remote endpoint and capture its response.",
        ),
        (
            "A local binary commonly contains a placeholder flag; local success proves control, not the answer.",
            "Repeatedly running the same payload after local control is established cannot produce new evidence.",
        ),
        "The remote response contains a verbatim flag, or the payload fails remotely with a new observable difference.",
    ),
    Playbook(
        "pwn-pie-leak-rop",
        "pwn",
        ("pie", "stack leak", "buffer overflow", "rop", "no canary", "return address"),
        "Convert an address disclosure and overwrite into a complete, reproducible exploit.",
        (
            "Save one representative service transcript and label every leaked address.",
            "Determine the overflow offset with cyclic data or a deterministic debugger pattern.",
            "Compute PIE base from a confirmed symbol/instruction offset; assert page alignment.",
            "Choose a minimal chain: ret2win, leak-and-return, ret2libc, or ORW when execve is blocked.",
            "Write solve.py with local/remote modes and explicit recv boundaries; test local once, then remote.",
        ),
        (
            "Do not guess that a leak belongs to PIE/libc/stack; validate its range and low bits.",
            "If interactive GDB dies, restart it or use batch gdb/objdump instead of repeating the failed call.",
            "Check amd64 stack alignment before libc calls.",
        ),
        "solve.py reaches the desired primitive locally and receives the remote flag without manual steps.",
    ),
    Playbook(
        "reverse-upx",
        "reverse",
        ("upx", "upx0", "upx1", "packed", "packer", "high entropy"),
        "Recover an analyzable binary from a standard UPX layer before deeper reversing.",
        (
            "Confirm UPX with `upx -t`, section names, or the UPX magic rather than entropy alone.",
            "Copy the attachment to a writable path and run `upx -d -o unpacked <copy>`.",
            "Repeat file/strings/nm/objdump on unpacked and run it with representative input.",
            "Only attempt manual OEP dumping when the installed UPX reports a modified or unsupported layer.",
        ),
        (
            "Do not spend the task budget manually reconstructing a standard packer before checking the installed tool.",
            "Preserve the original file and compare behavior after unpacking.",
        ),
        "The unpacked artifact executes equivalently and exposes code or data suitable for static analysis.",
    ),
    Playbook(
        "reverse-verifier-inversion",
        "reverse",
        ("check", "compare", "xor", "transform", "password", "vm", "bytecode"),
        "Recover accepted input by reproducing and inverting the verifier.",
        (
            "Locate success/failure strings and cross-reference the branches that print them.",
            "Translate the verifier into a small Python forward model with named intermediate values.",
            "Invert operations in reverse order or solve constraints; retain byte-width and signedness semantics.",
            "Round-trip the candidate through the forward model, then through the original binary.",
        ),
        (
            "Runtime-generated tables can differ from misleading static bytes.",
            "Do not accept readable plaintext without reproducing the final success branch.",
        ),
        "The original program reaches its success branch on the generated input.",
    ),
    Playbook(
        "crypto-rsa-decimal-digit-leak",
        "crypto",
        ("rsa", "decimal digits", "alternating digits", "partial p", "partial q", "digit leak"),
        "Reconstruct RSA factors from interleaved or partially known decimal digits using modular pruning.",
        (
            "Write down which decimal positions of p and q are fixed; decide whether indexing starts at the least significant digit.",
            "Grow p and q one decimal digit at a time from the least significant side.",
            "For depth i keep only candidates satisfying p*q modulo 10^(i+1) equals n modulo 10^(i+1).",
            "Enforce nonzero leading digits only when reaching the most significant position.",
            "Assert p*q == n before computing phi, d, and plaintext; print candidate counts per depth.",
        ),
        (
            "Do not mix most-significant and least-significant indexing.",
            "Prefer iterative candidate lists to fragile recursive closures; validate lengths before indexing.",
            "A zero-candidate depth is an orientation/constraint bug, not evidence that RSA arithmetic failed.",
        ),
        "Recovered integers multiply exactly to n and RSA decryption round-trips under the public exponent.",
    ),
    Playbook(
        "misc-restricted-pickle",
        "misc",
        ("pickle", "unpickler", "opcode", "find_class", "restricted", "sandbox"),
        "Construct a pickle opcode chain using only operations and globals admitted by the challenge validator.",
        (
            "Read the custom Unpickler and any opcode/global allowlist before building a payload.",
            "Model the pickle VM stack explicitly: mark, tuple, reduce, build, get/set state, and memo operations.",
            "Identify an allowed object that reaches attributes, subclasses, globals, builtins, or an evaluator.",
            "Assemble the shortest chain with pickletools/pickora when available, then disassemble it with pickletools.dis.",
            "Run the exact server-side validation locally before sending the bytes to the target.",
        ),
        (
            "A Python expression describing a gadget chain is not necessarily the pickle VM sequence that realizes it.",
            "Protocol and opcode restrictions matter more than library folklore; verify every emitted opcode.",
        ),
        "The payload passes the local validator and produces a controlled observable value or command output.",
    ),
    Playbook(
        "forensics-layered-message",
        "forensics",
        ("email", "eml", "mime", "attachment", "base64", "quoted-printable"),
        "Peel transport encodings and nested attachments while preserving provenance.",
        (
            "Parse the message with Python's email package and enumerate MIME parts, filenames, and content types.",
            "Decode transfer encoding through the parser; save each part with a content hash.",
            "Run file/strings/binwalk on decoded parts and recurse into archives or embedded messages.",
            "Record the exact part and decoding chain that produced any flag candidate.",
        ),
        ("Do not manually base64-decode already decoded parser output.",),
        "A flag is tied to an exact MIME part and reproducible decode chain.",
    ),
)


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_%]+", text.lower()))


def find_playbooks(category: str, evidence: str = "", *, limit: int = 3) -> list[Playbook]:
    """Return the most relevant category playbooks for observable evidence."""
    query = evidence.lower()
    query_tokens = _tokens(evidence)
    scored: list[tuple[int, str, Playbook]] = []
    for item in PLAYBOOKS:
        if item.category != category and not (category == "forensics" and item.category == "misc"):
            continue
        score = 1
        for signal in item.signals:
            if signal in query:
                score += 5
            else:
                score += len(_tokens(signal) & query_tokens)
        scored.append((score, item.key, item))
    scored.sort(key=lambda row: (-row[0], row[1]))
    return [row[2] for row in scored[: max(limit, 0)]]


def render_playbooks(category: str, evidence: str = "", *, limit: int = 3) -> str:
    """Render selected playbooks in a compact format suitable for an agent tool."""
    selected = find_playbooks(category, evidence, limit=limit)
    if not selected:
        return f"No curated playbook matches category={category!r}. Continue evidence-led analysis."
    blocks: list[str] = []
    for item in selected:
        steps = "\n".join(f"  {index}. {step}" for index, step in enumerate(item.steps, 1))
        traps = "\n".join(f"  - {trap}" for trap in item.traps)
        blocks.append(
            f"PLAYBOOK {item.key}\nObjective: {item.objective}\nSteps:\n{steps}\n"
            f"Traps:\n{traps}\nCompletion gate: {item.completion}"
        )
    return "\n\n".join(blocks)
