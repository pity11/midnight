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
        "pwn-ret2libc",
        "pwn",
        ("libc", "puts", "got", "plt", "nx", "rop", "system", "/bin/sh"),
        "Turn a code-reuse primitive into a version-correct two-stage ret2libc exploit.",
        (
            "Confirm the exact binary, libc, and loader; use pwninit_setup when all are supplied.",
            "Find the overwrite offset and a reliable return point such as main or the vulnerable function.",
            "Stage one: leak one GOT entry through its matching PLT call and return for a second input.",
            "Parse the leak at a stable recv boundary, compute libc base, and assert its page alignment.",
            "Stage two: align the stack, call system('/bin/sh') or an ORW chain, then exercise the target with run_exploit.",
        ),
        (
            "Do not use offsets from a different libc build.",
            "A short raw leak may contain newline or NUL bytes; parse bytes before converting to an integer.",
            "amd64 libc calls may fail on a misaligned stack even when every address is correct.",
        ),
        "The same solve.py proves the control-flow chain locally and returns target output under the supplied libc.",
    ),
    Playbook(
        "pwn-shellcode-seccomp",
        "pwn",
        ("shellcode", "seccomp", "rwx", "mprotect", "read", "orw", "syscall"),
        "Select shellcode or syscall behavior that respects the binary's memory and seccomp constraints.",
        (
            "Determine architecture, writable/executable mappings, input size, bad bytes, and exact seccomp rules.",
            "If execution is direct, assemble the smallest architecture-correct payload and disassemble it for review.",
            "If NX is enabled, use ROP to read a second stage and mprotect it, or build a syscall-only chain.",
            "When execve is blocked, open/read/write the known or discovered flag path.",
            "Verify the allowed syscalls locally and then run the identical payload against the target.",
        ),
        (
            "Do not assume execve is allowed just because a syscall gadget exists.",
            "Preserve register clobbers and syscall return values across an ORW chain.",
        ),
        "A locally observed read/control effect and target response are produced by one reproducible script.",
    ),
    Playbook(
        "pwn-heap-tcache",
        "pwn",
        ("heap", "malloc", "free", "tcache", "uaf", "double free", "edit", "delete"),
        "Convert a menu-level lifetime bug into a version-aware allocator primitive.",
        (
            "Script every menu action first; assign names to chunks and record sizes and indices.",
            "Prove one primitive: use-after-free read/write, double free, overlap, or out-of-bounds metadata access.",
            "Identify glibc version and account for tcache count, safe-linking, hook removal, and pointer mangling.",
            "Build the shortest target primitive: overlap a sensitive object, poison an allocation, or leak then ROP/FSOP.",
            "Assert each allocator state transition in GDB once and preserve the complete sequence in solve.py.",
        ),
        (
            "Allocator techniques are version-specific; __free_hook and classic tcache poisoning may not exist unchanged.",
            "Menu desynchronization often looks like heap corruption; use explicit recvuntil boundaries.",
            "Do not vary many allocation sizes at once; keep a written chunk-state table.",
        ),
        "The exploit recreates the same allocation state from a fresh process and reaches the target effect.",
    ),
    Playbook(
        "web-ssti",
        "web",
        ("ssti", "jinja", "template", "render_template_string", "flask"),
        "Confirm server-side template evaluation and turn the identified engine into a minimal flag-read request.",
        (
            "Locate the exact parameter and rendering sink from source or a harmless arithmetic probe.",
            "Fingerprint the template engine and record which characters, attributes, and delimiters survive filtering.",
            "Use fenjing_ssti for Jinja2 filters; otherwise construct the shortest engine-specific read primitive.",
            "Preserve the final HTTP request and the target response containing the flag.",
        ),
        (
            "Do not treat reflected input as template execution without an evaluated expression.",
            "Use the challenge target only; broad crawling wastes the short competition window.",
        ),
        "One reproducible target request evaluates server-side and returns the flag-bearing response.",
    ),
    Playbook(
        "web-sqli",
        "web",
        ("sql", "sqlite", "mysql", "select", "query", "login", "injection"),
        "Convert a source-supported SQL injection into the smallest query that reaches challenge data.",
        (
            "Identify the query, database engine, controllable clause, quoting context, and response oracle.",
            "Prove boolean or error influence with two contrasting requests.",
            "Prefer a direct UNION/error extraction when columns and output are known; use bounded automation only after proof.",
            "Save the exact request sequence and response containing the recovered value.",
        ),
        (
            "Do not launch an unbounded sqlmap scan before identifying the parameter and request shape.",
            "Account for JSON bodies, cookies, prepared statements, and second-order storage paths.",
        ),
        "A minimal scripted request recovers the target value from the real challenge service.",
    ),
    Playbook(
        "web-file-read",
        "web",
        ("lfi", "path traversal", "include", "file", "download", "php filter", "open("),
        "Turn path control into a reproducible source or flag read while respecting the application parser.",
        (
            "Trace path construction, normalization, extension appending, and allowlist checks from input to filesystem access.",
            "Prove traversal with a stable non-secret file or supplied source path.",
            "Apply encoding, wrapper, archive, or double-decoding behavior only when supported by the implementation.",
            "Use the resulting source disclosure to locate the flag path or a stronger application primitive.",
        ),
        (
            "A 200 response can be a custom error page; compare content and length against a negative control.",
            "Do not guess flag paths repeatedly when source or environment files can disclose them.",
        ),
        "The target returns a named file through a request reproducible from a clean session.",
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
        "reverse-symbolic-path",
        "reverse",
        ("angr", "symbolic", "many branches", "find", "avoid", "success string"),
        "Use bounded symbolic execution when the success and failure branches are identifiable but manual inversion is costly.",
        (
            "Locate input ingestion and exact success/failure basic blocks with strings and cross-references.",
            "Constrain input length and alphabet before exploration; hook unsupported library calls only when required.",
            "Run angr with explicit find and avoid addresses and a bounded state count.",
            "Replay the concrete solution through the original binary and save the solver script.",
        ),
        (
            "Unconstrained stdin and path explosion will consume the entire competition window.",
            "A symbolic candidate is incomplete until the original executable reaches success.",
        ),
        "A saved solver produces an input that the original program accepts from a fresh process.",
    ),
    Playbook(
        "reverse-protocol-state-machine",
        "reverse",
        ("protocol", "packet", "opcode", "state machine", "crc", "checksum", "frame"),
        "Recover a compact protocol grammar and implement a client or decoder that reproduces the accepted state transition.",
        (
            "Identify framing, byte order, length fields, message types, state variables, and integrity checks.",
            "Record one valid or partially valid exchange and map each response difference to a parser stage.",
            "Implement encode/decode and checksum functions with round-trip assertions in solve.py.",
            "Drive the minimal valid state sequence against the supplied target and preserve the transcript.",
        ),
        (
            "Do not fuzz every byte before identifying framing and checksum boundaries.",
            "Keep binary data as bytes; accidental text encoding commonly corrupts length and checksum fields.",
        ),
        "The client creates valid frames and reaches the target state without manual interaction.",
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
        "crypto-rsa-quick-attacks",
        "crypto",
        ("rsa", "modulus", "public exponent", "ciphertext", "fermat", "wiener", "small e"),
        "Eliminate common RSA construction failures before attempting expensive algebra.",
        (
            "Parse n, e, c and all auxiliary values exactly; check gcd relationships and modulus reuse.",
            "Test exact low-exponent roots when padding is absent, then Wiener for unusually small d.",
            "Try bounded Fermat only when p and q appear close; stop at the configured iteration cap.",
            "When factors are recovered, assert p*q == n, compute d, decrypt, and validate the byte encoding.",
        ),
        (
            "Do not call a factorization success without multiplying factors back to n.",
            "Readable bytes alone are not proof if padding or block ordering remains unresolved.",
        ),
        "A mathematically verified relation recovers plaintext bytes or rules out each quick attack.",
    ),
    Playbook(
        "crypto-prng-lcg",
        "crypto",
        ("lcg", "prng", "random", "seed", "consecutive output", "modulus", "nonce"),
        "Recover generator state or parameters from observed outputs and predict only after replay validation.",
        (
            "Write the exact recurrence and identify which state bits or transformed outputs are exposed.",
            "Use consecutive-output differences and gcd relations to recover an unknown modulus when applicable.",
            "Solve multiplier and increment modulo the verified modulus, accounting for non-invertible differences.",
            "Replay every known output before predicting the next value or reconstructing a key/nonce.",
        ),
        (
            "Python's random, libc rand, LCGs, and xorshift families require different state recovery methods.",
            "One matching output is insufficient; validate the complete observed sequence.",
        ),
        "Recovered parameters reproduce all observations and deterministically predict a withheld output.",
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
    Playbook(
        "forensics-pcap-streams",
        "forensics",
        ("pcap", "pcapng", "tshark", "tcp stream", "http", "dns", "ftp"),
        "Reduce a packet capture to relevant conversations and reproducible extracted content.",
        (
            "Run pcap_triage to record capture metadata, protocol hierarchy, conversations, and stream indices.",
            "Filter high-value protocols and endpoints; identify plaintext credentials, requests, transfers, and anomalies.",
            "Follow only evidence-supported TCP streams and preserve the stream index with each extracted transcript.",
            "Export transferred objects or decode application payloads, then identify and hash recovered files.",
            "Tie any flag to a packet, stream, object, and deterministic extraction command.",
        ),
        (
            "A strings scan loses packet direction and reassembly context.",
            "TLS payloads require key material, a protocol-side leak, or analysis of unencrypted metadata.",
        ),
        "The recovered value is reproducible from a named stream or object in the original capture.",
    ),
    Playbook(
        "forensics-archive-image",
        "forensics",
        ("zip", "archive", "image", "png", "jpeg", "metadata", "binwalk", "stego"),
        "Enumerate containers and image channels before applying format-specific recovery.",
        (
            "Identify the real file type, metadata, archive members, trailing bytes, and embedded signatures.",
            "Extract into a separate directory and hash recovered children to preserve provenance.",
            "For images, inspect dimensions, channels, palette, alpha, OCR, and bounded LSB scans based on format.",
            "Recurse only into evidence-bearing files and record the exact extraction chain.",
        ),
        (
            "File extensions are untrusted and recursive extraction may create loops or path traversal entries.",
            "A random-looking zsteg candidate needs structure or a flag-format match before acceptance.",
        ),
        "A deterministic command chain connects the original artifact to the recovered value.",
    ),
    Playbook(
        "forensics-incident-logs",
        "forensics",
        ("log", "incident", "access.log", "auth.log", "event", "powershell", "webshell"),
        "Build a short incident timeline that connects entry point, execution, persistence, and flag-bearing evidence.",
        (
            "Inventory timestamps, hosts, users, source addresses, event types, and available time zones.",
            "Find rare errors, authentication anomalies, encoded commands, uploads, process launches, and outbound connections.",
            "Normalize high-value events into chronological order and correlate identifiers across log sources.",
            "Decode or recover referenced payloads, then tie the answer to exact source lines and timestamps.",
        ),
        (
            "Keyword counts without a timeline do not establish causality.",
            "Normalize time zones before comparing events from different systems.",
        ),
        "A reproducible timeline cites the exact records that establish the requested incident fact.",
    ),
    Playbook(
        "forensics-windows-evtx",
        "forensics",
        ("evtx", "windows event", "event id", "sysmon", "powershell", "security.evtx"),
        "Reduce Windows event logs to the process, authentication, persistence, and cleanup events relevant to the incident.",
        (
            "Parse each EVTX with evtx_triage and preserve the generated XML beside the source log.",
            "Correlate logon IDs, process IDs, parent processes, users, hosts, and timestamps across Security, System, PowerShell, and Sysmon.",
            "Decode command lines and recover referenced scripts or payloads from companion artifacts.",
            "Build a chronological timeline and cite the exact event IDs and record values supporting the answer.",
        ),
        (
            "An event ID has different meaning across providers; retain provider/channel context.",
            "Process creation telemetry may be absent, so combine authentication, service, task, and script-block evidence.",
        ),
        "The timeline connects an initiating identity to a concrete process or persistence action and its artifacts.",
    ),
    Playbook(
        "forensics-deleted-files",
        "forensics",
        ("deleted", "filesystem", "disk image", "inode", "fls", "icat", "unallocated"),
        "Recover deleted or orphaned data from a known partition without modifying the source image.",
        (
            "Use disk_image_triage to record partition offsets and filesystem type.",
            "List deleted entries with filesystem_recover and copy the exact inode identifier from fls output.",
            "Recover one candidate at a time with icat, then identify and hash the output.",
            "Inspect filesystem timestamps and directory context before accepting recovered content as relevant.",
        ),
        (
            "An inode number without the correct partition offset can recover unrelated bytes.",
            "Never run repair tools against the only copy of a challenge image.",
        ),
        "A hashed recovered artifact is tied to a partition offset and exact TSK inode.",
    ),
    Playbook(
        "forensics-memory-incident",
        "forensics",
        ("memory dump", "ram", "volatility", "process", "malfind", "cmdline", "netscan"),
        "Use memory evidence to connect suspicious processes, commands, network activity, and recovered files.",
        (
            "Identify the operating system and kernel profile before running process-specific plugins.",
            "Enumerate process trees, command lines, consoles, network endpoints, loaded modules, and suspicious memory regions.",
            "Dump only evidence-supported processes or files and hash every recovered artifact.",
            "Correlate process IDs and timestamps with disk, network, and log evidence when provided.",
        ),
        (
            "Plugin failure often means the wrong OS symbol/profile, not absence of evidence.",
            "Large blind dumps waste time; pivot from named processes, paths, handles, or connections.",
        ),
        "A named memory object or process produces reproducible evidence answering the challenge question.",
    ),
    Playbook(
        "forensics-network-objects",
        "forensics",
        ("export objects", "file transfer", "http object", "smb", "ftp", "pcap"),
        "Recover transferred files from reassembled application streams and preserve their network provenance.",
        (
            "Use pcap_triage to identify protocols, endpoints, and stream indices before extraction.",
            "Call pcap_export_objects for the observed application protocol and inventory recovered files.",
            "Hash and identify each object, then recurse with artifact_triage only on relevant outputs.",
            "Tie the recovered value to protocol, endpoints, stream, and exported filename.",
        ),
        (
            "Packet-level strings may miss segmented or compressed application objects.",
            "Encrypted sessions require key material or a different evidence source.",
        ),
        "A recovered object and its flag-bearing content are reproducible from the original capture.",
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
