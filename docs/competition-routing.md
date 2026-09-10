# Competition challenge routing

The organizer API supplies `category`, `description`, `file_url`, `interactive`,
`capabilities`, `connection`, and optional `extensions`. Midnight preserves the
platform hint and context, downloads attachments, and classifies from the hint,
title, description, and file names before creating the category sandbox.

| Handbook direction | Midnight route | Main sandbox capabilities |
| --- | --- | --- |
| Website security | `web` | HTTP requests, curl, ffuf, sqlmap, Fenjing, TInjA, JWT tooling |
| Binary exploitation | `pwn` | file/checksec, GDB, pwntools, ROP tools, pwninit, one_gadget, seccomp tools |
| Reverse engineering | `reverse` | file/strings, objdump, GDB, radare2, UPX, Android and PyInstaller tooling |
| Cryptography | `crypto` | OpenSSL, PyCryptodome, SymPy, gmpy2, Z3, fpylll, RsaCtfTool, xortool |
| Forensic analysis | `forensics` | artifact and log triage, Volatility, EVTX, Hayabusa, Sleuth Kit, TestDisk, tshark |
| Complex web application testing | `web` | web specialist with source audit and target-bound verification |
| Binary vulnerabilities | `pwn` | pwn specialist with local and target exploit verification |
| Reverse engineering and complex protocols | `reverse` | reverse specialist; may ask crypto or pwn expert in the same workspace |
| Cryptanalysis | `crypto` | crypto specialist with invariant-driven solver scripts |
| Incident response and log forensics | `forensics` | dedicated timeline, event, memory, disk, and packet workflows |

The normalized route selects both an agent toolset in `config/tools.yaml` and a
Docker image in `config/images.yaml`. Required image commands and Python modules
are the executable contract in `config/sandbox_profiles.yaml`; `local-preflight`
fails if any required capability is missing.

Unknown or novel labels are classified by the model. The `unknown` fallback uses
the misc sandbox for safe file triage, and specialists can use `ask_expert` for a
cross-category subproblem. The organizer's Chinese labels for all second- and
third-stage handbook directions are normalized deterministically before this
fallback is needed.
