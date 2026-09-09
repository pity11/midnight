# Curated CTF tool integration

Midnight gives small models narrow, structured actions for common mechanical
CTF work. The goal is to save model turns after the model has identified a
technique, while preserving the model's responsibility for interpreting the
evidence and verifying a flag.

The integrated pack combines structured actions with a broader shell-accessible
tool layer:

| Category | Tool | Midnight action | Use when |
| --- | --- | --- | --- |
| Web | Fenjing | `fenjing_ssti` | A Jinja2 expression is reflected/evaluated, especially behind a blacklist or WAF |
| Pwn | pwninit | `pwninit_setup` | A challenge supplies an ELF plus libc and optionally its loader |
| Pwn | one_gadget | `one_gadget` | A libc leak/control-flow primitive exists and gadget constraints can be satisfied |
| Crypto | xortool | `xor_analyze` | Repeating-key XOR is suspected and frequency or known plaintext is available |
| Reverse | pyinstxtractor-ng | `pyinstaller_extract` | An ELF/PE is a PyInstaller bundle |
| Reverse | JADX | `android_decompile` | An APK or DEX needs source and resource recovery |
| Forensics | zsteg | `stego_scan` | PNG/BMP LSB steganography is plausible |
| Forensics | Volatility 3 | `memory_analyze` | A memory image needs process, network, registry, or kernel analysis |
| Forensics | Sleuthkit | `disk_image_triage` | A disk image needs partition discovery and filesystem enumeration |

Category images also expose common command-line tools used by strong public CTF
agents: angr, Unicorn, Capstone, ROPgadget and ropper for Pwn/Reverse; nmap,
sqlmap, nikto and whatweb for Web; Z3 and fpylll for Crypto; and binwalk,
foremost, ExifTool, steghide, OCR, audio/video utilities and filesystem tooling
for Misc/Forensics. Reverse includes radare2, UPX, JADX and apktool.

The tools are installed during image construction and remain available when a
benchmark run disables general internet access. Each action accepts typed
parameters and quotes paths/values before executing the upstream CLI. Direct
shell access remains available for options that a wrapper does not expose.

Build all specialist images as `linux/amd64`, matching `config/images.yaml`.
The supported entry point verifies the installed capabilities offline:

```sh
export MIDNIGHT_BUILD_PROXY=http://127.0.0.1:7890
export MIDNIGHT_APT_MIRROR=http://mirrors.tuna.tsinghua.edu.cn/ubuntu
uv run midnight --check-sandboxes
```

`config/toolpacks.yaml` records source, version, license, command, and purpose.
It also records reviewed tools that have been deferred because of image cost,
overlap, architecture, or licensing. Third-party programs run as separate
processes and keep their upstream licenses; the repository does not copy their
source code.

RsaCtfTool and Sage remain candidates for a crypto-heavy layer because of their
factorization and image-size cost. Ghidra remains optional because its current
distribution and Java runtime add hundreds of megabytes on top of radare2,
angr, JADX, GDB and objdump. TInjA can add multi-engine SSTI coverage after the
Jinja2-focused path is measured. Tools without an explicit redistribution
license are not built into published images.

Tool output is evidence, not a solution. A Fenjing finding must still be used
against the evaluator-provided challenge target, a one-gadget must satisfy its
listed constraints, and extracted artifacts must be inspected before any flag
is submitted.
