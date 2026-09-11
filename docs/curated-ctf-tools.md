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
| Web | TInjA | `tinja_ssti` | An evaluated template parameter needs multi-engine fingerprinting before choosing a payload |
| Web | Velocity 1.x adapter | `velocity_ssti` | Source or a harmless expression confirms Apache Velocity 1.x evaluation and command output must be recovered reliably |
| Web | jwt_tool | `jwt_analyze` | A JWT needs local decoding, mutation, bounded secret testing, or a target-bound verification scan |
| Pwn | pwninit | `pwninit_setup` | A challenge supplies an ELF plus libc and optionally its loader |
| Pwn | one_gadget | `one_gadget` | A libc leak/control-flow primitive exists and gadget constraints can be satisfied |
| Pwn | pwntools | `fmtstr_probe` | An uncontrolled printf needs one bounded positional leak pass |
| Pwn | pwntools | `run_exploit` | A complete solve.py must be checked and exercised locally or on the bound target |
| Crypto | xortool | `xor_analyze` | Repeating-key XOR is suspected and frequency or known plaintext is available |
| Crypto | RsaCtfTool | `rsa_attack` | Supplied RSA key files imply a known local key-recovery family beyond the fast raw-integer checks |
| Reverse | pyinstxtractor-ng | `pyinstaller_extract` | An ELF/PE is a PyInstaller bundle |
| Reverse | JADX | `android_decompile` | An APK or DEX needs source and resource recovery |
| Reverse | Kaitai Struct | `kaitai_compile` | A binary format or custom protocol needs an executable parser with explicit framing |
| Forensics | zsteg | `stego_scan` | PNG/BMP LSB steganography is plausible |
| Forensics | Volatility 3 | `memory_analyze` | A memory image needs process, network, registry, or kernel analysis |
| Forensics | Sleuthkit | `disk_image_triage` | A disk image needs partition discovery and filesystem enumeration |
| Forensics | tshark | `pcap_triage` | A capture needs protocol/conversation triage or an exact TCP stream transcript |
| Forensics | tshark | `pcap_stream_payload` | An opaque TCP stream needs bounded packet-level hex plus directional byte streams for decoder development |
| Forensics | Hayabusa | `hayabusa_timeline` | One or many EVTX logs need a normalized Sigma-enriched incident timeline |
| Forensics | log-audit | `log_audit` | One Web, authentication, application, or database log (or an immediate same-format directory) needs normalized events, rule detections, profiles, and IOC correlation |
| Forensics | Linux IR triage | `linux_ir_triage` | A recovered Linux host tree needs bounded account, permission, persistence, web, network, or MySQL UDF pivots |
| Misc/Forensics | 7-Zip | `archive_extract` | A supplied archive needs deterministic extraction and a bounded file inventory |
| Misc/Forensics | ZBar | `qr_decode` | A reconstructed PBM/PNG or suspicious image contains QR finder patterns or a module grid |
| Misc/Forensics | fcrackzip / 7-Zip | `archive_password` | A protected archive should be tested against a small or challenge-derived local candidate list |

Category images also expose common command-line tools used by strong public CTF
agents: angr, Unicorn, Capstone, ROPgadget and ropper for Pwn/Reverse; nmap,
sqlmap, nikto and whatweb for Web; Z3 and fpylll for Crypto; and binwalk,
foremost, ExifTool, steghide, OCR, audio/video utilities and filesystem tooling
for Misc/Forensics. Reverse includes radare2, UPX, JADX, apktool, LIEF,
Keystone, decompyle3 and Kaitai Struct. The forensics image includes Hayabusa's
bundled offline rules, YARA and bounded archive-password recovery.

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

Sage remains optional because of its image-size and mathematics-stack cost;
RsaCtfTool covers the common local RSA catalog in the current crypto image.
Ghidra remains optional because its distribution and Java runtime add hundreds
of megabytes on top of radare2, angr, JADX, GDB and objdump. Tools without an
explicit redistribution license are not built into published images.

Tool output is evidence, not a solution. A Fenjing finding must still be used
against the evaluator-provided challenge target, a one-gadget must satisfy its
listed constraints, and extracted artifacts must be inspected before any flag
is submitted.
