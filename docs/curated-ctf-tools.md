# Curated CTF tool integration

Midnight gives small models narrow, structured actions for common mechanical
CTF work. The goal is to save model turns after the model has identified a
technique, while preserving the model's responsibility for interpreting the
evidence and verifying a flag.

The first integrated pack is deliberately small:

| Category | Tool | Midnight action | Use when |
| --- | --- | --- | --- |
| Web | Fenjing | `fenjing_ssti` | A Jinja2 expression is reflected/evaluated, especially behind a blacklist or WAF |
| Pwn | pwninit | `pwninit_setup` | A challenge supplies an ELF plus libc and optionally its loader |
| Pwn | one_gadget | `one_gadget` | A libc leak/control-flow primitive exists and gadget constraints can be satisfied |
| Crypto | xortool | `xor_analyze` | Repeating-key XOR is suspected and frequency or known plaintext is available |
| Reverse | pyinstxtractor-ng | `pyinstaller_extract` | An ELF/PE is a PyInstaller bundle |
| Forensics | zsteg | `stego_scan` | PNG/BMP LSB steganography is plausible |

The tools are installed during image construction and remain available when a
benchmark run disables general internet access. Each action accepts typed
parameters and quotes paths/values before executing the upstream CLI. Direct
shell access remains available for options that a wrapper does not expose.

Build all specialist images as `linux/amd64`, matching `config/images.yaml`.
For example, when Clash exposes port 7890 on the host:

```sh
docker buildx build --load --platform linux/amd64 \
  --build-arg APT_MIRROR=http://mirrors.tuna.tsinghua.edu.cn/ubuntu \
  --build-arg HTTP_PROXY=http://host.docker.internal:7890 \
  --build-arg HTTPS_PROXY=http://host.docker.internal:7890 \
  -t midnight/web:latest -f docker/web.Dockerfile .
```

`config/toolpacks.yaml` records source, version, license, command, and purpose.
It also records reviewed tools that have been deferred because of image cost,
overlap, architecture, or licensing. Third-party programs run as separate
processes and keep their upstream licenses; the repository does not copy their
source code.

Larger candidates remain separate on purpose. RsaCtfTool may become a
crypto-heavy image when RSA coverage justifies its factorization/Sage
dependencies; angr belongs in a symbolic reverse image; Volatility 3 needs a
versioned symbol workflow; TInjA adds multi-engine SSTI coverage after the
Jinja2-focused path is measured. Tools without an explicit redistribution
license are not built into published images.

Tool output is evidence, not a solution. A Fenjing finding must still be used
against the evaluator-provided challenge target, a one-gadget must satisfy its
listed constraints, and extracted artifacts must be inspected before any flag
is submitted.
