"""Procedural knowledge and stagnation feedback tests."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from midnight.env.container_manager import ExecResult
from midnight.knowledge.playbooks import find_playbooks, render_playbooks
from midnight.tools.knowledge import make_lookup_playbook
from midnight.tools.shell import make_run_shell


def test_playbook_selection_uses_observable_signals():
    selected = find_playbooks("pwn", "ELF has PIE, no canary, stack leak and buffer overflow")
    assert selected[0].key == "pwn-pie-leak-rop"
    rendered = render_playbooks("crypto", "RSA with alternating decimal digits of p and q")
    assert "crypto-rsa-decimal-digit-leak" in rendered
    assert "p*q == n" in rendered
    assert find_playbooks("web", "Flask render_template_string Jinja SSTI")[0].key == "web-ssti"
    assert find_playbooks("forensics", "incident auth.log powershell")[0].key == (
        "forensics-incident-logs"
    )
    assert find_playbooks("forensics", "Windows Security.evtx Sysmon")[0].key == (
        "forensics-windows-evtx"
    )
    assert find_playbooks("web", "JWT bearer token alg HS256")[0].key == "web-jwt"
    assert find_playbooks("reverse", "binary protocol TLV length field")[0].key == (
        "reverse-kaitai-protocol"
    )
    assert find_playbooks("forensics", "many EVTX directory Sigma timeline")[0].key == (
        "forensics-hayabusa-timeline"
    )
    assert find_playbooks(
        "pwn", "unsafe Rust arr_ptr.offset read_exact into a fixed stack array"
    )[0].key == "pwn-oversized-stack-write"
    ret2libc = render_playbooks("pwn", "libc puts got plt system")
    assert "post-input banner" in ret2libc
    assert "recvline().rstrip()" in ret2libc
    xxe = render_playbooks("web", "XML XXE external entity parser")
    assert "root HTML and linked JavaScript" in xxe
    assert "generic flag regex" in xxe


def test_catalog_has_no_benchmark_specific_material():
    catalog = render_playbooks("pwn", "format string") + render_playbooks("reverse", "UPX")
    forbidden = ("Delulu", "PackedAway", "Partial Tenacity", "Were Pickle Phreaks")
    assert not any(name in catalog for name in forbidden)
    assert "flag{" not in catalog.lower()


def test_lookup_tool_is_bound_to_the_current_expert():
    tool = make_lookup_playbook(current_expert="reverse")
    result = tool.invoke({"evidence": "UPX0 UPX1 packed ELF"})
    assert "PLAYBOOK reverse-upx" in result


@dataclass
class FakeEnvironment:
    calls: int = 0

    async def exec(self, command: str) -> ExecResult:
        self.calls += 1
        return ExecResult(0, "same observation", "")


@pytest.mark.asyncio
async def test_repeated_identical_shell_observation_emits_stagnation_signal():
    env = FakeEnvironment()
    tool = make_run_shell(env=env)
    first = await tool.ainvoke({"command": "file ./chall"})
    second = await tool.ainvoke({"command": "  file   ./chall  "})
    assert "MIDNIGHT_STAGNATION" not in first
    assert "MIDNIGHT_STAGNATION" in second
