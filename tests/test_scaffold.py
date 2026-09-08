"""M0 scaffold tests: config loads, registry populates, flag util, mock provider.

These intentionally avoid importing langchain/langgraph/docker so they run in a
bare environment right after scaffolding.
"""

import asyncio
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def test_config_loads():
    from midnight.config import get_config

    cfg = get_config()
    assert "default" in cfg.models
    assert "pwn" in cfg.images
    assert cfg.images["pwn"].platform == "linux/amd64"
    assert cfg.settings.escalation_max_depth == 2
    # tools.yaml anchor expansion: pwn must include common + its own tools
    assert "run_shell" in cfg.tools["pwn"]
    assert "ask_expert" in cfg.tools["pwn"]
    assert "gdb_tool" in cfg.tools["pwn"]
    # common-only experts still get the shared tools
    assert "run_shell" in cfg.tools["crypto"]
    assert "gdb_tool" not in cfg.tools["crypto"]


def test_tools_dedup_order():
    from midnight.config import get_config

    pwn = get_config().tools["pwn"]
    assert len(pwn) == len(set(pwn)), "tool list should be de-duplicated"


def test_flag_extraction():
    from midnight.utils.flag import extract_flags

    text = "junk\nflag{abc_123}\nmore flag{abc_123} dup\nflag{second}"
    flags = extract_flags(text, flag_format=r"flag\{[^}]+\}")
    assert flags == ["flag{abc_123}", "flag{second}"]


def test_image_fallback():
    from midnight.env.images import image_for

    spec = image_for("unknown")
    assert spec.image.endswith("misc:latest") or "misc" in spec.image


def test_escalation_guard():
    from midnight.tools.ask_expert import check_escalation

    ok = check_escalation(current_expert="web", target_type="pwn", depth=0, stack=[], max_depth=2)
    assert ok.ok
    # cycle
    cyc = check_escalation(
        current_expert="pwn", target_type="web", depth=1, stack=["web"], max_depth=2
    )
    assert not cyc.ok
    # depth cap
    cap = check_escalation(current_expert="web", target_type="pwn", depth=2, stack=[], max_depth=2)
    assert not cap.ok


def test_registry_populated():
    import midnight.tools  # noqa: F401  triggers registration
    from midnight.tools.registry import REGISTRY

    names = REGISTRY.names()
    assert "run_shell" in names
    assert "ask_expert" in names
    assert "submit_flag" in names


def test_local_provider_lists_fixture():
    from midnight.interfaces.local_mock import LocalDirProvider

    provider = LocalDirProvider(FIXTURES)
    challenges = asyncio.run(provider.list_challenges())
    ids = {c["id"] for c in challenges}
    assert "sanity_misc" in ids
    ch = next(c for c in challenges if c["id"] == "sanity_misc")
    assert ch["category_hint"] == "misc"
    assert len(ch["files"]) == 1


def test_manual_submitter_verdict():
    from midnight.interfaces.local_mock import ManualSubmitter

    sub = ManualSubmitter(FIXTURES)
    good = asyncio.run(sub.submit("sanity_misc", "flag{hello_midnight}"))
    bad = asyncio.run(sub.submit("sanity_misc", "flag{wrong}"))
    assert good.accepted
    assert not bad.accepted


def test_initial_state():
    from midnight.state import initial_state

    st = initial_state({"id": "x", "name": "x", "description": "", "files": []})
    assert st["status"] == "running"
    assert st["escalation_depth"] == 0
    assert st["candidate_flags"] == []
