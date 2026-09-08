from __future__ import annotations

import pytest

import midnight.env.container_manager as container_module
from midnight.env.container_manager import ContainerManager, ExecResult


def test_container_names_are_run_scoped_and_sanitized():
    first = ContainerManager(run_id="run/one")
    second = ContainerManager(run_id="run-two")
    assert first.container_name("web/1") == "midnight-run-one-web-1"
    assert first.container_name("web/1") != second.container_name("web/1")
    assert len(first.container_name("x" * 100)) <= 66


@pytest.mark.asyncio
async def test_cleanup_run_uses_managed_run_labels(monkeypatch):
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, timeout=None):
        calls.append(args)
        if args[1:3] == ("ps", "-aq"):
            return ExecResult(0, "container-a\ncontainer-b\n", "")
        return ExecResult(0, "", "")

    monkeypatch.setattr(container_module, "_run", fake_run)
    removed = await ContainerManager(run_id="run-1").cleanup_run()

    assert removed == 2
    assert any("label=midnight.managed=true" in call for call in calls)
    assert any("label=midnight.run_id=run-1" in call for call in calls)
    assert ("docker", "rm", "-f", "container-a") in calls


@pytest.mark.asyncio
async def test_image_digest_resolves_immutable_id(monkeypatch):
    async def fake_ensure(self, ctype):
        return "midnight/pwn:latest"

    async def fake_run(*args: str, timeout=None):
        return ExecResult(0, "sha256:" + "a" * 64 + "\n", "")

    monkeypatch.setattr(ContainerManager, "ensure_image", fake_ensure)
    monkeypatch.setattr(container_module, "_run", fake_run)
    digest = await ContainerManager().image_digest("pwn")
    assert digest == "sha256:" + "a" * 64


@pytest.mark.asyncio
async def test_target_only_network_fails_closed(monkeypatch):
    async def fake_ensure(self, ctype):
        return "midnight/pwn:latest"

    monkeypatch.setattr(ContainerManager, "ensure_image", fake_ensure)
    with pytest.raises(NotImplementedError, match="target-only"):
        await ContainerManager().create("pwn", "test", network_policy="target_only")
