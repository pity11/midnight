from __future__ import annotations

import pytest

import midnight.env.container_manager as container_module
from midnight.env.container_manager import (
    ContainerManager,
    ExecResult,
    _apt_mirror,
    _docker_build_proxy,
)


def test_loopback_build_proxy_is_translated_for_docker():
    assert _docker_build_proxy("http://127.0.0.1:7890") == (
        "http://host.docker.internal:7890"
    )


def test_build_proxy_rejects_credentials():
    with pytest.raises(ValueError, match="authenticated"):
        _docker_build_proxy("http://user:secret@127.0.0.1:7890")


def test_apt_mirror_is_normalized_and_validated():
    assert _apt_mirror("https://mirrors.example.test/ubuntu/") == (
        "https://mirrors.example.test/ubuntu"
    )
    with pytest.raises(ValueError, match="plain http"):
        _apt_mirror("https://user:secret@mirrors.example.test/ubuntu")


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
async def test_target_only_solver_uses_internal_network(monkeypatch):
    calls: list[tuple[str, ...]] = []

    async def fake_ensure(self, ctype):
        return "midnight/pwn:latest"

    async def fake_run(*args: str, timeout=None):
        calls.append(args)
        if args[1:3] == ("network", "inspect"):
            return ExecResult(1, "", "missing")
        if args[1] == "run":
            return ExecResult(0, "solver-id\n", "")
        return ExecResult(0, "", "")

    monkeypatch.setattr(ContainerManager, "ensure_image", fake_ensure)
    monkeypatch.setattr(container_module, "_run", fake_run)
    await ContainerManager(run_id="run-1").create("pwn", "test", network_policy="target_only")
    assert ("docker", "network", "create", "--internal", "midnight-run-1-targets") in calls
    docker_run = next(call for call in calls if call[1] == "run")
    assert docker_run[docker_run.index("--network") + 1] == "midnight-run-1-targets"


@pytest.mark.asyncio
async def test_target_relay_has_fixed_destination_and_dual_network(monkeypatch):
    calls: list[tuple[str, ...]] = []

    async def fake_target_network(self):
        return "internal-net"

    async def fake_relay_image(self):
        return "relay:fixed"

    async def fake_run(*args: str, timeout=None):
        calls.append(args)
        if args[1] == "run":
            return ExecResult(0, "relay-id\n", "")
        return ExecResult(0, "", "")

    monkeypatch.setattr(ContainerManager, "ensure_target_network", fake_target_network)
    monkeypatch.setattr(ContainerManager, "ensure_relay_image", fake_relay_image)
    monkeypatch.setattr(container_module, "_run", fake_run)
    runtime_target = await ContainerManager(run_id="run-1").prepare_target_relay(
        "challenge.local:31337"
    )
    assert runtime_target.endswith(":31337")
    docker_run = next(call for call in calls if call[1] == "run")
    assert "TCP:challenge.local:31337" in docker_run
    assert any(call[1:3] == ("network", "connect") for call in calls)
