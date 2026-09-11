from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import midnight.env.container_manager as container_module
from midnight.config import AppConfig, SandboxProfile
from midnight.env.container_manager import (
    ContainerManager,
    ExecResult,
    _apt_mirror,
    _docker_build_proxy,
    _docker_workspace_path,
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


def test_challenge_scopes_get_distinct_container_and_network_names():
    first = ContainerManager(run_id="run-1", scope_id="run-1-challenge-a")
    second = ContainerManager(run_id="run-1", scope_id="run-1-challenge-b")
    assert first.container_name("relay") != second.container_name("relay")
    assert first.scope_id != second.scope_id


def test_external_macos_workspace_uses_docker_visible_fallback(monkeypatch):
    monkeypatch.setattr(container_module._platform, "system", lambda: "Darwin")
    monkeypatch.delenv("MIDNIGHT_DOCKER_WORKSPACE_ROOT", raising=False)

    first = _docker_workspace_path(Path("/Volumes/External/project/run-1"))
    second = _docker_workspace_path(Path("/Volumes/External/project/run-1"))

    assert first == second
    assert first.parent == Path("/private/tmp/midnight-workspaces")
    assert len(first.name) == 24


def test_workspace_fallback_root_can_be_overridden(monkeypatch, tmp_path):
    monkeypatch.setattr(container_module._platform, "system", lambda: "Darwin")
    monkeypatch.setenv("MIDNIGHT_DOCKER_WORKSPACE_ROOT", str(tmp_path))

    workspace = _docker_workspace_path(Path("/Volumes/External/project/run-1"))

    assert workspace.parent == tmp_path.resolve()


def test_non_external_workspace_is_unchanged(monkeypatch, tmp_path):
    monkeypatch.setattr(container_module._platform, "system", lambda: "Darwin")
    assert _docker_workspace_path(tmp_path) == tmp_path.resolve()


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
async def test_challenge_workspace_is_created_and_bind_mounted(monkeypatch, tmp_path):
    calls: list[tuple[str, ...]] = []

    async def fake_ensure(self, ctype):
        return "midnight/misc:latest"

    async def fake_run(*args: str, timeout=None):
        calls.append(args)
        if args[1] == "run":
            return ExecResult(0, "solver-id\n", "")
        return ExecResult(0, "", "")

    monkeypatch.setattr(ContainerManager, "ensure_image", fake_ensure)
    monkeypatch.setattr(container_module, "_run", fake_run)
    workspace = tmp_path / "run-1" / "misc-1"
    manager = ContainerManager(run_id="run-1", workspace_host_dir=workspace)
    await manager.create("misc", "test", network_policy="disabled")

    docker_run = next(call for call in calls if call[1] == "run")
    mount = docker_run[docker_run.index("--mount") + 1]
    assert mount == f"type=bind,source={workspace.resolve()},target=/ctf"
    assert workspace.is_dir()


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


@pytest.mark.asyncio
async def test_sandbox_preflight_checks_commands_and_python_modules(monkeypatch):
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, timeout=None):
        calls.append(args)
        return ExecResult(0, "", "")

    monkeypatch.setattr(container_module, "_run", fake_run)
    config = AppConfig.model_construct(
        sandbox_profiles={
            "pwn": SandboxProfile(
                required_commands=["gdb", "checksec"],
                required_python_modules=["pwn"],
            )
        }
    )
    await ContainerManager(config=config).validate_sandbox("pwn", "container-1")

    docker_exec = calls[-1]
    assert docker_exec[:4] == ("docker", "exec", "container-1", "bash")
    assert "command -v" in docker_exec[-1]
    assert "python3 -c" in docker_exec[-1]


@pytest.mark.asyncio
async def test_sandbox_preflight_reports_missing_capability(monkeypatch):
    async def fake_run(*args: str, timeout=None):
        return ExecResult(42, "", " command:gdb python:pwn\n")

    monkeypatch.setattr(container_module, "_run", fake_run)
    config = AppConfig.model_construct(
        sandbox_profiles={"pwn": SandboxProfile(required_commands=["gdb"])}
    )
    with pytest.raises(RuntimeError, match=r"sandbox preflight failed.*command:gdb"):
        await ContainerManager(config=config).validate_sandbox("pwn", "container-1")


@pytest.mark.asyncio
async def test_image_preflight_runs_offline(monkeypatch):
    calls: list[tuple[str, ...]] = []

    async def fake_ensure(self, ctype):
        return "midnight/pwn:latest"

    async def fake_run(*args: str, timeout=None):
        calls.append(args)
        return ExecResult(0, "", "")

    monkeypatch.setattr(ContainerManager, "ensure_image", fake_ensure)
    monkeypatch.setattr(container_module, "_run", fake_run)
    config = AppConfig.model_construct(
        images={
            "pwn": SimpleNamespace(
                image="midnight/pwn:latest",
                platform="linux/amd64",
            )
        },
        sandbox_profiles={"pwn": SandboxProfile(required_commands=["gdb"])},
    )
    await ContainerManager(config=config).validate_image("pwn")

    invocation = calls[-1]
    assert invocation[:5] == ("docker", "run", "--rm", "--network", "none")
    image_index = invocation.index("midnight/pwn:latest")
    assert invocation[5:image_index] in ((), ("--platform", "linux/amd64"))
    assert invocation[image_index + 1] == "bash"


def test_sandbox_profile_rejects_shell_fragments():
    with pytest.raises(ValueError, match="plain executable"):
        SandboxProfile(required_commands=["gdb;id"])
    with pytest.raises(ValueError, match="importable Python"):
        SandboxProfile(required_python_modules=["pwn;import os"])
