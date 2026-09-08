from __future__ import annotations

import json

import pytest

import midnight.evaluation.services as service_module
from midnight.env.container_manager import ExecResult
from midnight.evaluation.services import BenchmarkServiceManager


def _manifest(tmp_path):
    repository = tmp_path / "upstream"
    context = repository / "challenge"
    context.mkdir(parents=True)
    (context / "Dockerfile").write_text("FROM scratch\n")
    path = tmp_path / "private" / "services.json"
    path.parent.mkdir()
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_version": "abc123",
                "repository_root": "../upstream",
                "network": "midnight-test-targets",
                "tasks": {
                    "task-1": {
                        "context": "challenge",
                        "image": "midnight/target-test:abc123",
                        "target": "target_one:1337",
                    }
                },
            }
        )
    )
    return path


@pytest.mark.asyncio
async def test_service_manager_builds_and_records_digest(tmp_path, monkeypatch):
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, timeout=None):
        calls.append(args)
        if args[1:4] == ("image", "inspect", "--format"):
            return ExecResult(0, "sha256:1234\n", "")
        return ExecResult(0, "", "")

    monkeypatch.setattr(service_module, "_run", fake_run)
    manager = BenchmarkServiceManager(_manifest(tmp_path))
    digests = await manager.ensure_images()
    assert digests == {"_target/task-1": "sha256:1234"}
    assert any(call[1] == "build" for call in calls)
    assert manager.targets == {"task-1": "target_one:1337"}


def test_service_manager_rejects_context_escape(tmp_path):
    manager = BenchmarkServiceManager(_manifest(tmp_path))
    service = manager.manifest.tasks["task-1"].model_copy(update={"context": "../private"})
    with pytest.raises(ValueError, match="escapes repository root"):
        manager._paths(service)


def test_service_manager_accepts_private_dockerfile_override(tmp_path):
    path = _manifest(tmp_path)
    override = path.parent / "Dockerfile.override"
    override.write_text("FROM scratch\n")
    manager = BenchmarkServiceManager(path)
    service = manager.manifest.tasks["task-1"].model_copy(
        update={"dockerfile_override": "Dockerfile.override"}
    )
    _, selected = manager._paths(service)
    assert selected == override.resolve()
