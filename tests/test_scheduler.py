from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from midnight.interfaces.submitter import SubmitResult
from midnight.orchestrator.scheduler import (
    Result,
    Scheduler,
    _checkpoint_progress,
    _transcript_metrics,
)


class FixtureProvider:
    def __init__(self, source: Path):
        self.source = source
        self.download_calls = 0

    async def list_challenges(self):
        return []

    async def fetch(self, challenge_id: str):
        return {
            "id": challenge_id,
            "name": challenge_id,
            "description": "fixture",
            "category_hint": "pwn",
            "files": [],
        }

    async def download_files(self, challenge_id: str, dest: str):
        self.download_calls += 1
        target = Path(dest) / self.source.name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(self.source.read_bytes())
        return [str(target)]


class NoopSubmitter:
    async def submit(self, challenge_id: str, flag: str):
        return SubmitResult(accepted=True)


@pytest.mark.asyncio
async def test_hydration_downloads_files_and_assigns_content_revision(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"version one")
    provider = FixtureProvider(source)
    scheduler = Scheduler(
        provider=provider,
        submitter=NoopSubmitter(),
        artifacts_root=tmp_path / "artifacts",
        run_id="run-1",
    )

    first = await scheduler._hydrate({"id": "pwn-1"})
    source.write_bytes(b"version two")
    second = await scheduler._hydrate({"id": "pwn-1"})

    assert provider.download_calls == 2
    assert first["source_hash"] != second["source_hash"]
    assert len(first["file_hashes"]["source.bin"]) == 64


@pytest.mark.asyncio
async def test_native_binary_category_limit_is_shared(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"fixture")
    provider = FixtureProvider(source)
    scheduler = Scheduler(
        provider=provider,
        submitter=NoopSubmitter(),
        artifacts_root=tmp_path / "artifacts",
        run_id="run-1",
        max_concurrency=2,
    )
    active = 0
    maximum_active = 0

    async def fake_solve(challenge):
        nonlocal active, maximum_active
        active += 1
        maximum_active = max(maximum_active, active)
        await asyncio.sleep(0.02)
        active -= 1
        return Result(challenge["id"], "failed")

    scheduler._solve_one = fake_solve
    await scheduler.solve_all([{"id": "pwn-1"}, {"id": "pwn-2"}])

    assert maximum_active == 1


@pytest.mark.asyncio
async def test_unsafe_challenge_id_is_rejected(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"fixture")
    scheduler = Scheduler(
        provider=FixtureProvider(source),
        submitter=NoopSubmitter(),
        artifacts_root=tmp_path,
    )
    with pytest.raises(ValueError, match="unsafe challenge id"):
        await scheduler._hydrate({"id": "../escape"})


def test_transcript_metrics_count_usage_repeats_and_errors():
    messages = [
        SimpleNamespace(
            type="ai",
            usage_metadata={"input_tokens": 20, "output_tokens": 5},
            additional_kwargs={"midnight_protocol_error": "MODEL_EMPTY_CONTENT"},
            tool_calls=[
                {"name": "run_shell", "args": {"command": "file chall"}},
                {"name": "run_shell", "args": {"command": "file chall"}},
            ],
            content="",
        ),
        SimpleNamespace(
            type="tool",
            usage_metadata={},
            additional_kwargs={},
            tool_calls=[],
            content="failed\n[exit=1]",
        ),
    ]
    metrics = _transcript_metrics(messages)
    assert metrics == {
        "input_tokens": 20,
        "output_tokens": 5,
        "tool_calls": 2,
        "repeated_tool_calls": 1,
        "tool_errors": 1,
        "protocol_recoveries": 1,
    }


def test_checkpoint_progress_deduplicates_nested_messages():
    message = SimpleNamespace(
        id="message-1",
        type="ai",
        usage_metadata={"input_tokens": 12, "output_tokens": 3},
        additional_kwargs={},
        tool_calls=[{"name": "pcap_triage", "args": {"path": "capture.pcap"}}],
        content="",
    )
    progress = _checkpoint_progress(
        [
            {"attempt": 1, "messages": [message]},
            {"attempt": 2, "messages": [message]},
        ]
    )
    assert progress["attempts"] == 2
    assert progress["input_tokens"] == 12
    assert progress["output_tokens"] == 3
    assert progress["tool_calls"] == 1


def test_scheduler_rejects_unknown_agent_mode(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"fixture")
    with pytest.raises(ValueError, match="unknown agent mode"):
        Scheduler(
            provider=FixtureProvider(source),
            submitter=NoopSubmitter(),
            agent_mode="unknown",
        )


def test_scheduler_rejects_unsafe_run_id(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"fixture")
    with pytest.raises(ValueError, match="unsafe run id"):
        Scheduler(
            provider=FixtureProvider(source),
            submitter=NoopSubmitter(),
            run_id="../other-run",
        )


def test_scheduler_prioritizes_easy_tasks_then_category():
    ordered = sorted(
        [
            {"id": "hard-misc", "difficulty": "hard", "category_hint": "misc"},
            {"id": "easy-pwn", "difficulty": "easy", "category_hint": "pwn"},
            {"id": "easy-crypto", "difficulty": "easy", "category_hint": "crypto"},
            {"id": "medium-web", "difficulty": "medium", "category_hint": "web"},
        ],
        key=Scheduler._priority_key,
    )
    assert [item["id"] for item in ordered] == [
        "easy-crypto",
        "easy-pwn",
        "medium-web",
        "hard-misc",
    ]


@pytest.mark.asyncio
async def test_global_run_timeout_is_shared_by_all_tasks(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"fixture")
    scheduler = Scheduler(
        provider=FixtureProvider(source),
        submitter=NoopSubmitter(),
        artifacts_root=tmp_path / "artifacts",
        run_id="timed-run",
        max_concurrency=1,
        per_task_timeout=10,
        run_timeout=0.05,
    )

    async def slow_solve(challenge):
        await asyncio.sleep(1)
        return Result(challenge["id"], "failed")

    scheduler._solve_one = slow_solve
    started = asyncio.get_running_loop().time()
    results = await scheduler.solve_all([{"id": "pwn-1"}, {"id": "pwn-2"}])
    elapsed = asyncio.get_running_loop().time() - started
    assert elapsed < 0.3
    assert [result.status for result in results] == ["timeout", "timeout"]


@pytest.mark.asyncio
async def test_task_timeout_recovers_durable_checkpoint_metrics(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"fixture")
    message = SimpleNamespace(
        id="durable-message",
        type="ai",
        usage_metadata={"input_tokens": 7, "output_tokens": 2},
        additional_kwargs={},
        tool_calls=[{"name": "log_triage", "args": {"path": "."}}],
        content="",
    )

    class DurableStore:
        def latest_channel_values(self, thread_id):
            assert thread_id.startswith("timed-run:pwn-1:")
            return [{"attempt": 2, "messages": [message]}]

    scheduler = Scheduler(
        provider=FixtureProvider(source),
        submitter=NoopSubmitter(),
        artifacts_root=tmp_path / "artifacts",
        run_id="timed-run",
        per_task_timeout=0.01,
        checkpoint_store=DurableStore(),
    )

    async def slow_solve(challenge):
        await asyncio.sleep(1)
        return Result(challenge["id"], "failed")

    scheduler._solve_one = slow_solve
    result = (await scheduler.solve_all([{"id": "pwn-1"}]))[0]
    assert result.status == "timeout"
    assert result.attempts == 2
    assert result.input_tokens == 7
    assert result.output_tokens == 2
    assert result.tool_calls == 1


@pytest.mark.asyncio
async def test_managed_provider_instance_is_always_stopped(tmp_path):
    class ManagedProvider(FixtureProvider):
        def __init__(self, source):
            super().__init__(source)
            self.started = False
            self.stopped = False

        async def start_challenge(self, challenge_id: str):
            self.started = True

        async def stop_challenge(self, challenge_id: str):
            self.stopped = True

        async def fetch(self, challenge_id: str):
            assert self.started
            return await super().fetch(challenge_id)

    source = tmp_path / "source.bin"
    source.write_bytes(b"fixture")
    provider = ManagedProvider(source)
    scheduler = Scheduler(provider=provider, submitter=NoopSubmitter(), artifacts_root=tmp_path)

    async def fail_after_start(challenge):
        raise RuntimeError("solver failed")

    scheduler._solve_one = fail_after_start
    result = (await scheduler.solve_all([{"id": "managed-1"}]))[0]
    assert result.status == "failed"
    assert provider.started
    assert provider.stopped


@pytest.mark.asyncio
async def test_static_tasks_run_broadly_while_interactive_instances_are_capped(tmp_path):
    class ManagedProvider(FixtureProvider):
        def __init__(self, source):
            super().__init__(source)
            self.active_instances = 0
            self.maximum_instances = 0

        async def start_challenge(self, challenge_id: str):
            if challenge_id.startswith("remote-"):
                self.active_instances += 1
                self.maximum_instances = max(
                    self.maximum_instances,
                    self.active_instances,
                )

        async def stop_challenge(self, challenge_id: str):
            if challenge_id.startswith("remote-"):
                self.active_instances -= 1

        async def fetch(self, challenge_id: str):
            challenge = await super().fetch(challenge_id)
            challenge["category_hint"] = "misc"
            return challenge

    source = tmp_path / "source.bin"
    source.write_bytes(b"fixture")
    provider = ManagedProvider(source)
    scheduler = Scheduler(
        provider=provider,
        submitter=NoopSubmitter(),
        artifacts_root=tmp_path / "artifacts",
        max_concurrency=8,
        platform_instance_concurrency=2,
    )
    active_solves = 0
    maximum_solves = 0

    async def fake_solve(challenge):
        nonlocal active_solves, maximum_solves
        active_solves += 1
        maximum_solves = max(maximum_solves, active_solves)
        await asyncio.sleep(0.02)
        active_solves -= 1
        return Result(challenge["id"], "failed")

    scheduler._solve_one = fake_solve
    challenges = [
        *[{"id": f"static-{index}", "interactive": False} for index in range(6)],
        *[{"id": f"remote-{index}", "interactive": True} for index in range(4)],
    ]

    await scheduler.solve_all(challenges)

    assert maximum_solves > 2
    assert provider.maximum_instances == 2
    assert provider.active_instances == 0


@pytest.mark.asyncio
async def test_scheduler_preserves_hydrated_metadata_on_solver_failure(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"fixture")
    scheduler = Scheduler(
        provider=FixtureProvider(source),
        submitter=NoopSubmitter(),
        artifacts_root=tmp_path / "artifacts",
    )

    async def fail(challenge):
        raise RuntimeError("graph failed")

    scheduler._solve_one = fail
    result = (await scheduler.solve_all([{"id": "pwn-1"}]))[0]
    assert result.status == "failed"
    assert result.category == "pwn"
    assert result.revision is not None
