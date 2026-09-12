"""Concurrent scheduler: solve many challenges in parallel.

Each challenge gets its own compiled graph instance and its own container; an
asyncio.Semaphore caps concurrency; per-task timeout + finally-cleanup prevent
container leaks. Skeleton at M0; ties into build_main_graph at M4.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, replace
from pathlib import Path
from uuid import uuid4

from midnight.config import get_config
from midnight.env.container_manager import ContainerManager
from midnight.events import EventJournal, RunEvent
from midnight.interfaces.provider import ChallengeProvider, ManagedChallengeProvider
from midnight.interfaces.submitter import FlagSubmitter
from midnight.persistence import CheckpointStore
from midnight.state import Challenge, initial_state
from midnight.utils.logging import get_logger

log = get_logger(__name__)


def _sha256_file(path: Path) -> tuple[str, str]:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return path.name, digest.hexdigest()


@dataclass
class Result:
    challenge_id: str
    status: str
    flag: str | None = None
    error: str | None = None
    duration_seconds: float = 0.0
    revision: str | None = None
    category: str | None = None
    attempts: int = 0
    points: int | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    repeated_tool_calls: int = 0
    tool_errors: int = 0
    flags_solved: int = 0
    flags_available: int = 1
    protocol_recoveries: int = 0
    model_transport_failures: int = 0


def _transcript_metrics(messages: list) -> dict[str, int]:
    """Extract provider-neutral usage and tool activity from graph messages."""
    input_tokens = 0
    output_tokens = 0
    tool_calls = 0
    tool_errors = 0
    protocol_recoveries = 0
    call_counts: dict[str, int] = {}
    for message in messages:
        if (getattr(message, "additional_kwargs", None) or {}).get("midnight_protocol_error"):
            protocol_recoveries += 1
        usage = getattr(message, "usage_metadata", None) or {}
        input_tokens += int(usage.get("input_tokens", 0) or 0)
        output_tokens += int(usage.get("output_tokens", 0) or 0)
        calls = getattr(message, "tool_calls", None) or []
        for call in calls:
            name = str(call.get("name") or "")
            args = call.get("args") or {}
            signature = json.dumps([name, args], sort_keys=True, ensure_ascii=False, default=str)
            call_counts[signature] = call_counts.get(signature, 0) + 1
            tool_calls += 1
        if getattr(message, "type", "") == "tool":
            content = str(getattr(message, "content", ""))
            if "[error]" in content or re.search(r"\[exit=[1-9][0-9]*\]", content):
                tool_errors += 1
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "tool_calls": tool_calls,
        "repeated_tool_calls": sum(max(count - 1, 0) for count in call_counts.values()),
        "tool_errors": tool_errors,
        "protocol_recoveries": protocol_recoveries,
    }


def _checkpoint_progress(states: list[dict]) -> dict[str, int]:
    """Merge nested checkpoint state into deduplicated timeout metrics."""
    messages: list = []
    seen: set[str] = set()
    attempts = 0
    model_transport_failures = 0
    for state in states:
        attempts = max(attempts, int(state.get("attempt", 0) or 0))
        model_transport_failures = max(
            model_transport_failures,
            int(state.get("model_transport_failures", 0) or 0),
        )
        for message in state.get("messages") or []:
            identity = getattr(message, "id", None)
            if not identity:
                identity = hashlib.sha256(repr(message).encode()).hexdigest()
            if identity in seen:
                continue
            seen.add(identity)
            messages.append(message)
    return {
        "attempts": attempts,
        "model_transport_failures": model_transport_failures,
        **_transcript_metrics(messages),
    }


class Scheduler:
    def __init__(
        self,
        *,
        provider: ChallengeProvider,
        submitter: FlagSubmitter,
        max_concurrency: int | None = None,
        platform_instance_concurrency: int = 2,
        per_task_timeout: int | None = None,
        run_timeout: float | None = None,
        journal: EventJournal | None = None,
        run_id: str | None = None,
        checkpoint_store: CheckpointStore | None = None,
        artifacts_root: str | Path = "logs/artifacts",
        workspace_root: str | Path = "logs/workspaces",
        agent_mode: str = "midnight",
    ):
        cfg = get_config().settings
        self.provider = provider
        self.submitter = submitter
        self.max_concurrency = max_concurrency or cfg.max_concurrency
        if platform_instance_concurrency <= 0:
            raise ValueError("platform_instance_concurrency must be positive")
        self._platform_instance_limit = asyncio.Semaphore(platform_instance_concurrency)
        self.per_task_timeout = per_task_timeout or cfg.per_task_timeout
        self.run_timeout = run_timeout
        self.journal = journal
        self.run_id = run_id or uuid4().hex
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", self.run_id):
            raise ValueError(f"unsafe run id: {self.run_id!r}")
        self.checkpoint_store = checkpoint_store
        self.artifacts_root = Path(artifacts_root)
        self.workspace_root = Path(workspace_root)
        if agent_mode not in {"midnight", "bare"}:
            raise ValueError(f"unknown agent mode: {agent_mode}")
        self.agent_mode = agent_mode
        native_binary_limit = asyncio.Semaphore(cfg.pwn_max_concurrency)
        self._category_limits = {
            "pwn": native_binary_limit,
            "reverse": native_binary_limit,
        }

    def _event(self, event: str, challenge_id: str | None = None, **payload) -> None:
        if self.journal is not None:
            self.journal.append(
                RunEvent(
                    event=event,
                    run_id=self.run_id,
                    challenge_id=challenge_id,
                    payload=payload,
                )
            )

    async def _durable_progress(
        self,
        challenge_id: str,
        hydrated: Challenge | None,
    ) -> dict[str, int]:
        """Recover redacted counters when a graph invocation exits exceptionally."""
        if self.checkpoint_store is None or hydrated is None:
            return {}
        thread_id = CheckpointStore.thread_id(
            self.run_id,
            challenge_id,
            hydrated.get("source_hash") or hydrated.get("round_id"),
        )
        try:
            states = await asyncio.to_thread(
                self.checkpoint_store.latest_channel_values,
                thread_id,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("could not recover checkpoint metrics for %s: %s", challenge_id, exc)
            return {}
        return _checkpoint_progress(states)

    async def solve_all(self, challenges: list[Challenge]) -> list[Result]:
        run_deadline = time.time() + self.run_timeout if self.run_timeout else None
        ordered = sorted(challenges, key=self._priority_key)
        self._event(
            "run_started",
            challenge_count=len(challenges),
            global_timeout_seconds=self.run_timeout,
        )
        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one(ch: Challenge) -> Result:
            async with sem:
                started = time.monotonic()
                challenge_id = ch.get("id", "?")
                remaining = run_deadline - time.time() if run_deadline else None
                if remaining is not None and remaining <= 0:
                    self._event("challenge_finished", challenge_id, status="timeout")
                    return Result(
                        challenge_id,
                        status="timeout",
                        category=ch.get("category_hint"),
                    )
                hydrated: Challenge | None = None
                self._event("challenge_started", challenge_id)
                instance_started = False
                instance_slot_acquired = False
                try:
                    if isinstance(self.provider, ManagedChallengeProvider):
                        if ch.get("interactive") or ch.get("remote"):
                            await self._platform_instance_limit.acquire()
                            instance_slot_acquired = True
                        await self.provider.start_challenge(challenge_id)
                        instance_started = True
                        self._event("challenge_instance_started", challenge_id)
                    hydrated = await self._hydrate(ch)
                    task_deadline = time.time() + self.per_task_timeout
                    hydrated["deadline_epoch"] = (
                        min(task_deadline, run_deadline) if run_deadline else task_deadline
                    )
                    category = hydrated.get("category_hint") or "unknown"
                    category_sem = self._category_limits.get(category)
                    if category_sem is None:
                        operation = self._solve_one(hydrated)
                    else:

                        async def category_limited() -> Result:
                            async with category_sem:
                                return await self._solve_one(hydrated)

                        operation = category_limited()
                    deadline = hydrated.get("deadline_epoch")
                    if deadline is None:
                        raise RuntimeError("challenge deadline was not initialized")
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise TimeoutError
                    result = await asyncio.wait_for(operation, timeout=remaining)
                    result = replace(
                        result,
                        duration_seconds=round(time.monotonic() - started, 3),
                    )
                    self._event(
                        "challenge_finished",
                        challenge_id,
                        status=result.status,
                        has_flag=result.flag is not None,
                    )
                    return result
                except TimeoutError:
                    progress = await self._durable_progress(challenge_id, hydrated)
                    self._event("challenge_finished", challenge_id, status="timeout")
                    return Result(
                        challenge_id,
                        status="timeout",
                        revision=(hydrated or ch).get("source_hash")
                        or (hydrated or ch).get("round_id"),
                        category=(hydrated or ch).get("category_hint"),
                        duration_seconds=round(time.monotonic() - started, 3),
                        attempts=progress.get("attempts", 0),
                        input_tokens=progress.get("input_tokens", 0),
                        output_tokens=progress.get("output_tokens", 0),
                        tool_calls=progress.get("tool_calls", 0),
                        repeated_tool_calls=progress.get("repeated_tool_calls", 0),
                        tool_errors=progress.get("tool_errors", 0),
                        protocol_recoveries=progress.get("protocol_recoveries", 0),
                        model_transport_failures=progress.get("model_transport_failures", 0),
                    )
                except Exception as exc:  # noqa: BLE001
                    progress = await self._durable_progress(challenge_id, hydrated)
                    self._event(
                        "challenge_finished",
                        challenge_id,
                        status="failed",
                        error=str(exc),
                    )
                    return Result(
                        challenge_id,
                        status="failed",
                        error=str(exc),
                        revision=(hydrated or ch).get("source_hash")
                        or (hydrated or ch).get("round_id"),
                        category=(hydrated or ch).get("category_hint"),
                        duration_seconds=round(time.monotonic() - started, 3),
                        attempts=progress.get("attempts", 0),
                        input_tokens=progress.get("input_tokens", 0),
                        output_tokens=progress.get("output_tokens", 0),
                        tool_calls=progress.get("tool_calls", 0),
                        repeated_tool_calls=progress.get("repeated_tool_calls", 0),
                        tool_errors=progress.get("tool_errors", 0),
                        protocol_recoveries=progress.get("protocol_recoveries", 0),
                        model_transport_failures=progress.get("model_transport_failures", 0),
                    )
                finally:
                    if instance_started:
                        try:
                            await self.provider.stop_challenge(challenge_id)  # type: ignore[attr-defined]
                            self._event("challenge_instance_stopped", challenge_id)
                        except Exception as exc:  # noqa: BLE001
                            self._event(
                                "challenge_instance_stop_failed",
                                challenge_id,
                                error=str(exc),
                            )
                    if instance_slot_acquired:
                        self._platform_instance_limit.release()

        results = list(await asyncio.gather(*(run_one(c) for c in ordered)))
        self._event(
            "run_finished",
            solved=sum(result.status == "solved" for result in results),
            total=len(results),
        )
        return results

    @staticmethod
    def _priority_key(challenge: Challenge) -> tuple[int, int, int, str]:
        """Prefer static and organizer-labelled easy tasks deterministically."""
        instance_rank = int(bool(challenge.get("interactive") or challenge.get("remote")))
        difficulty = str(challenge.get("difficulty") or "").strip().lower()
        difficulty_rank = {
            "easy": 0,
            "简单": 0,
            "medium": 1,
            "中等": 1,
            "hard": 2,
            "困难": 2,
        }.get(difficulty, 1)
        category = str(challenge.get("category_hint") or "unknown").lower()
        category_rank = {
            "misc": 0,
            "forensics": 1,
            "crypto": 2,
            "web": 3,
            "reverse": 4,
            "pwn": 5,
        }.get(category, 6)
        return instance_rank, difficulty_rank, category_rank, str(challenge.get("id") or "")

    async def _hydrate(self, challenge: Challenge) -> Challenge:
        """Refresh metadata, materialize attachments, and assign a revision."""
        challenge_id = challenge.get("id", "?")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", challenge_id):
            raise ValueError(f"unsafe challenge id: {challenge_id!r}")
        current = await self.provider.fetch(challenge_id)
        if not current.get("files"):
            destination = self.artifacts_root / self.run_id / challenge_id
            current["files"] = await self.provider.download_files(challenge_id, str(destination))

        hash_entries = await asyncio.gather(
            *(asyncio.to_thread(_sha256_file, Path(path)) for path in current.get("files") or [])
        )
        file_hashes = dict(hash_entries)
        current["file_hashes"] = file_hashes

        if not current.get("source_hash"):
            source = {
                key: current.get(key)
                for key in (
                    "id",
                    "name",
                    "description",
                    "remote",
                    "category_hint",
                    "flag_format",
                    "round_id",
                    "targets",
                    "flag_count",
                )
            }
            source["file_hashes"] = dict(sorted(file_hashes.items()))
            current["source_hash"] = hashlib.sha256(
                json.dumps(source, sort_keys=True, ensure_ascii=False).encode()
            ).hexdigest()
        return current

    async def _solve_one(self, ch: Challenge) -> Result:
        """Run one challenge end-to-end with its own graph + container."""
        # imported here to avoid importing langgraph at module load.
        if self.agent_mode == "bare":
            from midnight.graph.bare_graph import build_bare_graph

            def build_graph(checkpointer=None):
                return build_bare_graph(
                    submitter=self.submitter,
                    manager=manager,
                    checkpointer=checkpointer,
                )

        else:
            from midnight.graph.main_graph import build_main_graph

            def build_graph(checkpointer=None):
                return build_main_graph(
                    provider=self.provider,
                    submitter=self.submitter,
                    manager=manager,
                    checkpointer=checkpointer,
                )

        cfg = get_config()
        challenge_scope = hashlib.sha256(ch.get("id", "?").encode()).hexdigest()[:12]
        revision = str(ch.get("source_hash") or ch.get("round_id") or "unversioned")
        revision_scope = hashlib.sha256(revision.encode()).hexdigest()[:16]
        manager = ContainerManager(
            run_id=self.run_id,
            scope_id=f"{self.run_id[:16]}-{challenge_scope}",
            workspace_host_dir=(
                self.workspace_root / self.run_id / ch.get("id", "unknown") / revision_scope
            ),
        )

        async def invoke(checkpointer=None):
            graph = build_graph(checkpointer)
            config = {
                "recursion_limit": cfg.settings.recursion_limit,
                "configurable": {
                    "thread_id": CheckpointStore.thread_id(
                        self.run_id,
                        ch.get("id", "?"),
                        ch.get("source_hash") or ch.get("round_id"),
                    )
                },
            }
            if checkpointer is not None:
                snapshot = await graph.aget_state(config)
                if snapshot.values:
                    if not snapshot.next:
                        self._event("challenge_checkpoint_hit", ch.get("id", "?"))
                        return snapshot.values
                    self._event("challenge_resumed", ch.get("id", "?"))
                    return await graph.ainvoke(None, config=config)
            return await graph.ainvoke(
                initial_state(ch, workdir=cfg.settings.workdir), config=config
            )

        try:
            if self.checkpoint_store is None:
                final = await invoke()
            else:
                async with self.checkpoint_store.open() as checkpointer:
                    final = await invoke(checkpointer)
            return Result(
                challenge_id=ch.get("id", "?"),
                status=final.get("status", "failed"),
                flag=final.get("flag"),
                error=final.get("error"),
                revision=ch.get("source_hash") or ch.get("round_id"),
                category=final.get("challenge_type") or ch.get("category_hint"),
                attempts=final.get("attempt", 0),
                points=final.get("points"),
                **_transcript_metrics(final.get("messages") or []),
                flags_solved=len(final.get("accepted_flags") or []),
                flags_available=ch.get("flag_count") or 1,
                model_transport_failures=final.get("model_transport_failures", 0),
            )
        finally:
            await manager.cleanup_all()
