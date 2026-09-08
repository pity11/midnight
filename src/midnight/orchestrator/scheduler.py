"""Concurrent scheduler: solve many challenges in parallel.

Each challenge gets its own compiled graph instance and its own container; an
asyncio.Semaphore caps concurrency; per-task timeout + finally-cleanup prevent
container leaks. Skeleton at M0; ties into build_main_graph at M4.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional
from uuid import uuid4

from midnight.config import get_config
from midnight.env.container_manager import ContainerManager
from midnight.events import EventJournal, RunEvent
from midnight.interfaces.provider import ChallengeProvider
from midnight.interfaces.submitter import FlagSubmitter
from midnight.state import Challenge, initial_state
from midnight.utils.logging import get_logger

log = get_logger(__name__)


@dataclass
class Result:
    challenge_id: str
    status: str
    flag: Optional[str] = None
    error: Optional[str] = None


class Scheduler:
    def __init__(
        self,
        *,
        provider: ChallengeProvider,
        submitter: FlagSubmitter,
        max_concurrency: Optional[int] = None,
        per_task_timeout: Optional[int] = None,
        journal: Optional[EventJournal] = None,
        run_id: Optional[str] = None,
    ):
        cfg = get_config().settings
        self.provider = provider
        self.submitter = submitter
        self.max_concurrency = max_concurrency or cfg.max_concurrency
        self.per_task_timeout = per_task_timeout or cfg.per_task_timeout
        self.journal = journal
        self.run_id = run_id or uuid4().hex

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

    async def solve_all(self, challenges: list[Challenge]) -> list[Result]:
        self._event("run_started", challenge_count=len(challenges))
        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one(ch: Challenge) -> Result:
            async with sem:
                challenge_id = ch.get("id", "?")
                self._event("challenge_started", challenge_id)
                try:
                    result = await asyncio.wait_for(
                        self._solve_one(ch), timeout=self.per_task_timeout
                    )
                    self._event(
                        "challenge_finished",
                        challenge_id,
                        status=result.status,
                        has_flag=result.flag is not None,
                    )
                    return result
                except asyncio.TimeoutError:
                    self._event("challenge_finished", challenge_id, status="timeout")
                    return Result(challenge_id, status="timeout")
                except Exception as exc:  # noqa: BLE001
                    self._event(
                        "challenge_finished",
                        challenge_id,
                        status="failed",
                        error=str(exc),
                    )
                    return Result(challenge_id, status="failed", error=str(exc))

        results = list(await asyncio.gather(*(run_one(c) for c in challenges)))
        self._event(
            "run_finished",
            solved=sum(result.status == "solved" for result in results),
            total=len(results),
        )
        return results

    async def _solve_one(self, ch: Challenge) -> Result:
        """Run one challenge end-to-end with its own graph + container."""
        # imported here to avoid importing langgraph at module load.
        from midnight.graph.main_graph import build_main_graph

        cfg = get_config()
        manager = ContainerManager()  # per-challenge manager -> isolated cleanup
        graph = build_main_graph(
            provider=self.provider, submitter=self.submitter, manager=manager
        )
        try:
            final = await graph.ainvoke(
                initial_state(ch, workdir=cfg.settings.workdir),
                config={"recursion_limit": cfg.settings.recursion_limit},
            )
            return Result(
                challenge_id=ch.get("id", "?"),
                status=final.get("status", "failed"),
                flag=final.get("flag"),
            )
        finally:
            await manager.cleanup_all()
