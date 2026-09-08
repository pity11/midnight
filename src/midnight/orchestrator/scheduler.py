"""Concurrent scheduler: solve many challenges in parallel.

Each challenge gets its own compiled graph instance and its own container; an
asyncio.Semaphore caps concurrency; per-task timeout + finally-cleanup prevent
container leaks. Skeleton at M0; ties into build_main_graph at M4.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

from midnight.config import get_config
from midnight.env.container_manager import ContainerManager
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
    ):
        cfg = get_config().settings
        self.provider = provider
        self.submitter = submitter
        self.max_concurrency = max_concurrency or cfg.max_concurrency
        self.per_task_timeout = per_task_timeout or cfg.per_task_timeout

    async def solve_all(self, challenges: list[Challenge]) -> list[Result]:
        sem = asyncio.Semaphore(self.max_concurrency)

        async def run_one(ch: Challenge) -> Result:
            async with sem:
                try:
                    return await asyncio.wait_for(
                        self._solve_one(ch), timeout=self.per_task_timeout
                    )
                except asyncio.TimeoutError:
                    return Result(ch.get("id", "?"), status="timeout")
                except Exception as exc:  # noqa: BLE001
                    return Result(ch.get("id", "?"), status="failed", error=str(exc))

        return list(await asyncio.gather(*(run_one(c) for c in challenges)))

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
