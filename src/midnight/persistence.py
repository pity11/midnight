"""SQLite-backed LangGraph checkpoints for resumable local runs."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

# Restrict checkpoint deserialization to the safe built-in serializer surface.
os.environ.setdefault("LANGGRAPH_STRICT_MSGPACK", "true")


class CheckpointStore:
    """Owns the on-disk location and thread naming convention."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    @staticmethod
    def thread_id(run_id: str, challenge_id: str, revision: str | None = None) -> str:
        """Return a checkpoint namespace that cannot cross challenge revisions."""
        suffix = revision or "unversioned"
        return f"{run_id}:{challenge_id}:{suffix}"

    @asynccontextmanager
    async def open(self) -> AsyncIterator[AsyncSqliteSaver]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        async with AsyncSqliteSaver.from_conn_string(str(self.path)) as saver:
            yield saver
