"""SQLite-backed LangGraph checkpoints for resumable local runs."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
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

    def latest_channel_values(self, thread_id: str) -> list[dict]:
        """Recover the newest durable state from every graph namespace.

        Nested specialist graphs use their own checkpoint namespaces. Reading
        one newest snapshot per namespace preserves partial usage/tool evidence
        when the outer task is cancelled by a competition time limit.
        """
        if not self.path.exists():
            return []
        serializer = JsonPlusSerializer(pickle_fallback=False)
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute(
                """
                SELECT checkpoint_ns, type, checkpoint
                FROM checkpoints
                WHERE thread_id = ?
                ORDER BY checkpoint_ns, checkpoint_id DESC
                """,
                (thread_id,),
            ).fetchall()
        states: list[dict] = []
        seen_namespaces: set[str] = set()
        for namespace, encoding, payload in rows:
            if namespace in seen_namespaces:
                continue
            seen_namespaces.add(namespace)
            checkpoint = serializer.loads_typed((encoding, payload))
            values = checkpoint.get("channel_values") if isinstance(checkpoint, dict) else None
            if isinstance(values, dict):
                states.append(values)
        return states

    @asynccontextmanager
    async def open(self) -> AsyncIterator[AsyncSqliteSaver]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        async with AsyncSqliteSaver.from_conn_string(str(self.path)) as saver:
            yield saver
