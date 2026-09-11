from __future__ import annotations

import asyncio
import sqlite3

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph

from midnight.persistence import CheckpointStore


def test_checkpoint_store_persists_graph_state(tmp_path):
    async def scenario():
        store = CheckpointStore(tmp_path / "checkpoints.sqlite")
        graph_builder = StateGraph(dict)
        graph_builder.add_node("increment", lambda state: {"count": state["count"] + 1})
        graph_builder.add_edge(START, "increment")
        graph_builder.add_edge("increment", END)
        config = {"configurable": {"thread_id": CheckpointStore.thread_id("run-1", "challenge-1")}}

        async with store.open() as saver:
            graph = graph_builder.compile(checkpointer=saver)
            result = await graph.ainvoke({"count": 0}, config=config)
            assert result["count"] == 1

        async with store.open() as saver:
            graph = graph_builder.compile(checkpointer=saver)
            snapshot = await graph.aget_state(config)
            assert snapshot.values["count"] == 1
            assert snapshot.next == ()

    asyncio.run(scenario())


def test_checkpoint_thread_ids_are_run_scoped():
    assert CheckpointStore.thread_id("a", "x") != CheckpointStore.thread_id("b", "x")


def test_checkpoint_thread_ids_are_revision_scoped():
    assert CheckpointStore.thread_id("a", "x", "v1") != CheckpointStore.thread_id("a", "x", "v2")


def test_latest_channel_values_reads_one_snapshot_per_namespace(tmp_path):
    store = CheckpointStore(tmp_path / "checkpoints.sqlite")
    serializer = JsonPlusSerializer(pickle_fallback=False)
    encoding, old = serializer.dumps_typed({"channel_values": {"attempt": 1}})
    _, new = serializer.dumps_typed({"channel_values": {"attempt": 2}})
    _, nested = serializer.dumps_typed({"channel_values": {"attempt": 3}})
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            """CREATE TABLE checkpoints (
            thread_id TEXT, checkpoint_ns TEXT, checkpoint_id TEXT,
            type TEXT, checkpoint BLOB)"""
        )
        connection.executemany(
            "INSERT INTO checkpoints VALUES (?, ?, ?, ?, ?)",
            [
                ("run:task:rev", "", "1", encoding, old),
                ("run:task:rev", "", "2", encoding, new),
                ("run:task:rev", "specialist", "1", encoding, nested),
            ],
        )
    states = store.latest_channel_values("run:task:rev")
    assert sorted(state["attempt"] for state in states) == [2, 3]
