from __future__ import annotations

import asyncio

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
