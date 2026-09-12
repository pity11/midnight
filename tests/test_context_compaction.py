from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from midnight.graph.main_graph import _compact_continuation_messages


def test_continuation_context_keeps_only_coherent_recent_tool_cycles() -> None:
    messages = [HumanMessage("task")]
    for index in range(7):
        call_id = f"call-{index}"
        messages.extend(
            [
                AIMessage(
                    content="",
                    tool_calls=[{"id": call_id, "name": "read_file", "args": {}}],
                ),
                ToolMessage(content="x" * 5000, tool_call_id=call_id),
            ]
        )

    compacted = _compact_continuation_messages(messages, tool_cycles=4)
    assert len(compacted) == 8
    assert compacted[0].tool_calls[0]["id"] == "call-3"
    assert compacted[-1].tool_call_id == "call-6"
    assert len(compacted[-1].content) < 3000
