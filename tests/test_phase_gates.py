"""Weak-model phase gates and candidate provenance tests."""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage

from midnight.graph.middleware import ArtifactPhaseGateMiddleware, PwnPhaseGateMiddleware
from midnight.tools.shell import make_submit_flag


def _tool_message(index: int, name: str = "gdb_tool", args: dict | None = None):
    return AIMessage(content="", tool_calls=[{"id": str(index), "name": name, "args": args or {}}])


def test_phase_gate_forces_exploit_artifact_after_recon_budget():
    gate = ArtifactPhaseGateMiddleware(category="misc", target="target:1337", artifact_gate=2)
    update = gate.before_model({"messages": [_tool_message(1), _tool_message(2)]}, None)
    assert update is not None
    assert "PHASE_GATE:IMPLEMENT" in update["messages"][0].content
    assert "misc specialist" in update["messages"][0].content


def test_phase_gate_does_not_repeat_or_override_existing_artifact():
    gate = PwnPhaseGateMiddleware(target="", artifact_gate=2)
    messages = [
        _tool_message(1),
        _tool_message(2, "write_file", {"path": "/ctf/solve.py", "content": "x"}),
    ]
    assert gate.before_model({"messages": messages}, None) is None
    messages.append(HumanMessage("[PHASE_GATE:IMPLEMENT] already sent"))
    assert gate.before_model({"messages": messages}, None) is None


def test_network_candidate_requires_target_provenance():
    found: list[str] = []
    tool = make_submit_flag(
        record_flag=found.append,
        flag_format=r"flag\{[^}]+\}",
        state={"challenge": {"remote": "target:1337"}},
    )
    rejected = tool.invoke({"candidate": "flag{local}", "source": "local"})
    accepted = tool.invoke({"candidate": "flag{remote}", "source": "target"})
    assert rejected.startswith("rejected:")
    assert accepted.startswith("recorded")
    assert found == ["flag{remote}"]
