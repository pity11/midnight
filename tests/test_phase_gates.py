"""Weak-model phase gates and candidate provenance tests."""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage

from midnight.config import get_config
from midnight.graph.middleware import ArtifactPhaseGateMiddleware, PwnPhaseGateMiddleware
from midnight.graph.toolset import build_specialist_tools
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


def test_phase_gate_constrains_implementation_to_artifact_writer():
    gate = ArtifactPhaseGateMiddleware(artifact_gate=2, target_gate=99)
    messages = [_tool_message(1), _tool_message(2)]
    assert gate.constrained_tool_names(messages) == {"write_file"}


def test_phase_gate_constrains_target_lane_after_artifact():
    gate = ArtifactPhaseGateMiddleware(target="target:1337", artifact_gate=2, target_gate=3)
    messages = [
        _tool_message(1),
        _tool_message(2, "write_file", {"path": "/ctf/solve.py", "content": "x"}),
        _tool_message(3, "run_shell", {"command": "python -m py_compile solve.py"}),
    ]
    assert gate.constrained_tool_names(messages) == {
        "run_exploit", "connect_tool", "http_request", "fenjing_ssti",
        "fmtstr_write_scan",
    }
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:TARGET" in update["messages"][0].content


def test_target_gate_recognizes_target_bound_structured_tools():
    gate = ArtifactPhaseGateMiddleware(target="target:1337", artifact_gate=99, target_gate=2)
    messages = [
        _tool_message(1),
        _tool_message(2, "run_exploit", {"script": "solve.py", "mode": "target"}),
    ]
    assert gate.before_model({"messages": messages}, None) is None


def test_pwn_format_evidence_selects_narrow_specialist_lane():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99, target_gate=99)
    messages = [HumanMessage("objdump shows printf(buf), then compare target value")]
    allowed = gate.constrained_tool_names(messages)
    assert allowed is not None
    assert "fmtstr_probe" in allowed
    assert "fmtstr_write_scan" in allowed
    assert "connect_tool" not in allowed
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "SPECIALIST_LANE:FORMAT_STRING" in update["messages"][0].content


def test_pwn_format_lane_can_start_from_static_dataflow():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99, target_gate=99)
    disassembly = """
    [main-disassembly]
    1452: lea rax,[rbp-0x30]
    1456: mov rdi,rax
    1459: mov eax,0x0
    145e: call 10c0 <printf@plt>
    """
    messages = [HumanMessage(disassembly)]
    assert gate.constrained_tool_names(messages) is not None
    assert "fmtstr_probe" in gate.constrained_tool_names(messages)


def test_pwn_format_lane_ignores_literal_printf():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99, target_gate=99)
    disassembly = """
    [main-disassembly]
    1452: lea rax,[rip+0x123]
    1459: mov rdi,rax
    145e: call 10c0 <printf@plt>
    """
    assert gate.constrained_tool_names([HumanMessage(disassembly)]) is None


def test_repeated_exploit_requires_revision_or_different_tool():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99, target_gate=99)
    messages = [
        _tool_message(1, "write_file", {"path": "/ctf/solve.py", "content": "x"}),
        _tool_message(2, "run_exploit", {"mode": "target"}),
        _tool_message(3, "run_exploit", {"mode": "target"}),
    ]
    allowed = gate.constrained_tool_names(messages)
    assert allowed is not None
    assert "write_file" in allowed
    assert "run_exploit" not in allowed


def test_network_candidate_requires_target_provenance():
    found: list[str] = []
    tool = make_submit_flag(
        record_flag=found.append,
        flag_format=r"flag\{[^}]+\}",
        state={"challenge": {"remote": "target:1337"}},
        observed_target_flags={"flag{remote}"},
    )
    rejected = tool.invoke({"candidate": "flag{local}", "source": "local"})
    accepted = tool.invoke({"candidate": "flag{remote}", "source": "target"})
    assert rejected.startswith("rejected:")
    assert accepted.startswith("recorded")
    assert found == ["flag{remote}"]


def test_target_tool_output_records_candidate_without_model_retyping(monkeypatch):
    found: list[str] = []
    captured: dict = {}

    class Entry:
        def factory(self, **kwargs):
            captured.update(kwargs)
            return object()

    monkeypatch.setattr("midnight.graph.toolset.REGISTRY.get", lambda name: Entry())
    config = get_config().model_copy(update={"tools": {"pwn": ["fake"]}})
    monkeypatch.setattr("midnight.graph.toolset.get_config", lambda: config)
    build_specialist_tools(
        expert="pwn",
        env=object(),
        state={"challenge": {"flag_format": r"flag\{[^}]+\}"}},
        record_flag=found.append,
    )

    captured["observe_target_output"]("server says flag{verified}")
    assert captured["observed_target_flags"] == {"flag{verified}"}
    assert found == ["flag{verified}"]
