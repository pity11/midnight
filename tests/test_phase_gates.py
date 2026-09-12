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


def test_pwn_phase_gate_requires_inventory_then_binary_triage():
    gate = ArtifactPhaseGateMiddleware(category="pwn")
    assert gate.constrained_tool_names([]) == {"list_dir"}
    messages = [_tool_message(1, "list_dir", {"path": "/ctf"})]
    assert gate.constrained_tool_names(messages) == {"binary_triage"}
    update = gate.before_model({"messages": []}, None)
    assert update is not None
    assert "PHASE_GATE:TRIAGE" in update["messages"][0].content


def test_forensics_phase_gate_starts_with_inventory_without_forcing_solver():
    gate = ArtifactPhaseGateMiddleware(category="forensics", artifact_gate=1, target="target:1")
    assert gate.constrained_tool_names([]) == {"list_dir"}
    update = gate.before_model({"messages": []}, None)
    assert update is not None
    assert "PHASE_GATE:FORENSICS_LIST_DIR" in update["messages"][0].content

    messages = [_tool_message(1, "list_dir"), HumanMessage("/ctf/readme.txt")]
    assert gate.constrained_tool_names(messages) is None
    assert gate.before_model({"messages": messages}, None) is None


def test_forensics_archive_gate_triages_then_extracts():
    gate = ArtifactPhaseGateMiddleware(category="forensics")
    messages = [_tool_message(1, "list_dir"), HumanMessage("/ctf/evidence.tar.gz")]
    assert gate.constrained_tool_names(messages) == {"artifact_triage"}

    messages.append(_tool_message(2, "artifact_triage", {"path": "/ctf/evidence.tar.gz"}))
    assert gate.constrained_tool_names(messages) == {"archive_extract"}

    messages.append(_tool_message(3, "archive_extract", {"path": "/ctf/evidence.tar.gz"}))
    assert gate.constrained_tool_names(messages) is None


def test_forensics_discovered_logs_force_log_audit():
    gate = ArtifactPhaseGateMiddleware(category="forensics")
    messages = [_tool_message(1, "list_dir"), HumanMessage("/ctf/auth.log")]
    assert gate.constrained_tool_names(messages) == {"log_audit"}
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:FORENSICS_LOG_AUDIT" in update["messages"][0].content


def test_forensics_capture_gate_triages_then_extracts():
    gate = ArtifactPhaseGateMiddleware(category="forensics")
    messages = [_tool_message(1, "list_dir"), HumanMessage("/ctf/traffic.pcapng")]
    assert gate.constrained_tool_names(messages) == {"pcap_triage"}

    messages.append(_tool_message(2, "pcap_triage", {"path": "/ctf/traffic.pcapng"}))
    assert gate.constrained_tool_names(messages) == {"pcap_artifact_extract"}


def test_forensics_prior_tool_names_survive_outer_retry_truncation():
    gate = ArtifactPhaseGateMiddleware(
        category="forensics",
        prior_tool_names=frozenset({"list_dir", "pcap_triage"}),
    )
    messages = [HumanMessage("Continue analysis of /ctf/traffic.pcap")]
    assert gate.constrained_tool_names(messages) == {"pcap_artifact_extract"}


def test_forensics_observed_tool_names_survive_inner_continuation_truncation():
    gate = ArtifactPhaseGateMiddleware(category="forensics")
    first = [_tool_message(1, "list_dir"), HumanMessage("/ctf/access.log")]
    assert gate.constrained_tool_names(first) == {"log_audit"}
    completed = [*first, _tool_message(2, "log_audit", {"path": "/ctf/access.log"})]
    assert gate.constrained_tool_names(completed) is None
    assert gate.constrained_tool_names([HumanMessage("continue /ctf/access.log")]) is None


def test_forensics_shell_budget_counts_prior_and_current_unique_calls():
    gate = ArtifactPhaseGateMiddleware(
        category="forensics",
        prior_tool_counts=(("run_shell", 10),),
        prior_tool_call_ids=frozenset({"old-1"}),
        forensics_shell_limit=12,
    )
    calls = [
        _tool_message(1, "run_shell"),
        _tool_message(2, "run_shell"),
    ]
    gate.constrained_tool_names(calls)
    assert gate._observed_tool_counts["run_shell"] == 12

    class Tool:
        def __init__(self, name: str):
            self.name = name

    class Request:
        def __init__(self, tools: list[Tool]):
            self.tools = tools

        def override(self, *, tools: list[Tool]):
            return Request(tools)

    constrained = gate._constrain_request(Request([Tool("run_shell"), Tool("read_file")]), None)
    assert [tool.name for tool in constrained.tools] == ["read_file"]
    gate.constrained_tool_names(calls)
    assert gate._observed_tool_counts["run_shell"] == 12


def test_forensics_read_and_write_budgets_span_prior_attempts():
    gate = ArtifactPhaseGateMiddleware(
        category="forensics",
        prior_tool_counts=(("read_file", 18), ("write_file", 6)),
        forensics_read_limit=18,
        forensics_write_limit=6,
    )

    class Tool:
        def __init__(self, name: str):
            self.name = name

    class Request:
        def __init__(self, tools: list[Tool]):
            self.tools = tools

        def override(self, *, tools: list[Tool]):
            return Request(tools)

    constrained = gate._constrain_request(
        Request([Tool("read_file"), Tool("write_file"), Tool("read_evidence")]),
        None,
    )
    assert [tool.name for tool in constrained.tools] == ["read_evidence"]

    update = gate.before_model({"messages": [_tool_message(1, "list_dir")]}, None)
    assert update is not None
    assert "TASK_BUDGET:READ_FILE" in update["messages"][0].content

def test_forensics_detects_capture_path_from_tool_arguments():
    gate = ArtifactPhaseGateMiddleware(
        category="forensics",
        prior_tool_names=frozenset({"list_dir"}),
    )
    messages = [_tool_message(1, "read_file", {"path": "/ctf/network.pcapng"})]
    assert gate.constrained_tool_names(messages) == {"pcap_triage"}


def test_pwn_retry_reads_existing_solver_before_retriage():
    gate = ArtifactPhaseGateMiddleware(category="pwn")
    messages = [
        _tool_message(1, "list_dir"),
        HumanMessage("/ctf/nettools\n/ctf/solve.py"),
    ]
    assert gate.constrained_tool_names(messages) == {"read_file"}
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:RESUME_SOLVER" in update["messages"][0].content


def test_pwn_phase_gate_requires_source_audit_when_native_source_is_visible():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99)
    messages = [
        _tool_message(1, "list_dir"),
        HumanMessage("/ctf/challenge.rs /ctf/challenge"),
        _tool_message(2, "binary_triage"),
    ]
    assert gate.constrained_tool_names(messages) == {"source_audit"}
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:SOURCE" in update["messages"][0].content

    messages.append(_tool_message(3, "source_audit"))
    assert gate.constrained_tool_names(messages) is None


def test_pickle_phase_gate_requires_policy_audit_after_find_class_evidence():
    gate = ArtifactPhaseGateMiddleware(category="misc", artifact_gate=99)
    messages = [
        _tool_message(1, "read_file"),
        HumanMessage("class RestrictedUnpickler: def find_class(self, module, name): pass"),
    ]
    assert gate.constrained_tool_names(messages) == {"pickle_policy_audit"}
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:PICKLE_POLICY" in update["messages"][0].content

    messages.append(_tool_message(2, "pickle_policy_audit"))
    assert gate.constrained_tool_names(messages) == {"pickle_build"}


def test_pickle_policy_audit_immediately_forces_compiler():
    gate = ArtifactPhaseGateMiddleware(category="misc", artifact_gate=99)
    messages = [
        HumanMessage("RestrictedUnpickler.find_class calls super().find_class"),
        _tool_message(1, "pickle_policy_audit"),
    ]
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:PICKLE_BUILD" in update["messages"][0].content
    assert "__globals__.__class__.get" in update["messages"][0].content


def test_repeated_manual_cyclic_probes_force_batch_crash_probe():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99, target_gate=99)
    messages = [
        _tool_message(1, "list_dir"),
        _tool_message(2, "binary_triage"),
        _tool_message(3, "run_shell", {"command": "python -c 'print(cyclic(500))'"}),
        _tool_message(4, "run_shell", {"command": "python -c 'print(cyclic(600))'"}),
    ]
    assert gate.constrained_tool_names(messages) == {"pwn_crash_probe"}
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:CRASH_PROBE" in update["messages"][0].content


def test_pie_leak_and_source_overflow_force_rop_inventory():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99, target_gate=99)
    messages = [
        HumanMessage("Something is leaked: {:p}; split_at after read size 0x400 stack overflow"),
        _tool_message(1, "list_dir"),
        _tool_message(2, "binary_triage"),
        _tool_message(3, "source_audit"),
    ]
    assert gate.constrained_tool_names(messages) == {"pwn_rop_inventory"}
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:PIE_ROP" in update["messages"][0].content


def test_rop_inventory_injects_padding_and_gadget_invariants():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99, target_gate=99)
    messages = [_tool_message(1, "pwn_rop_inventory")]
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    content = update["messages"][0].content
    assert "PHASE_GATE:ROP_INVARIANTS" in content
    assert "do not subtract" in content
    assert "side effect" in content


def test_interactive_pwn_solver_must_be_rewritten_for_observable_output():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99, target_gate=99)
    messages = [
        _tool_message(
            1,
            "write_file",
            {"path": "/ctf/solve.py", "content": "io.interactive()"},
        )
    ]
    assert gate.constrained_tool_names(messages) == {"write_file"}
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:NONINTERACTIVE" in update["messages"][0].content


def test_crash_only_pwn_solver_must_be_rewritten_after_rop_inventory():
    gate = ArtifactPhaseGateMiddleware(category="pwn")
    messages = [
        _tool_message(1, "pwn_rop_inventory"),
        _tool_message(
            2,
            "write_file",
            {
                "path": "/ctf/solve.py",
                "content": "# crash to confirm offset\npayload += p64(0xdeadbeef)",
            },
        ),
    ]

    assert gate.constrained_tool_names(messages) == {"write_file"}
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:ROP_INVARIANTS" in update["messages"][0].content

    messages.extend(update["messages"])
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:FINAL_EXPLOIT" in update["messages"][0].content


def test_pickle_tuple_validator_failure_forces_atomic_call_rebuild():
    gate = ArtifactPhaseGateMiddleware(category="misc", artifact_gate=99)
    messages = [
        _tool_message(1, "pickle_policy_audit"),
        _tool_message(2, "pickle_build"),
        HumanMessage("validator=FAIL TypeError: argument list must be a tuple"),
    ]
    assert gate.constrained_tool_names(messages) == {"pickle_build"}
    update = gate.before_model({"messages": messages}, None)
    assert update is not None
    assert "PHASE_GATE:PICKLE_CALL" in update["messages"][0].content

    messages.append(HumanMessage("validator=PASS result_type=str"))
    assert gate.constrained_tool_names(messages) is None


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
        "run_exploit", "pwn_ret2libc_target", "connect_tool", "http_request", "fenjing_ssti",
        "tinja_ssti", "velocity_ssti", "jwt_analyze",
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


def test_pwn_ret2libc_artifact_forces_deterministic_target_tool():
    gate = ArtifactPhaseGateMiddleware(category="pwn", target="target:1337")
    messages = [
        _tool_message(1, "list_dir", {"path": "/ctf"}),
        _tool_message(2, "binary_triage", {"path": "/ctf/chall"}),
        _tool_message(
            3,
            "write_file",
            {
                "path": "/ctf/solve.py",
                "content": "offset = 88\n# libc ret2libc via puts GOT and puts PLT",
            },
        ),
    ]
    assert gate.constrained_tool_names(messages) == {"pwn_ret2libc_target"}


def test_pwn_format_evidence_selects_narrow_specialist_lane():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99, target_gate=99)
    messages = [
        _tool_message(1, "list_dir"),
        _tool_message(2, "binary_triage"),
        HumanMessage("objdump shows printf(buf), then compare target value"),
    ]
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
    messages = [
        _tool_message(1, "list_dir"),
        _tool_message(2, "binary_triage"),
        HumanMessage(disassembly),
    ]
    assert gate.constrained_tool_names(messages) is not None
    assert "fmtstr_probe" in gate.constrained_tool_names(messages)


def test_pwn_format_lane_takes_priority_over_generic_target_gate():
    gate = ArtifactPhaseGateMiddleware(
        category="pwn", target="target:1337", artifact_gate=2, target_gate=3
    )
    messages = [
        _tool_message(1, "list_dir"),
        _tool_message(2, "binary_triage"),
        _tool_message(3, "write_file", {"path": "/ctf/solve.py", "content": "x"}),
        _tool_message(4, "run_shell", {"command": "objdump -d chall"}),
        HumanMessage(
            "lea rax,[rbp-0x30]\nmov rdi,rax\ncall 10c0 <printf@plt>"
        ),
    ]
    allowed = gate.constrained_tool_names(messages)
    assert allowed is not None
    assert "fmtstr_probe" in allowed
    assert "connect_tool" not in allowed


def test_pwn_format_lane_ignores_literal_printf():
    gate = ArtifactPhaseGateMiddleware(category="pwn", artifact_gate=99, target_gate=99)
    disassembly = """
    [main-disassembly]
    1452: lea rax,[rip+0x123]
    1459: mov rdi,rax
    145e: call 10c0 <printf@plt>
    """
    messages = [
        _tool_message(1, "list_dir"),
        _tool_message(2, "binary_triage"),
        HumanMessage(disassembly),
    ]
    assert gate.constrained_tool_names(messages) is None


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
