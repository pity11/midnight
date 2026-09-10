"""Deterministic phase gates for weak-model specialist loops."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import HumanMessage


def _calls(messages: list) -> list[dict]:
    return [call for message in messages for call in (getattr(message, "tool_calls", None) or [])]


@dataclass
class ArtifactPhaseGateMiddleware(AgentMiddleware):
    """Interrupt excessive reconnaissance with artifact and target gates."""

    category: str = "ctf"
    target: str = ""
    # Weak text-only models often spend three useful actions on list/read/
    # playbook, then drift into prose. Force an executable first draft early;
    # the artifact can still be refined with later evidence.
    artifact_gate: int = 5
    target_gate: int = 10

    @staticmethod
    def _made_artifact(calls: list[dict]) -> bool:
        return any(
            call.get("name") == "write_file"
            and "solve.py" in str((call.get("args") or {}).get("path", ""))
            for call in calls
        ) or any(
            call.get("name") == "run_shell"
            and "solve.py" in str((call.get("args") or {}).get("command", ""))
            for call in calls
        )

    def _reached_target(self, calls: list[dict]) -> bool:
        return any(
            call.get("name")
            in {"connect_tool", "http_request", "fenjing_ssti", "pwn_ret2libc_target"}
            or (
                call.get("name") == "run_exploit"
                and (call.get("args") or {}).get("mode") == "target"
            )
            or self.target in str(call.get("args") or {})
            for call in calls
        )

    def _format_string_indicated(self, messages: list) -> bool:
        if self.category != "pwn":
            return False
        text = "\n".join(str(getattr(message, "content", "")) for message in messages).lower()
        has_printf = "printf" in text
        has_format_evidence = any(
            marker in text
            for marker in ("format string", "%p", "%n", "%hn", "printf(buf", "printf((char")
        )
        if has_printf and has_format_evidence:
            return True
        # Generic x86-64 SysV static-dataflow heuristic: a stack-local address
        # is loaded into RDI immediately before printf. This distinguishes the
        # common printf(user_buffer) sink from RIP-relative literal formats and
        # lets a weak model enter the right lane before it invents a payload.
        for call in re.finditer(r"call[^\n]{0,100}printf", text):
            window = text[max(0, call.start() - 500) : call.start()]
            if re.search(
                r"lea\s+rax,\s*\[rbp-[^\]]+\].{0,220}mov\s+rdi,\s*rax",
                window,
                flags=re.DOTALL,
            ):
                return True
        return False

    def _source_indicated(self, messages: list) -> bool:
        if self.category != "pwn":
            return False
        text = "\n".join(str(getattr(message, "content", "")) for message in messages).lower()
        return bool(re.search(r"(?:^|[ /])[^\n ]+\.(?:c|cc|cpp|rs)(?:\b|$)", text))

    def _restricted_pickle_indicated(self, messages: list) -> bool:
        if self.category not in {"misc", "forensics"}:
            return False
        text = "\n".join(str(getattr(message, "content", "")) for message in messages).lower()
        return "find_class" in text and "unpickl" in text

    def _repeated_manual_cyclic(self, calls: list[dict]) -> bool:
        if self.category != "pwn":
            return False
        return sum(
            call.get("name") == "run_shell"
            and "cyclic(" in str((call.get("args") or {}).get("command", ""))
            for call in calls
        ) >= 2

    def _pie_overflow_indicated(self, messages: list) -> bool:
        if self.category != "pwn":
            return False
        text = "\n".join(str(getattr(message, "content", "")) for message in messages).lower()
        has_leak = "leaked" in text or "runtime symbol leak" in text or "{:p}" in text
        has_overwrite = any(
            marker in text
            for marker in ("stack overwrite", "stack overflow", "buffer overflow", "0x400", "split_at")
        )
        return has_leak and has_overwrite

    @staticmethod
    def _solver_visible(messages: list) -> bool:
        text = "\n".join(str(getattr(message, "content", "")) for message in messages)
        return "solve.py" in text

    @staticmethod
    def _interactive_solver(calls: list[dict]) -> bool:
        writes = [
            call for call in calls
            if call.get("name") == "write_file"
            and "solve.py" in str((call.get("args") or {}).get("path", ""))
        ]
        if not writes:
            return False
        content = str((writes[-1].get("args") or {}).get("content", ""))
        return ".interactive()" in content

    @staticmethod
    def _diagnostic_pwn_solver(calls: list[dict]) -> bool:
        """Detect a crash-only probe accidentally persisted as the final solver."""
        writes = [
            call for call in calls
            if call.get("name") == "write_file"
            and "solve.py" in str((call.get("args") or {}).get("path", ""))
        ]
        if not writes:
            return False
        content = str((writes[-1].get("args") or {}).get("content", "")).lower()
        return any(marker in content for marker in (
            "0xdeadbeef",
            "crash to confirm",
            "just crash",
            "placeholder exploit",
            "todo: build",
        ))

    @staticmethod
    def _ret2libc_artifact(calls: list[dict]) -> bool:
        writes = [
            call
            for call in calls
            if call.get("name") == "write_file"
            and "solve.py" in str((call.get("args") or {}).get("path", ""))
        ]
        if not writes:
            return False
        content = str((writes[-1].get("args") or {}).get("content", "")).lower()
        return (
            all(marker in content for marker in ("libc", "got", "plt", "offset"))
            and re.search(r"offset\s*=\s*(?:0x[0-9a-f]+|\d+)", content) is not None
        )

    def _pickle_tuple_failure(self, messages: list) -> bool:
        if self.category not in {"misc", "forensics"}:
            return False
        text = "\n".join(str(getattr(message, "content", "")) for message in messages)
        failure = text.rfind("validator=FAIL TypeError: argument list must be a tuple")
        success = text.rfind("validator=PASS")
        return failure >= 0 and failure > success

    def _pickle_audited_without_build(self, messages: list) -> bool:
        if not self._restricted_pickle_indicated(messages):
            return False
        calls = _calls(messages)
        return (
            any(call.get("name") == "pickle_policy_audit" for call in calls)
            and not any(call.get("name") == "pickle_build" for call in calls)
        )

    @staticmethod
    def _calls_after_last_write(calls: list[dict], tool_name: str) -> int:
        last_write = max(
            (index for index, call in enumerate(calls) if call.get("name") == "write_file"),
            default=-1,
        )
        return sum(
            call.get("name") == tool_name for call in calls[last_write + 1 :]
        )

    def constrained_tool_names(self, messages: list) -> set[str] | None:
        """Return the deterministic tool lane for the current phase, if any."""
        calls = _calls(messages)
        if self.category == "pwn" and not calls:
            return {"list_dir"}
        if (
            self.category == "pwn"
            and any(call.get("name") == "list_dir" for call in calls)
            and self._solver_visible(messages)
            and not any(call.get("name") == "read_file" for call in calls)
        ):
            return {"read_file"}
        if (
            self.category == "pwn"
            and any(call.get("name") == "list_dir" for call in calls)
            and not any(call.get("name") == "binary_triage" for call in calls)
        ):
            return {"binary_triage"}
        if (
            self.category == "pwn"
            and any(call.get("name") == "binary_triage" for call in calls)
            and self._source_indicated(messages)
            and not any(call.get("name") == "source_audit" for call in calls)
        ):
            return {"source_audit"}
        if (
            self._restricted_pickle_indicated(messages)
            and not any(call.get("name") == "pickle_policy_audit" for call in calls)
        ):
            return {"pickle_policy_audit"}
        if self._pickle_audited_without_build(messages):
            return {"pickle_build"}
        if (
            self.category == "pwn"
            and self._ret2libc_artifact(calls)
            and not any(call.get("name") == "pwn_ret2libc_target" for call in calls)
        ):
            return {"pwn_ret2libc_target"}
        if (
            self._repeated_manual_cyclic(calls)
            and not any(call.get("name") == "pwn_crash_probe" for call in calls)
        ):
            return {"pwn_crash_probe"}
        if (
            self._pie_overflow_indicated(messages)
            and any(call.get("name") == "source_audit" for call in calls)
            and not any(call.get("name") == "pwn_rop_inventory" for call in calls)
        ):
            return {"pwn_rop_inventory"}
        if self._pickle_tuple_failure(messages):
            return {"pickle_build"}
        if self.category == "pwn" and self._interactive_solver(calls):
            return {"write_file"}
        if (
            self.category == "pwn"
            and any(call.get("name") == "pwn_rop_inventory" for call in calls)
            and self._diagnostic_pwn_solver(calls)
        ):
            return {"write_file"}
        if len(calls) >= self.artifact_gate and not self._made_artifact(calls):
            return {"write_file"}
        if (
            self.target
            and len(calls) >= self.target_gate
            and self._made_artifact(calls)
            and not self._reached_target(calls)
            and not self._format_string_indicated(messages)
        ):
            return {
                "run_exploit",
                "pwn_ret2libc_target",
                "connect_tool",
                "http_request",
                "fenjing_ssti",
                "tinja_ssti",
                "velocity_ssti",
                "jwt_analyze",
                "fmtstr_write_scan",
            }
        if self.category == "pwn" and self._calls_after_last_write(calls, "run_exploit") >= 2:
            return {
                "read_file",
                "write_file",
                "run_shell",
                "record_evidence",
                "lookup_playbook",
                "fmtstr_probe",
                "fmtstr_write_scan",
                "pwn_crash_probe",
                "pwn_rop_inventory",
                "pwn_ret2libc_target",
            }
        if self._format_string_indicated(messages):
            return {
                "read_file",
                "write_file",
                "record_evidence",
                "lookup_playbook",
                "fmtstr_probe",
                "fmtstr_write_scan",
                "run_exploit",
                "submit_flag",
            }
        return None

    @staticmethod
    def _constrain_request(request: Any, allowed: set[str] | None):
        if not allowed:
            return request
        selected = [tool for tool in request.tools if getattr(tool, "name", "") in allowed]
        return request.override(tools=selected) if selected else request

    def wrap_model_call(self, request, handler):
        """Make a phase gate enforceable by exposing only phase-valid tools."""
        allowed = self.constrained_tool_names(list(request.state.get("messages") or []))
        return handler(self._constrain_request(request, allowed))

    async def awrap_model_call(self, request, handler):
        """Async counterpart used by the competition solver."""
        allowed = self.constrained_tool_names(list(request.state.get("messages") or []))
        return await handler(self._constrain_request(request, allowed))

    def before_model(self, state, runtime):
        messages = list(state.get("messages") or [])
        calls = _calls(messages)
        text = "\n".join(str(getattr(message, "content", "")) for message in messages)

        if self.category == "pwn" and not calls and "[PHASE_GATE:TRIAGE]" not in text:
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:TRIAGE] List /ctf now. The following turn must run "
                    "binary_triage on the primary executable before building an exploit."
                )]
            }

        if (
            self.category == "pwn"
            and any(call.get("name") == "list_dir" for call in calls)
            and self._solver_visible(messages)
            and not any(call.get("name") == "read_file" for call in calls)
            and "[PHASE_GATE:RESUME_SOLVER]" not in text
        ):
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:RESUME_SOLVER] An existing solve.py is present from a prior "
                    "attempt. Read it before new reconnaissance. Preserve confirmed offsets, "
                    "leaks, and validated primitives; revise only the observed failure."
                )]
            }

        if (
            self.category == "pwn"
            and any(call.get("name") == "pwn_rop_inventory" for call in calls)
            and "[PHASE_GATE:ROP_INVARIANTS]" not in text
        ):
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:ROP_INVARIANTS] Use candidate_saved_return_distance directly "
                    "as the padding from the identified input buffer; do not subtract the buffer "
                    "offset a second time. Copy each full gadget's semantics into the plan. A "
                    "gadget with an add/mov/call side effect is not a plain pop: establish safe "
                    "registers and writable mapped memory before it executes. Assert the PIE "
                    "base equation and payload length in solve.py before target execution."
                )]
            }

        if (
            self.category == "pwn"
            and self._interactive_solver(calls)
            and "[PHASE_GATE:NONINTERACTIVE]" not in text
        ):
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:NONINTERACTIVE] Autonomous evaluation cannot stop in "
                    "io.interactive(). Rewrite solve.py to send a bounded post-exploitation "
                    "flag retrieval command, receive until EOF or timeout, and print the full "
                    "response so the target-bound verifier can observe the flag."
                )]
            }

        if (
            self.category == "pwn"
            and any(call.get("name") == "pwn_rop_inventory" for call in calls)
            and self._diagnostic_pwn_solver(calls)
            and "[PHASE_GATE:FINAL_EXPLOIT]" not in text
        ):
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:FINAL_EXPLOIT] The current solve.py is only a crash or "
                    "control-offset diagnostic. It cannot close a challenge. Rewrite it now "
                    "as a complete exploit using the recorded ROP inventory, full gadget "
                    "semantics, runtime base equation, and an observable bounded flag-retrieval "
                    "stage. Preserve measured offsets; remove sentinel return addresses and "
                    "placeholder crash code before contacting the target."
                )]
            }

        if (
            self.category == "pwn"
            and any(call.get("name") == "binary_triage" for call in calls)
            and self._source_indicated(messages)
            and not any(call.get("name") == "source_audit" for call in calls)
            and "[PHASE_GATE:SOURCE]" not in text
        ):
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:SOURCE] Supplied native source is visible. Run source_audit now, "
                    "compare destination capacities with real write bounds, and trace every "
                    "post-copy check before selecting an exploit primitive."
                )]
            }

        if (
            self._restricted_pickle_indicated(messages)
            and not any(call.get("name") == "pickle_policy_audit" for call in calls)
            and "[PHASE_GATE:PICKLE_POLICY]" not in text
        ):
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:PICKLE_POLICY] A custom Unpickler/find_class policy is visible. "
                    "Run pickle_policy_audit on its source and any current payload. Treat an "
                    "opcode chain as invalid until pickletools and the local validator accept it."
                )]
            }

        if (
            self._pickle_audited_without_build(messages)
            and "[PHASE_GATE:PICKLE_BUILD]" not in text
        ):
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:PICKLE_BUILD] Policy reconnaissance is complete. Build and "
                    "locally validate the shortest executable stack program now. Use a version-"
                    "resilient mapping chain: resolve an allowed dotted global ending in "
                    "<function>.__globals__.__class__.get, memoize it, and call it on the dotted "
                    "<function>.__globals__ object plus '__builtins__'. Memoize that result, reuse "
                    "the get callable to fetch 'exec' or 'eval', then call it with the expression. "
                    "Supply the challenge validator to pickle_build."
                )]
            }

        if (
            self._repeated_manual_cyclic(calls)
            and not any(call.get("name") == "pwn_crash_probe" for call in calls)
            and "[PHASE_GATE:CRASH_PROBE]" not in text
        ):
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:CRASH_PROBE] Manual cyclic shell probes repeated without "
                    "a measured offset. Call pwn_crash_probe with the exact binary, menu "
                    "prefix, and any required NUL sentinel. Use its register and stack "
                    "offset report before revising solve.py."
                )]
            }

        if (
            self._pie_overflow_indicated(messages)
            and any(call.get("name") == "source_audit" for call in calls)
            and not any(call.get("name") == "pwn_rop_inventory" for call in calls)
            and "[PHASE_GATE:PIE_ROP]" not in text
        ):
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:PIE_ROP] Source evidence establishes a raw stack overwrite "
                    "and the service exposes a runtime symbol address. Call pwn_rop_inventory "
                    "on the primary ELF with the vulnerable function and leaked symbol. Use "
                    "its exact saved-return distance and PIE base equation; do not probe for "
                    "a format string."
                )]
            }

        if (
            self._pickle_tuple_failure(messages)
            and "[PHASE_GATE:PICKLE_CALL]" not in text
        ):
            return {
                "messages": [HumanMessage(
                    "[PHASE_GATE:PICKLE_CALL] The latest local validator says REDUCE did not "
                    "receive an argument tuple. Rebuild with pickle_build and replace each "
                    "manual callable/argument/REDUCE sequence with call(count). Do not contact "
                    "the target until validator=PASS."
                )]
            }

        if len(calls) >= self.artifact_gate and "[PHASE_GATE:IMPLEMENT]" not in text:
            made_artifact = self._made_artifact(calls)
            if not made_artifact:
                return {
                    "messages": [
                        HumanMessage(
                            "[PHASE_GATE:IMPLEMENT] Reconnaissance budget is exhausted. "
                            f"As the {self.category} specialist, your next action must create "
                            "/ctf/solve.py (or the directly executable payload artifact) from "
                            "the best current hypothesis. Include assertions or local validation. "
                            "Do not perform more open-ended analysis before an executable artifact exists."
                        )
                    ]
                }

        if (
            self.target
            and len(calls) >= self.target_gate
            and "[PHASE_GATE:TARGET]" not in text
            and not self._format_string_indicated(messages)
        ):
            reached_target = self._reached_target(calls)
            if not reached_target:
                return {
                    "messages": [
                        HumanMessage(
                            f"[PHASE_GATE:TARGET] Stop local analysis. The target is {self.target}. "
                            "Run the best current payload against it now and inspect the complete "
                            "response. Report a flag only with submit_flag(source='target')."
                        )
                    ]
                }
        if (
            self._format_string_indicated(messages)
            and "[SPECIALIST_LANE:FORMAT_STRING]" not in text
        ):
            return {
                "messages": [
                    HumanMessage(
                        "[SPECIALIST_LANE:FORMAT_STRING] Evidence indicates an uncontrolled "
                        "printf. Stop generic probing. Use fmtstr_probe once to identify "
                        "positional arguments. If a desired halfword and stack-resident "
                        "pointer are known, use fmtstr_write_scan. Put the confirmed payload "
                        "in solve.py, verify it, then submit only a flag observed in target output."
                    )
                ]
            }
        return None


# Backward-compatible descriptive alias for callers/tests written during the
# first pwn-only rollout.
PwnPhaseGateMiddleware = ArtifactPhaseGateMiddleware
