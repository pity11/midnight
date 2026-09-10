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
            call.get("name") in {"connect_tool", "http_request", "fenjing_ssti"}
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
