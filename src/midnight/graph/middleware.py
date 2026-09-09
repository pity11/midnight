"""Deterministic phase gates for weak-model specialist loops."""

from __future__ import annotations

from dataclasses import dataclass

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import HumanMessage


def _calls(messages: list) -> list[dict]:
    return [call for message in messages for call in (getattr(message, "tool_calls", None) or [])]


@dataclass
class PwnPhaseGateMiddleware(AgentMiddleware):
    """Interrupt excessive pwn reconnaissance with artifact and target gates."""

    target: str = ""
    artifact_gate: int = 8
    target_gate: int = 16

    def before_model(self, state, runtime):
        messages = list(state.get("messages") or [])
        calls = _calls(messages)
        text = "\n".join(str(getattr(message, "content", "")) for message in messages)

        if len(calls) >= self.artifact_gate and "[PHASE_GATE:IMPLEMENT]" not in text:
            made_artifact = any(
                call.get("name") == "write_file"
                and "solve.py" in str((call.get("args") or {}).get("path", ""))
                for call in calls
            ) or any(
                call.get("name") == "run_shell"
                and "solve.py" in str((call.get("args") or {}).get("command", ""))
                for call in calls
            )
            if not made_artifact:
                return {
                    "messages": [
                        HumanMessage(
                            "[PHASE_GATE:IMPLEMENT] Reconnaissance budget is exhausted. "
                            "Your next action must create /ctf/solve.py from the best "
                            "current hypothesis. Include assertions and local/remote modes. "
                            "Do not call GDB again before an executable exploit artifact exists."
                        )
                    ]
                }

        if self.target and len(calls) >= self.target_gate and "[PHASE_GATE:TARGET]" not in text:
            reached_target = any(
                call.get("name") == "connect_tool"
                or self.target in str(call.get("args") or {})
                for call in calls
            )
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
        return None
