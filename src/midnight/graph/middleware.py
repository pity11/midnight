"""Deterministic phase gates for weak-model specialist loops."""

from __future__ import annotations

from dataclasses import dataclass

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
    artifact_gate: int = 3
    target_gate: int = 6

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
                            f"As the {self.category} specialist, your next action must create "
                            "/ctf/solve.py (or the directly executable payload artifact) from "
                            "the best current hypothesis. Include assertions or local validation. "
                            "Do not perform more open-ended analysis before an executable artifact exists."
                        )
                    ]
                }

        if self.target and len(calls) >= self.target_gate and "[PHASE_GATE:TARGET]" not in text:
            reached_target = any(
                call.get("name") in {"connect_tool", "http_request", "fenjing_ssti"}
                or (
                    call.get("name") == "run_exploit"
                    and (call.get("args") or {}).get("mode") == "target"
                )
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


# Backward-compatible descriptive alias for callers/tests written during the
# first pwn-only rollout.
PwnPhaseGateMiddleware = ArtifactPhaseGateMiddleware
