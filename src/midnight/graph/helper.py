"""Cross-expert help runner (M3.5).

Provides ``make_run_helper(manager)`` -> an async ``run_helper`` callable that
ask_expert invokes. It builds a helper specialist subgraph for ``target_type``,
binds it to the SAME container env, runs it on an isolated messages context, and
returns only the helper's final textual result (plus any flags it surfaced).

This keeps the originating specialist's ReAct loop intact: ask_expert is just a
tool whose return value flows back as a ToolMessage.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

from langchain_core.messages import HumanMessage

from midnight.config import get_config
from midnight.env.ctf_environment import CTFEnvironment
from midnight.graph.specialists import prompts
from midnight.graph.specialists.base_specialist import make_specialist
from midnight.models import build_llm
from midnight.state import ChallengeType, CTFState
from midnight.utils.flag import extract_flags
from midnight.utils.logging import get_logger

log = get_logger(__name__)


def make_run_helper(
    *, base_state: CTFState, record_flag: Callable[[str], None]
) -> Callable[..., object]:
    """Build the run_helper callable closed over the current challenge state."""
    cfg = get_config()

    async def run_helper(
        *, target_type: str, subtask: str, env: CTFEnvironment, depth: int, stack: list[str]
    ) -> str:
        log.info("ask_expert -> %s (depth=%d): %s", target_type, depth, subtask[:80])

        # build a helper-scoped state so the helper's own tools (incl. a further
        # ask_expert) inherit the advanced depth/stack for cycle prevention.
        helper_state = cast(CTFState, dict(base_state))  # shallow copy
        helper_state["escalation_depth"] = depth
        helper_state["escalation_stack"] = stack
        helper_state["challenge_type"] = cast(ChallengeType, target_type)

        # import here to avoid a circular import (toolset -> tools -> ...).
        from midnight.graph.toolset import build_specialist_tools

        tools = build_specialist_tools(
            expert=target_type,
            env=env,
            state=helper_state,
            record_flag=record_flag,
            run_helper=run_helper,  # nested escalation allowed up to max_depth
        )
        llm = build_llm(target_type)
        agent = make_specialist(
            llm=llm,
            tools=tools,
            system_prompt=prompts.BY_TYPE.get(target_type, prompts.MISC)
            + "\n\nYou are assisting another expert. Solve ONLY the requested "
            "subtask and report the concrete result/artifact concisely.",
        )

        msg = HumanMessage(
            f"Subtask delegated to you ({target_type} expert), in the shared "
            f"container at {env.workdir}:\n\n{subtask}\n\n"
            f"Return the concrete result. If you find a flag, call submit_flag."
        )
        result = await agent.ainvoke(
            {"messages": [msg]},
            config={"recursion_limit": cfg.settings.helper_recursion_limit},
        )

        msgs = result.get("messages", [])
        # surface any flags found by the helper
        transcript = "\n".join(
            getattr(m, "content", "") or ""
            for m in msgs
            if isinstance(getattr(m, "content", ""), str)
        )
        for f in extract_flags(
            transcript, flag_format=(base_state.get("challenge") or {}).get("flag_format")
        ):
            record_flag(f)

        # return the helper's last non-empty assistant message as the result
        for m in reversed(msgs):
            content = getattr(m, "content", "")
            if isinstance(content, str) and content.strip():
                return f"[{target_type} expert result]\n{content.strip()}"
        return f"[{target_type} expert produced no textual result]"

    return run_helper
