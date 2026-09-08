"""Cross-expert help delegation tool (ask_expert).

Method B "expert-as-tool": calling ask_expert synchronously runs a helper
specialist subgraph *in the same challenge container*, returning its result as
the tool's return value. The originating specialist's ReAct loop then continues
naturally — no checkpointer/interrupt needed.

Guards: escalation depth cap + cycle detection (forbid A->B->A).

The helper-subgraph invocation is provided by graph/helper.py's run_helper,
injected via the ``run_helper`` factory kwarg.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from midnight.env.ctf_environment import CTFEnvironment
from midnight.tools.registry import register_tool


@dataclass
class EscalationGuard:
    ok: bool
    reason: str = ""


def check_escalation(
    *, current_expert: str, target_type: str, depth: int, stack: list[str], max_depth: int
) -> EscalationGuard:
    if depth >= max_depth:
        return EscalationGuard(False, f"escalation limit reached (depth={depth}); solve it yourself")
    if target_type == current_expert:
        return EscalationGuard(False, f"already the {target_type} expert; no need to ask")
    if target_type in stack:
        return EscalationGuard(False, f"cycle detected ({'->'.join(stack)}->{target_type})")
    return EscalationGuard(True)


@register_tool(name="ask_expert", groups=["pwn", "reverse", "web", "crypto", "misc"])
def make_ask_expert(
    *,
    env: CTFEnvironment,
    current_expert: str,
    depth: int,
    stack: list[str],
    max_depth: int,
    run_helper: Callable[..., object] | None = None,
    **_,
) -> object:
    from langchain_core.tools import tool

    @tool
    async def ask_expert(target_type: str, subtask: str) -> str:
        """Ask another category's expert to solve a subtask in THIS container.

        Use when the challenge needs a capability outside your specialty (e.g.
        a web task that needs to debug a local binary -> ask the pwn expert).
        Returns the helper's result; you keep ownership of the final flag.
        """
        guard = check_escalation(
            current_expert=current_expert,
            target_type=target_type,
            depth=depth,
            stack=stack,
            max_depth=max_depth,
        )
        if not guard.ok:
            return guard.reason
        if run_helper is None:
            return "[ask_expert not yet wired: available from M3.5]"
        # helper runs with an isolated messages context, same env/container,
        # depth+1 and an extended stack to prevent cycles.
        return await run_helper(
            target_type=target_type,
            subtask=subtask,
            env=env,
            depth=depth + 1,
            stack=[*stack, current_expert],
        )

    return ask_expert
