"""Assemble a specialist's toolset from config + registry, bound to one env.

Bridges config/tools.yaml (expert -> tool names) and the tool registry (name ->
factory). Each factory is called with the per-challenge binding context (env,
flag recorder, escalation context, helper runner).
"""

from __future__ import annotations

from collections.abc import Callable

import midnight.tools  # noqa: F401  ensure tools are registered
from midnight.config import get_config
from midnight.env.ctf_environment import CTFEnvironment
from midnight.state import CTFState
from midnight.tools.registry import REGISTRY
from midnight.utils.flag import extract_flags
from midnight.utils.logging import get_logger

log = get_logger(__name__)


def build_specialist_tools(
    *,
    expert: str,
    env: CTFEnvironment,
    state: CTFState,
    record_flag: Callable[[str], None],
    run_helper: Callable[..., object] | None = None,
) -> list[object]:
    """Instantiate the tools configured for ``expert``, bound to ``env``."""
    cfg = get_config()
    tool_names = cfg.tools.get(expert) or cfg.tools.get("unknown") or []
    ch = state.get("challenge", {})
    flag_format = ch.get("flag_format")
    observed_target_flags: set[str] = set()

    def observe_target_output(output: str) -> None:
        observed_target_flags.update(extract_flags(output, flag_format=flag_format))

    factory_kwargs = {
        "env": env,
        "state": state,
        "record_flag": record_flag,
        "flag_format": flag_format,
        "current_expert": expert,
        "depth": state.get("escalation_depth", 0),
        "stack": state.get("escalation_stack", []),
        "max_depth": cfg.settings.escalation_max_depth,
        "run_helper": run_helper,
        "observe_target_output": observe_target_output,
        "observed_target_flags": observed_target_flags,
    }

    tools: list[object] = []
    for name in tool_names:
        try:
            entry = REGISTRY.get(name)
        except KeyError:
            # Tool declared in tools.yaml but not registered (e.g. a custom tool
            # not yet added). Skip gracefully so the specialist still runs with
            # whatever is available rather than crashing.
            log.warning("tool %r declared for %s but not registered; skipping", name, expert)
            continue
        tools.append(entry.factory(**factory_kwargs))
    return tools
