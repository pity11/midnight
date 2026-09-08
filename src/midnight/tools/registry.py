"""Tool registry: the extension entry point.

Tools register themselves via ``@register_tool(name=..., groups=[...])``. The
graph builds a specialist's toolset by looking up ``config/tools.yaml`` and
fetching the matching registered factories from here.

A registered entry is a *factory*: ``(env, state_ref) -> langchain tool``,
because most tools need to be bound to a specific challenge's CTFEnvironment.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

# A factory takes the per-challenge environment (and optionally a state accessor)
# and returns a LangChain-compatible tool object. Typed loosely to avoid a hard
# langchain import at module load.
ToolFactory = Callable[..., object]


@dataclass
class _Entry:
    name: str
    factory: ToolFactory
    groups: set[str] = field(default_factory=set)


class ToolRegistry:
    def __init__(self) -> None:
        self._entries: dict[str, _Entry] = {}

    def register(self, name: str, factory: ToolFactory, groups: list[str]) -> None:
        if name in self._entries:
            raise ValueError(f"tool already registered: {name}")
        self._entries[name] = _Entry(name=name, factory=factory, groups=set(groups))

    def get(self, name: str) -> _Entry:
        if name not in self._entries:
            raise KeyError(f"unknown tool: {name}")
        return self._entries[name]

    def names(self) -> list[str]:
        return sorted(self._entries)

    def build_for_expert(self, tool_names: list[str], **factory_kwargs) -> list[object]:
        """Instantiate the named tools, passing factory kwargs (e.g. env, state)."""
        tools: list[object] = []
        for name in tool_names:
            entry = self.get(name)
            tools.append(entry.factory(**factory_kwargs))
        return tools


# process-wide singleton
REGISTRY = ToolRegistry()


def register_tool(*, name: str, groups: list[str]) -> Callable[[ToolFactory], ToolFactory]:
    """Decorator to register a tool factory under ``name`` for ``groups``."""

    def deco(factory: ToolFactory) -> ToolFactory:
        REGISTRY.register(name, factory, groups)
        return factory

    return deco


def tool_names_for(expert: str, tools_config: dict[str, list[str]]) -> list[str]:
    """Return the configured tool names for an expert, falling back to common."""
    return tools_config.get(expert) or tools_config.get("unknown") or []
