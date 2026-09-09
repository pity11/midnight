"""midnight.tools package.

Importing this package triggers registration of all built-in tools (their
``@register_tool`` decorators run at import time).
"""

from midnight.tools import advanced, ask_expert, category, evidence, knowledge, shell  # noqa: F401
from midnight.tools.interactive import connect_tool, gdb_tool  # noqa: F401
from midnight.tools.registry import REGISTRY, register_tool, tool_names_for

__all__ = ["REGISTRY", "register_tool", "tool_names_for"]
