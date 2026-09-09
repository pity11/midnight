"""Specialist subgraph factory.

Every category expert is built through LangChain's ``create_agent`` factory;
they differ only in injected tools + system prompt + model.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from langchain_core.language_models.chat_models import BaseChatModel


def make_specialist(
    *, llm: BaseChatModel, tools: list[Any], system_prompt: str, middleware: list[Any] | None = None
):
    """Create a ReAct specialist subgraph.

    Thin wrapper over langchain.agents.create_agent so all experts share
    one construction path; differences come from tools/prompt/model.
    """
    from langchain.agents import create_agent
    from langchain.agents.middleware import ToolErrorMiddleware

    def tool_error_observation(exc: Exception, _request: Any) -> str:
        detail = " ".join(str(exc).split())[:240]
        return (
            f"[error] Tool execution failed ({type(exc).__name__}): {detail}. "
            "Correct the arguments or choose a different tool; preserve the current hypothesis."
        )

    return create_agent(
        model=llm,
        tools=tools,
        system_prompt=system_prompt,
        middleware=[ToolErrorMiddleware(on_error=tool_error_observation), *(middleware or ())],
    )
