"""Specialist subgraph factory.

Every category expert is built the same way via ``create_react_agent``;
Every category expert is built the same way via ``create_react_agent``;
they differ only in injected tools + system prompt + model.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from langchain_core.language_models.chat_models import BaseChatModel


def make_specialist(*, llm: "BaseChatModel", tools: list[object], system_prompt: str):
    """Create a ReAct specialist subgraph.

    Thin wrapper over langgraph.prebuilt.create_react_agent so all experts share
    one construction path; differences come from tools/prompt/model.
    """
    from langgraph.prebuilt import create_react_agent

    return create_react_agent(model=llm, tools=tools, prompt=system_prompt)
