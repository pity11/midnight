"""Model abstraction layer.

Single entry point ``build_llm(role)`` -> a LangChain chat model, driven by
config/models.yaml. Switching provider = editing YAML, no code change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from midnight.config import AppConfig, model_spec_for

if TYPE_CHECKING:
    from langchain_core.language_models.chat_models import BaseChatModel


def build_llm(role: str = "default", *, config: Optional[AppConfig] = None) -> "BaseChatModel":
    """Build a chat model for a given role (classify / pwn / web / ...).

    ``spec.model`` is "<provider>:<model_name>", parsed by init_chat_model.
    The special provider ``stub:`` returns a deterministic fake model used for
    closed-loop smoke tests (no network/tokens).
    """
    spec = model_spec_for(role, config=config)

    if spec.model.startswith("stub:"):
        from midnight.models.stub import StubReActModel

        return StubReActModel()

    # imported lazily so importing this module doesn't require langchain at
    # scaffold time / in environments without provider packages installed.
    from langchain.chat_models import init_chat_model

    return init_chat_model(
        spec.model,
        temperature=spec.temperature,
        max_tokens=spec.max_tokens,
    )
