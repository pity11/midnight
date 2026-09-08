"""Model abstraction layer.

Single entry point ``build_llm(role)`` -> a LangChain chat model, driven by
config/models.yaml. Switching provider = editing YAML, no code change.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from httpx import Timeout
from pydantic import SecretStr

from midnight.config import AppConfig, ModelSpec, ProviderSpec, model_spec_for, provider_spec_for

if TYPE_CHECKING:
    from langchain_core.language_models.chat_models import BaseChatModel


def build_llm(role: str = "default", *, config: AppConfig | None = None) -> BaseChatModel:
    """Build a chat model for a given role (classify / pwn / web / ...).

    ``spec.model`` is "<provider>:<model_name>", parsed by init_chat_model.
    The special provider ``stub:`` returns a deterministic fake model used for
    closed-loop smoke tests (no network/tokens).
    """
    spec = model_spec_for(role, config=config)

    if spec.model and spec.model.startswith("stub:"):
        from midnight.models.stub import StubReActModel

        return StubReActModel()

    provider_id, provider = provider_spec_for(spec.provider, config=config)
    model_name = _env_or_default(provider.model_env, spec.model or provider.model)
    if provider.adapter == "openai_compatible":
        model = _build_openai_compatible(provider_id, provider, model_name, spec)
    else:
        model = _build_langchain_provider(provider, model_name, spec)
    if provider.tool_mode == "json_protocol":
        from midnight.models.json_protocol import JsonProtocolChatModel

        return JsonProtocolChatModel(delegate=model, provider_id=provider_id)
    return model


def _env_or_default(env_name: str | None, default: str | None) -> str:
    value = os.environ.get(env_name, "").strip() if env_name else ""
    resolved = value or (default or "").strip()
    if not resolved:
        raise RuntimeError("MODEL_CONFIGURATION_EMPTY")
    return resolved


def _api_key(provider: ProviderSpec) -> str:
    if not provider.api_key_env:
        return ""
    value = os.environ.get(provider.api_key_env, "").strip()
    if not value:
        raise RuntimeError(f"MODEL_API_KEY_MISSING:{provider.api_key_env}")
    return value


def _build_openai_compatible(
    provider_id: str, provider: ProviderSpec, model_name: str, spec: ModelSpec
) -> BaseChatModel:
    from langchain_openai import ChatOpenAI

    base_url = _env_or_default(provider.base_url_env, provider.base_url)
    if provider.require_https and not base_url.startswith("https://"):
        raise RuntimeError(f"MODEL_BASE_URL_REQUIRES_HTTPS:{provider_id}")
    return ChatOpenAI(
        api_key=SecretStr(_api_key(provider)),
        base_url=base_url.rstrip("/"),
        model=model_name,
        temperature=spec.temperature,
        extra_body={"max_tokens": spec.max_tokens},
        timeout=Timeout(provider.timeout, connect=provider.connect_timeout),
        max_retries=provider.max_retries,
        streaming=False,
        use_responses_api=False,
    )


def _build_langchain_provider(
    provider: ProviderSpec, model_name: str, spec: ModelSpec
) -> BaseChatModel:
    _api_key(provider)
    if not provider.langchain_provider:
        raise RuntimeError("MODEL_LANGCHAIN_PROVIDER_MISSING")
    from langchain.chat_models import init_chat_model

    return init_chat_model(
        f"{provider.langchain_provider}:{model_name}",
        temperature=spec.temperature,
        max_tokens=spec.max_tokens,
        timeout=provider.timeout,
        max_retries=provider.max_retries,
    )
