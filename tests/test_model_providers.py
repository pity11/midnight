from __future__ import annotations

from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from pydantic import BaseModel, ConfigDict, Field

from midnight.models.json_protocol import JsonProtocolChatModel


class ScriptedModel(BaseChatModel):
    replies: list[Any] = Field(default_factory=list)
    seen: list[list[BaseMessage]] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def _generate(self, messages: list[BaseMessage], stop: list[str] | None = None,
                  run_manager: Any = None, **kwargs: Any) -> ChatResult:
        self.seen.append(messages)
        reply = self.replies.pop(0)
        message = reply if isinstance(reply, AIMessage) else AIMessage(content=reply)
        return ChatResult(generations=[ChatGeneration(message=message)])


@tool
def http_probe(path: str) -> str:
    """Probe an in-scope HTTP path."""
    return path


def test_json_protocol_converts_validated_action_to_tool_call():
    delegate = ScriptedModel(replies=[
        '{"type":"tool_call","tool":"http_probe","arguments":{"path":"/health"}}'
    ])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])

    result = model.invoke("check health")

    assert result.tool_calls[0]["name"] == "http_probe"
    assert result.tool_calls[0]["args"] == {"path": "/health"}
    assert "Available tool schemas" in delegate.seen[0][0].content


@pytest.mark.parametrize(
    "wrapped",
    [
        '<json>{"type":"tool_call","tool":"http_probe","arguments":{"path":"/"}}</json>',
        '<tool_call>\n{"type":"tool_call","tool":"http_probe","arguments":{"path":"/"}}\n</tool_call>',
        '```json\n{"type":"tool_call","tool":"http_probe","arguments":{"path":"/"}}\n```',
    ],
)
def test_json_protocol_accepts_common_json_wrappers(wrapped):
    delegate = ScriptedModel(replies=[wrapped])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])

    result = model.invoke("probe")

    assert result.tool_calls[0]["name"] == "http_probe"


def test_json_protocol_skips_flag_braces_before_action_object():
    delegate = ScriptedModel(replies=[
        (
            'I found TEST{redacted} and will verify it.\n'
            '{"type":"tool_call","tool":"http_probe","arguments":{"path":"/verify"}}'
        )
    ])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])

    result = model.invoke("probe")

    assert result.tool_calls[0]["args"] == {"path": "/verify"}


@pytest.mark.parametrize(
    "variant",
    [
        '{"name":"http_probe","args":{"path":"/health"}}',
        '{"type":"function_call","tool":"http_probe","input":{"path":"/health"}}',
        '{"function":{"name":"http_probe","arguments":{"path":"/health"}}}',
    ],
)
def test_json_protocol_normalizes_common_tool_action_variants(variant):
    delegate = ScriptedModel(replies=[variant])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])

    result = model.invoke("probe")

    assert result.tool_calls[0]["name"] == "http_probe"
    assert result.tool_calls[0]["args"] == {"path": "/health"}


def test_json_protocol_repairs_structured_output_once():
    class Decision(BaseModel):
        model_config = ConfigDict(extra="forbid")
        value: int

    delegate = ScriptedModel(replies=["not json", '{"value":7}'])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test")

    result = model.with_structured_output(Decision).invoke("decide")

    assert result.value == 7
    assert len(delegate.seen) == 2


def test_json_protocol_preserves_usage_on_converted_tool_action():
    delegate = ScriptedModel(
        replies=[
            AIMessage(
                content='{"type":"tool_call","tool":"http_probe","arguments":{"path":"/"}}',
                usage_metadata={"input_tokens": 12, "output_tokens": 5, "total_tokens": 17},
            )
        ]
    )
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])
    result = model.invoke("probe")
    assert result.usage_metadata == {
        "input_tokens": 12,
        "output_tokens": 5,
        "total_tokens": 17,
    }


def test_json_protocol_flattens_native_tool_history_to_text():
    delegate = ScriptedModel(replies=[
        '{"type":"complete","summary":"done"}'
    ])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])
    history = [
        HumanMessage(content="check"),
        AIMessage(content="", tool_calls=[{
            "name": "http_probe", "args": {"path": "/health"}, "id": "call_1"
        }]),
        ToolMessage(content="200 OK", tool_call_id="call_1", name="http_probe"),
    ]

    result = model.invoke(history)

    assert result.content == "done"
    assert not getattr(delegate.seen[0][2], "tool_calls", [])
    assert isinstance(delegate.seen[0][3], HumanMessage)
    assert "Observation from http_probe" in delegate.seen[0][3].content


def test_json_protocol_is_the_final_system_instruction():
    delegate = ScriptedModel(
        replies=['{"type":"complete","summary":"done"}']
    )
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])
    model.invoke([SystemMessage(content="specialist"), HumanMessage(content="task")])
    assert delegate.seen[0][0].content == "specialist"
    assert "Available tool schemas" in delegate.seen[0][1].content
    assert isinstance(delegate.seen[0][2], HumanMessage)


def test_json_protocol_rejects_unknown_tool_arguments_after_bounded_repairs():
    invalid = (
        '{"type":"tool_call","tool":"http_probe",'
        '"arguments":{"path":"/","unexpected":true}}'
    )
    delegate = ScriptedModel(replies=[invalid, invalid, invalid])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])

    with pytest.raises(RuntimeError, match="MODEL_TOOL_ARGUMENTS_INVALID"):
        model.invoke("probe")


def test_json_protocol_falls_back_to_plain_completion_after_bounded_repairs():
    delegate = ScriptedModel(replies=["working", "still working", "final narrative"])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])

    result = model.invoke("probe")

    assert result.content == "final narrative"
    assert result.tool_calls == []


def test_cuc_factory_uses_registry_defaults_without_network(monkeypatch):
    from midnight.config import ModelSpec, get_config
    from midnight.models import build_llm

    monkeypatch.setenv("CUC_API_KEY", "test-only-key")
    monkeypatch.setenv("CUC_BASE_URL", "")
    monkeypatch.setenv("CUC_MODEL", "")
    cfg = get_config()
    # Other legacy tests intentionally select models.stub.yaml process-wide.
    # Supply the role policy explicitly so this unit test remains order-independent.
    cfg = cfg.model_copy(update={
        "active_provider": "cuc",
        "models": {**cfg.models, "classify": ModelSpec(max_tokens=1024)},
    })
    model = build_llm("classify", config=cfg)

    assert isinstance(model, JsonProtocolChatModel)
    assert model.delegate.model_name == "cuc/deepseek"
    assert str(model.delegate.openai_api_base) == "https://openai.cuc.edu.cn/v1"
    assert model.delegate.extra_body == {"max_tokens": 1024}
