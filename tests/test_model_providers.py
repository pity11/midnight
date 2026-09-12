from __future__ import annotations

from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import tool
from pydantic import BaseModel, ConfigDict, Field

from midnight.graph.specialists.base_specialist import make_specialist
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


def test_json_protocol_projects_tools_to_compact_schemas():
    delegate = ScriptedModel(replies=[
        '{"type":"complete","summary":"done"}'
    ])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])
    model.invoke("probe")
    prompt = delegate.seen[0][0].content
    assert '"name":"http_probe"' in prompt
    assert '"arguments":{"path":{"type":"string"}}' in prompt
    assert '"function"' not in prompt


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


def test_json_protocol_normalizes_canonical_action_extras_and_string_arguments():
    delegate = ScriptedModel(replies=[
        (
            '{"type":"tool_call","phase":"TRIAGE","reasoning":"probe next",'
            '"tool":"http_probe","arguments":"{\\"path\\":\\"/health\\"}"}'
        )
    ])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])
    result = model.invoke("probe")
    assert result.tool_calls[0]["name"] == "http_probe"
    assert result.tool_calls[0]["args"] == {"path": "/health"}


def test_json_protocol_normalizes_canonical_complete_extras():
    delegate = ScriptedModel(replies=[
        '{"type":"complete","summary":"done","reasoning":"verified"}'
    ])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])
    result = model.invoke("probe")
    assert result.content == "done"


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
    assert "exactly one JSON object" in delegate.seen[0][-1].content


def test_json_protocol_recovers_from_unknown_tool_arguments_after_bounded_repairs():
    invalid = (
        '{"type":"tool_call","tool":"http_probe",'
        '"arguments":{"path":"/","unexpected":true}}'
    )
    delegate = ScriptedModel(replies=[invalid, invalid])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])

    result = model.invoke("probe")
    assert "MODEL_PROTOCOL_RECOVERY:MODEL_TOOL_ARGUMENTS_INVALID" in result.content
    assert result.additional_kwargs["midnight_protocol_error"] == "MODEL_TOOL_ARGUMENTS_INVALID"


def test_json_protocol_recovers_without_exposing_invalid_plain_text():
    delegate = ScriptedModel(replies=["working", "final narrative"])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test").bind_tools([http_probe])

    result = model.invoke("probe")

    assert "MODEL_PROTOCOL_RECOVERY:MODEL_ACTION_JSON_INVALID" in result.content
    assert "final narrative" not in result.content
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
    assert model.delegate.http_client is not None
    assert model.delegate.http_async_client is not None
    assert model.delegate.http_client._trust_env is False
    assert model.delegate.http_async_client._trust_env is False
    assert model.delegate.http_client._transport._pool._local_address == "0.0.0.0"
    assert model.delegate.http_async_client._transport._pool._local_address == "0.0.0.0"


def test_competition_llm_environment_overrides_legacy_gateway(monkeypatch):
    from midnight.config import ModelSpec, effective_model_id, get_config
    from midnight.models import build_llm

    monkeypatch.setenv("CUC_API_KEY", "legacy-test-key")
    monkeypatch.setenv("CUC_BASE_URL", "https://legacy.invalid/v1")
    monkeypatch.setenv("CUC_MODEL", "legacy-model")
    monkeypatch.setenv("MIDNIGHT_LLM_API_KEY", "venue-test-key")
    monkeypatch.setenv("MIDNIGHT_LLM_BASE_URL", "https://venue.invalid/v1")
    monkeypatch.setenv("MIDNIGHT_LLM_MODEL", "venue-deepseek")
    cfg = get_config()
    cfg = cfg.model_copy(
        update={
            "active_provider": "competition",
            "models": {**cfg.models, "classify": ModelSpec(max_tokens=1024)},
        }
    )

    model = build_llm("classify", config=cfg)

    assert isinstance(model, JsonProtocolChatModel)
    assert model.provider_id == "competition"
    assert model.delegate.model_name == "venue-deepseek"
    assert str(model.delegate.openai_api_base) == "https://venue.invalid/v1"
    assert model.delegate.openai_api_key.get_secret_value() == "venue-test-key"
    assert effective_model_id("classify", config=cfg) == "competition:venue-deepseek"


@pytest.mark.asyncio
async def test_specialist_returns_tool_exceptions_as_observations():
    @tool
    def fragile(mode: str) -> str:
        """Run a fragile test tool."""
        raise ValueError("mode must be local or target")

    delegate = ScriptedModel(replies=[
        '{"type":"tool_call","tool":"fragile","arguments":{"mode":"remote"}}',
        '{"type":"complete","summary":"correct the mode next"}',
    ])
    model = JsonProtocolChatModel(delegate=delegate, provider_id="test")
    agent = make_specialist(llm=model, tools=[fragile], system_prompt="test")

    result = await agent.ainvoke({"messages": [HumanMessage("run it")]})

    tool_messages = [message for message in result["messages"] if isinstance(message, ToolMessage)]
    assert len(tool_messages) == 1
    assert "Tool execution failed (ValueError)" in tool_messages[0].content
