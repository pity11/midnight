"""LangChain adapter for gateways that only guarantee plain JSON text.

The upstream model never receives native ``tools`` or ``response_format``
parameters. Tool actions and structured output are prompted as JSON, validated
locally, and retried once only for formatting errors.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, Literal
from uuid import uuid4

from jsonschema import Draft202012Validator
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import BaseModel, ConfigDict, Field, ValidationError


class _ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["tool_call"]
    tool: str
    arguments: dict[str, Any]


class _Complete(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["complete"]
    summary: str


def _messages(value: Any) -> list[BaseMessage]:
    if isinstance(value, str):
        return [HumanMessage(content=value)]
    if hasattr(value, "to_messages"):
        return list(value.to_messages())
    if isinstance(value, Sequence):
        return list(value)
    raise TypeError("MODEL_INPUT_UNSUPPORTED")


def _text(message: BaseMessage) -> str:
    if not isinstance(message.content, str) or not message.content.strip():
        raise RuntimeError("MODEL_EMPTY_CONTENT")
    return message.content


class _StructuredRunnable(Runnable[Any, Any]):
    def __init__(self, model: JsonProtocolChatModel, schema: type[BaseModel]) -> None:
        self._model = model
        self._schema = schema

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        return self._model._structured(input, self._schema, **kwargs)

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        return await self._model._astructured(input, self._schema, **kwargs)


class JsonProtocolChatModel(BaseChatModel):
    """Expose text-only JSON generation as a LangChain chat/tool model."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    delegate: BaseChatModel
    provider_id: str
    bound_tools: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return f"json-protocol-{self.provider_id}"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"provider_id": self.provider_id, "tool_mode": "json_protocol"}

    def bind_tools(self, tools: Sequence[Any], **kwargs: Any) -> JsonProtocolChatModel:
        converted = [convert_to_openai_tool(tool, strict=True) for tool in tools]
        return self.model_copy(update={"bound_tools": converted})

    def with_structured_output(self, schema: Any, **kwargs: Any) -> Runnable[Any, Any]:
        if not isinstance(schema, type) or not issubclass(schema, BaseModel):
            raise TypeError("MODEL_SCHEMA_MUST_BE_PYDANTIC")
        return _StructuredRunnable(self, schema)

    def _tool_prompt(self) -> str:
        definitions = json.dumps(self.bound_tools, ensure_ascii=False, separators=(",", ":"))
        return (
            "You control tools through strict JSON text. Return exactly one JSON object and no "
            "Markdown. To call a tool use "
            '{"type":"tool_call","tool":"<name>","arguments":{...}}. '
            "To finish use "
            '{"type":"complete","summary":"<final answer>"}. '
            f"Available tool schemas: {definitions}"
        )

    def _parse_action(self, raw: str) -> AIMessage:
        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise TypeError
            if data.get("type") == "complete":
                complete_action = _Complete.model_validate(data)
                return AIMessage(content=complete_action.summary)
            tool_action = _ToolCall.model_validate(data)
            matching = [
                item for item in self.bound_tools
                if item["function"]["name"] == tool_action.tool
            ]
            if len(matching) != 1:
                raise ValueError
            params = matching[0]["function"].get("parameters", {})
            Draft202012Validator(params).validate(tool_action.arguments)
            return AIMessage(
                content="",
                tool_calls=[{
                    "name": tool_action.tool,
                    "args": tool_action.arguments,
                    "id": f"json_{uuid4().hex}",
                }],
            )
        except (ValueError, KeyError, TypeError, ValidationError) as exc:
            raise RuntimeError("MODEL_TOOL_ACTION_INVALID") from exc
        except Exception as exc:  # jsonschema validation errors
            raise RuntimeError("MODEL_TOOL_ARGUMENTS_INVALID") from exc

    @staticmethod
    def _attach_metadata(parsed: AIMessage, *responses: BaseMessage) -> AIMessage:
        """Preserve provider usage after converting text JSON into a tool call."""
        input_tokens = 0
        output_tokens = 0
        saw_usage = False
        for response in responses:
            usage = getattr(response, "usage_metadata", None) or {}
            if usage:
                saw_usage = True
                input_tokens += int(usage.get("input_tokens", 0) or 0)
                output_tokens += int(usage.get("output_tokens", 0) or 0)
        update: dict[str, Any] = {
            "response_metadata": getattr(responses[-1], "response_metadata", {}) or {}
        }
        if saw_usage:
            update["usage_metadata"] = {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            }
        return parsed.model_copy(update=update)

    def _tool_messages(self, messages: list[BaseMessage]) -> list[BaseMessage]:
        # Tool-call message fields themselves are part of the native OpenAI tool
        # protocol. Flatten prior actions/results back into ordinary text so the
        # gateway only needs standard system/user/assistant messages.
        flattened: list[BaseMessage] = []
        for message in messages:
            if isinstance(message, ToolMessage):
                name = getattr(message, "name", None) or "tool"
                flattened.append(HumanMessage(
                    content=f"Observation from {name}:\n{message.content}"
                ))
            elif isinstance(message, AIMessage) and message.tool_calls:
                calls = [
                    {"type": "tool_call", "tool": call["name"], "arguments": call["args"]}
                    for call in message.tool_calls
                ]
                flattened.append(AIMessage(
                    content=f"Previous validated action: {json.dumps(calls, ensure_ascii=False)}"
                ))
            else:
                flattened.append(message)
        system_messages = [message for message in flattened if isinstance(message, SystemMessage)]
        conversation = [message for message in flattened if not isinstance(message, SystemMessage)]
        # Keep the tool protocol as the final system instruction. Some
        # OpenAI-compatible gateways give the last system message precedence.
        return [*system_messages, SystemMessage(content=self._tool_prompt()), *conversation]

    def _generate(self, messages: list[BaseMessage], stop: list[str] | None = None,
                  run_manager: Any = None, **kwargs: Any) -> ChatResult:
        if not self.bound_tools:
            result = self.delegate.invoke(messages, stop=stop, **kwargs)
            return ChatResult(generations=[ChatGeneration(message=result)])
        request = self._tool_messages(messages)
        first = self.delegate.invoke(request, stop=stop, **kwargs)
        try:
            parsed = self._parse_action(_text(first))
        except RuntimeError:
            repair = HumanMessage(content=(
                "Your previous response failed local schema validation. Return one valid JSON "
                "object only, using exactly one available tool or the complete action."
            ))
            second = self.delegate.invoke([*request, first, repair], stop=stop, **kwargs)
            parsed = self._parse_action(_text(second))
            return ChatResult(
                generations=[ChatGeneration(message=self._attach_metadata(parsed, first, second))]
            )
        return ChatResult(
            generations=[ChatGeneration(message=self._attach_metadata(parsed, first))]
        )

    async def _agenerate(self, messages: list[BaseMessage], stop: list[str] | None = None,
                         run_manager: Any = None, **kwargs: Any) -> ChatResult:
        if not self.bound_tools:
            result = await self.delegate.ainvoke(messages, stop=stop, **kwargs)
            return ChatResult(generations=[ChatGeneration(message=result)])
        request = self._tool_messages(messages)
        first = await self.delegate.ainvoke(request, stop=stop, **kwargs)
        try:
            parsed = self._parse_action(_text(first))
        except RuntimeError:
            repair = HumanMessage(content=(
                "Your previous response failed local schema validation. Return one valid JSON "
                "object only, using exactly one available tool or the complete action."
            ))
            second = await self.delegate.ainvoke([*request, first, repair], stop=stop, **kwargs)
            parsed = self._parse_action(_text(second))
            return ChatResult(
                generations=[ChatGeneration(message=self._attach_metadata(parsed, first, second))]
            )
        return ChatResult(
            generations=[ChatGeneration(message=self._attach_metadata(parsed, first))]
        )

    def _structured_prompt(self, schema: type[BaseModel]) -> SystemMessage:
        rendered = json.dumps(schema.model_json_schema(), ensure_ascii=False, separators=(",", ":"))
        return SystemMessage(content=(
            "Return exactly one JSON object matching this JSON Schema. Do not use Markdown "
            f"code fences and do not add unknown fields. Schema: {rendered}"
        ))

    def _structured(self, input: Any, schema: type[BaseModel], **kwargs: Any) -> BaseModel:
        request = [self._structured_prompt(schema), *_messages(input)]
        first = self.delegate.invoke(request, **kwargs)
        try:
            return schema.model_validate_json(_text(first))
        except (ValidationError, ValueError):
            repair = HumanMessage(content=(
                "The previous response failed local JSON Schema validation. Return only one "
                "corrected JSON object; do not add commentary or Markdown."
            ))
            second = self.delegate.invoke([*request, first, repair], **kwargs)
            try:
                return schema.model_validate_json(_text(second))
            except (ValidationError, ValueError) as exc:
                raise RuntimeError("MODEL_JSON_INVALID") from exc

    async def _astructured(self, input: Any, schema: type[BaseModel], **kwargs: Any) -> BaseModel:
        request = [self._structured_prompt(schema), *_messages(input)]
        first = await self.delegate.ainvoke(request, **kwargs)
        try:
            return schema.model_validate_json(_text(first))
        except (ValidationError, ValueError):
            repair = HumanMessage(content=(
                "The previous response failed local JSON Schema validation. Return only one "
                "corrected JSON object; do not add commentary or Markdown."
            ))
            second = await self.delegate.ainvoke([*request, first, repair], **kwargs)
            try:
                return schema.model_validate_json(_text(second))
            except (ValidationError, ValueError) as exc:
                raise RuntimeError("MODEL_JSON_INVALID") from exc
