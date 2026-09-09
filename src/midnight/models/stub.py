"""A scripted fake chat model for closed-loop testing without a real LLM.

It mimics a tiny ReAct policy: for the sanity_misc challenge it issues a couple
of shell tool calls (cat the flag file, base64-decode) and then calls
submit_flag with whatever flag-looking string it has seen. Purely deterministic;
no network, no tokens.

Activated via models.yaml using ``model: "stub:react"``.
"""

from __future__ import annotations

import re
from typing import Any

from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

_FLAG_RE = re.compile(r"[A-Za-z0-9_]+\{[^}]+\}")


class StubReActModel(BaseChatModel):
    """Deterministic ReAct-ish model used only for pipeline smoke tests."""

    @property
    def _llm_type(self) -> str:
        return "stub-react"

    def bind_tools(self, tools: Any, **kwargs: Any) -> StubReActModel:
        # tools are irrelevant to the scripted policy; just return self.
        return self

    def with_structured_output(self, schema: Any, **kwargs: Any):
        # used by the classifier; parse the category hint from the prompt so the
        # stub routes to the right specialist/image deterministically.
        import re as _re

        class _Structured:
            @staticmethod
            def _pick(prompt: str) -> str:
                m = _re.search(r"Category hint.*?:\s*([a-z]+)", prompt)
                cand = (m.group(1) if m else "misc").lower()
                valid = {"pwn", "reverse", "web", "crypto", "misc", "forensics"}
                return cand if cand in valid else "misc"

            async def ainvoke(self, prompt: str, **_kw):
                if "status" in schema.model_fields:
                    return schema(status="PONG")
                t = self._pick(prompt)
                return schema(challenge_type=t, reason=f"stub classifier (hint={t})")

            def invoke(self, prompt: str, **_kw):
                if "status" in schema.model_fields:
                    return schema(status="PONG")
                t = self._pick(prompt)
                return schema(challenge_type=t, reason=f"stub classifier (hint={t})")

        return _Structured()

    def _scripted_step(self, messages: list[BaseMessage]) -> AIMessage:
        # If we've already issued a submit_flag, end the loop (no tool call).
        for m in messages:
            for tc in getattr(m, "tool_calls", None) or []:
                if tc.get("name") == "submit_flag":
                    return AIMessage(content="Flag already submitted. Done.")

        # 1) If any tool output already contains a flag, submit it.
        tool_outputs = [str(m.content) for m in messages if isinstance(m, ToolMessage)]
        joined = "\n".join(tool_outputs)
        flag_match = _FLAG_RE.search(joined)
        if flag_match:
            return AIMessage(
                content="Found the flag in tool output; submitting.",
                tool_calls=[
                    {
                        "name": "submit_flag",
                        "args": {"candidate": flag_match.group(0)},
                        "id": "call_submit",
                    }
                ],
            )

        # Track which shell commands we've already issued (from prior AIMessages).
        issued: list[str] = []
        for m in messages:
            for tc in getattr(m, "tool_calls", None) or []:
                cmd = (tc.get("args") or {}).get("command", "")
                if cmd:
                    issued.append(cmd)

        def _already(substr: str) -> bool:
            return any(substr in c for c in issued)

        # 2) recon ladder: cat -> base64 decode (if textual b64) -> strings.
        if not _already("cat /ctf"):
            return AIMessage(
                content="Reading the challenge files.",
                tool_calls=[
                    {
                        "name": "run_shell",
                        "args": {"command": "cat /ctf/* 2>/dev/null"},
                        "id": "call_cat",
                    }
                ],
            )

        # only attempt base64 decode if the cat output looked like printable b64
        printable = "".join(c for c in joined if c.isprintable() or c in "\n\r\t")
        looks_b64 = bool(re.search(r"^[A-Za-z0-9+/]{16,}={0,2}\s*$", printable, re.MULTILINE))
        if looks_b64 and not _already("base64 -d"):
            return AIMessage(
                content="Decoding the base64 content.",
                tool_calls=[
                    {
                        "name": "run_shell",
                        "args": {"command": "cat /ctf/* 2>/dev/null | base64 -d 2>/dev/null; echo"},
                        "id": "call_decode",
                    }
                ],
            )

        if not _already("strings"):
            return AIMessage(
                content="No flag in plain files; running strings on binaries.",
                tool_calls=[
                    {
                        "name": "run_shell",
                        "args": {
                            "command": "strings -n 6 /ctf/* 2>/dev/null | grep -iE 'flag|ctf' | head"
                        },
                        "id": "call_strings",
                    }
                ],
            )

        # give up gracefully
        return AIMessage(content="No flag found by the scripted policy.")

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        msg = self._scripted_step(messages)
        return ChatResult(generations=[ChatGeneration(message=msg)])

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        msg = self._scripted_step(messages)
        return ChatResult(generations=[ChatGeneration(message=msg)])
