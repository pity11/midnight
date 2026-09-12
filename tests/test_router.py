from __future__ import annotations

import pytest

import midnight.graph.router as router_module
from midnight.graph.router import make_classify_node
from midnight.state import initial_state


@pytest.mark.asyncio
async def test_trusted_category_hint_bypasses_model(monkeypatch) -> None:
    def fail_build(role: str):
        raise AssertionError("trusted category must not build or call a model")

    monkeypatch.setattr(router_module, "build_llm", fail_build)
    state = initial_state(
        {
            "id": "bundle-pwn",
            "name": "Bundle Pwn",
            "category_hint": "pwn",
            "category_hint_trusted": True,
        }
    )
    result = await make_classify_node()(state)
    assert result == {
        "challenge_type": "pwn",
        "classify_reason": "trusted validated category hint",
    }


@pytest.mark.asyncio
async def test_untrusted_category_hint_still_uses_model(monkeypatch) -> None:
    calls: list[str] = []

    class Structured:
        async def ainvoke(self, prompt: str):
            return router_module.Classification(challenge_type="reverse", reason="model result")

    class Model:
        def with_structured_output(self, schema):
            return Structured()

    def build(role: str):
        calls.append(role)
        return Model()

    monkeypatch.setattr(router_module, "build_llm", build)
    state = initial_state(
        {"id": "live-task", "name": "Live Task", "category_hint": "pwn"}
    )
    result = await make_classify_node()(state)
    assert calls == ["classify"]
    assert result["challenge_type"] == "reverse"
