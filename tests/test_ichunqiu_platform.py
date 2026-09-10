from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from midnight.app import _load_http_adapter
from midnight.interfaces.ichunqiu import IchunqiuConfig, IchunqiuPlatformAdapter


def _json(data: object) -> httpx.Response:
    return httpx.Response(
        200,
        content=json.dumps(data).encode(),
        headers={"content-type": "application/json"},
    )


def test_ichunqiu_inventory_reset_download_and_submit(tmp_path, monkeypatch):
    monkeypatch.setenv("MIDNIGHT_PLATFORM_TOKEN", "team-token-for-test")
    requests: list[httpx.Request] = []
    reset_challenges: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host != "files.invalid":
            assert request.url.params.get("token") == "team-token-for-test"
        if request.url.path == "/questions":
            pwn_connection = (
                {
                    "docker_url": "nc 192.0.2.5 31337",
                    "docker_ip": "192.0.2.5",
                    "docker_port": "31337",
                }
                if "pwn-1" in reset_challenges
                else []
            )
            return _json(
                {
                    "code": 0,
                    "message": "查询成功",
                    "data": [
                        {
                            "question_id": "pwn-1",
                            "title": "sign_shellcode",
                            "score": 500,
                            "file_url": "https://files.invalid/challenge.bin",
                            "is_solved": False,
                            "category": "pwn",
                            "attributes": ["docker"],
                            "description": "test",
                            "interactive": "true",
                            "capabilities": ["docker"],
                            "connection": pwn_connection,
                            "extensions": {"pwn": "context"},
                        },
                        {
                            "question_id": "web-1",
                            "title": "web",
                            "file_url": "",
                            "is_solved": False,
                            "category": "web",
                            "description": "web task",
                            "interactive": "true",
                            "connection": {"docker_url": "web.invalid:80"},
                        },
                        {
                            "question_id": "done",
                            "title": "done",
                            "is_solved": True,
                            "category": "misc",
                            "interactive": "false",
                            "connection": [],
                        },
                    ],
                }
            )
        if request.url.path == "/reset":
            assert request.url.params.get("question_id") in {"pwn-1", "web-1"}
            reset_challenges.add(str(request.url.params.get("question_id")))
            return _json({"code": 0, "message": "操作成功"})
        if request.url.path == "/submit":
            assert request.method == "GET"
            assert request.url.params.get("question_id") == "pwn-1"
            assert request.url.params.get("answer") == "flag{test value}"
            return _json({"code": 0, "message": "答案正确", "status": 1})
        if request.url.host == "files.invalid":
            return httpx.Response(200, content=b"binary")
        return httpx.Response(404)

    async def scenario() -> None:
        from midnight.interfaces.ichunqiu import IchunqiuEndpoints

        config = IchunqiuConfig(
            base_url="https://api.invalid",
            endpoints=IchunqiuEndpoints("/questions", "/reset", "/submit"),
        )
        client = httpx.AsyncClient(
            base_url="https://api.invalid",
            transport=httpx.MockTransport(handler),
        )
        adapter = IchunqiuPlatformAdapter(config, client=client)
        challenges = await adapter.list_challenges()
        assert [item["id"] for item in challenges] == ["pwn-1", "web-1"]
        assert challenges[0]["remote"] is None
        assert challenges[1]["remote"] == "http://web.invalid:80"
        assert 'Capabilities: ["docker"]' in challenges[0]["description"]

        await adapter.start_challenge("pwn-1")
        await adapter.start_challenge("web-1")
        reset_requests = [request for request in requests if request.url.path == "/reset"]
        assert len(reset_requests) == 1
        refreshed = await adapter.fetch("pwn-1")
        assert refreshed["remote"] == "192.0.2.5:31337"

        paths = await adapter.download_files("pwn-1", str(tmp_path))
        assert len(paths) == 1
        assert (tmp_path / "challenge.bin").read_bytes() == b"binary"

        result = await adapter.submit("pwn-1", "flag{test value}")
        assert result.accepted and result.status == "accepted"
        await client.aclose()

    asyncio.run(scenario())


def test_ichunqiu_static_challenge_does_not_reset(monkeypatch):
    monkeypatch.setenv("MIDNIGHT_PLATFORM_TOKEN", "token")
    reset_called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal reset_called
        if request.url.path == "/questions":
            return _json(
                {
                    "code": 0,
                    "data": [
                        {
                            "question_id": "static-1",
                            "title": "static",
                            "is_solved": False,
                            "category": "rev",
                            "interactive": "false",
                            "connection": [],
                        }
                    ],
                }
            )
        reset_called = True
        return _json({"code": 0})

    async def scenario() -> None:
        from midnight.interfaces.ichunqiu import IchunqiuEndpoints

        client = httpx.AsyncClient(
            base_url="https://api.invalid",
            transport=httpx.MockTransport(handler),
        )
        adapter = IchunqiuPlatformAdapter(
            IchunqiuConfig(
                base_url="https://api.invalid",
                endpoints=IchunqiuEndpoints("/questions", "/reset", "/submit"),
            ),
            client=client,
        )
        challenge = await adapter.fetch("static-1")
        assert challenge["category_hint"] == "reverse"
        assert challenge["remote"] is None
        await adapter.start_challenge("static-1")
        assert not reset_called
        await client.aclose()

    asyncio.run(scenario())


def test_ichunqiu_rejected_submission_is_a_result(monkeypatch):
    monkeypatch.setenv("MIDNIGHT_PLATFORM_TOKEN", "token")

    def handler(request: httpx.Request) -> httpx.Response:
        return _json({"code": 1, "message": "答案错误", "status": 0})

    async def scenario() -> None:
        client = httpx.AsyncClient(
            base_url="https://api.invalid",
            transport=httpx.MockTransport(handler),
        )
        adapter = IchunqiuPlatformAdapter(
            IchunqiuConfig(base_url="https://api.invalid"), client=client
        )
        result = await adapter.submit("one", "flag{wrong}")
        assert not result.accepted
        assert result.status == "rejected"
        assert result.message == "答案错误"
        await client.aclose()

    asyncio.run(scenario())


def test_ichunqiu_accepts_observed_success_message_without_status(monkeypatch):
    monkeypatch.setenv("MIDNIGHT_PLATFORM_TOKEN", "token")

    def handler(request: httpx.Request) -> httpx.Response:
        return _json({"code": 0, "message": "恭喜您，回答正确"})

    async def scenario() -> None:
        client = httpx.AsyncClient(
            base_url="https://api.invalid",
            transport=httpx.MockTransport(handler),
        )
        adapter = IchunqiuPlatformAdapter(
            IchunqiuConfig(base_url="https://api.invalid"), client=client
        )
        result = await adapter.submit("one", "flag{right}")
        assert result.accepted
        assert result.status == "accepted"
        await client.aclose()

    asyncio.run(scenario())


def test_platform_loader_selects_ichunqiu_adapter(tmp_path, monkeypatch):
    monkeypatch.setenv("MIDNIGHT_PLATFORM_TOKEN", "token")
    config = tmp_path / "platform.yaml"
    config.write_text(
        """\
adapter: ichunqiu
base_url: https://api.invalid
endpoints:
  challenges: /inventory
  reset: /restart
  submit: /answer
""",
        encoding="utf-8",
    )
    adapter = _load_http_adapter(str(config))
    assert isinstance(adapter, IchunqiuPlatformAdapter)
    assert adapter.config.endpoints.challenges == "/inventory"
    assert adapter.client.headers["user-agent"] == "Midnight-CTF-Agent/1.0"
    assert not adapter.config.trust_env
    asyncio.run(adapter.close())


def test_platform_http_error_does_not_expose_query_token(monkeypatch):
    token = "secret-platform-token"
    monkeypatch.setenv("MIDNIGHT_PLATFORM_TOKEN", token)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    async def scenario() -> None:
        client = httpx.AsyncClient(
            base_url="https://api.invalid",
            transport=httpx.MockTransport(handler),
        )
        adapter = IchunqiuPlatformAdapter(
            IchunqiuConfig(base_url="https://api.invalid"), client=client
        )
        with pytest.raises(RuntimeError) as caught:
            await adapter.list_challenges()
        message = str(caught.value)
        assert message == "challenge query returned HTTP 403"
        assert token not in message
        assert "?token=" not in message
        await client.aclose()

    asyncio.run(scenario())


def test_interactive_submission_retries_after_instance_reset(monkeypatch):
    monkeypatch.setenv("MIDNIGHT_PLATFORM_TOKEN", "token")
    was_reset = False
    submissions = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal was_reset, submissions
        if request.url.path == "/questions":
            connection = {"docker_ip": "192.0.2.1", "docker_port": 31337} if was_reset else []
            return _json(
                {
                    "code": 0,
                    "data": [
                        {
                            "question_id": "dynamic",
                            "title": "dynamic",
                            "category": "pwn",
                            "interactive": "true",
                            "connection": connection,
                        }
                    ],
                }
            )
        if request.url.path == "/reset":
            was_reset = True
            return _json({"code": 0, "message": "操作成功"})
        if request.url.path == "/submit":
            submissions += 1
            if submissions == 1:
                return _json({"code": 0, "message": "答案错误", "status": 0})
            return _json({"code": 0, "message": "恭喜您，回答正确"})
        return httpx.Response(404)

    async def scenario() -> None:
        client = httpx.AsyncClient(
            base_url="https://api.invalid",
            transport=httpx.MockTransport(handler),
        )
        adapter = IchunqiuPlatformAdapter(
            IchunqiuConfig(
                base_url="https://api.invalid",
                submission_retry_delay_seconds=0,
            ),
            client=client,
        )
        await adapter.start_challenge("dynamic")
        result = await adapter.submit("dynamic", "flag{synced}")
        assert result.accepted
        assert submissions == 2
        await client.aclose()

    asyncio.run(scenario())
