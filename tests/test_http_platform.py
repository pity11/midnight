from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from midnight.interfaces.http_platform import (
    ChallengeFieldMap,
    HTTPPlatformAdapter,
    HTTPPlatformConfig,
    ResponseMap,
)


def _response(data, status=200):
    return httpx.Response(
        status, content=json.dumps(data).encode(), headers={"content-type": "application/json"}
    )


def test_http_adapter_lists_fetches_downloads_and_submits(tmp_path):
    async def scenario():
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/challenges" and request.method == "GET":
                return _response({"challenges": [{"id": "1", "name": "Demo", "category": "misc"}]})
            if request.url.path == "/api/challenges/1" and request.method == "GET":
                return _response(
                    {
                        "id": "1",
                        "name": "Demo",
                        "description": "offline fixture",
                        "category": "misc",
                        "round_id": "r1",
                        "attachments": [{"name": "sample.bin", "url": "/files/sample.bin"}],
                    }
                )
            if request.url.path == "/files/sample.bin":
                return httpx.Response(200, content=b"sample")
            if request.url.path == "/api/challenges/1/submit" and request.method == "POST":
                return _response({"accepted": True, "message": "correct", "points": 100})
            return httpx.Response(404)

        client = httpx.AsyncClient(
            base_url="https://ctf.invalid",
            transport=httpx.MockTransport(handler),
        )
        adapter = HTTPPlatformAdapter(
            HTTPPlatformConfig(base_url="https://ctf.invalid"), client=client
        )
        listed = await adapter.list_challenges()
        assert listed[0]["id"] == "1"
        challenge = await adapter.fetch("1")
        assert challenge["round_id"] == "r1"
        paths = await adapter.download_files("1", str(tmp_path))
        assert len(paths) == 1
        assert (tmp_path / "sample.bin").read_bytes() == b"sample"
        result = await adapter.submit("1", "flag{demo}")
        assert result.accepted and result.points == 100
        await client.aclose()

    asyncio.run(scenario())


def test_http_adapter_blocks_external_attachments(tmp_path):
    async def scenario():
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/challenges/1":
                return _response(
                    {
                        "id": "1",
                        "attachments": [{"name": "x", "url": "https://other.invalid/x"}],
                    }
                )
            return httpx.Response(404)

        client = httpx.AsyncClient(
            base_url="https://ctf.invalid",
            transport=httpx.MockTransport(handler),
        )
        adapter = HTTPPlatformAdapter(
            HTTPPlatformConfig(base_url="https://ctf.invalid"), client=client
        )
        await adapter.fetch("1")
        with pytest.raises(ValueError, match="external"):
            await adapter.download_files("1", str(tmp_path))
        await client.aclose()

    asyncio.run(scenario())


def test_http_adapter_enforces_attachment_size_limit(tmp_path):
    async def scenario():
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/challenges/1":
                return _response(
                    {
                        "id": "1",
                        "attachments": [{"name": "large.bin", "url": "/large.bin"}],
                    }
                )
            if request.url.path == "/large.bin":
                return httpx.Response(200, content=b"too large")
            return httpx.Response(404)

        client = httpx.AsyncClient(
            base_url="https://ctf.invalid",
            transport=httpx.MockTransport(handler),
        )
        adapter = HTTPPlatformAdapter(
            HTTPPlatformConfig(base_url="https://ctf.invalid", max_attachment_bytes=4),
            client=client,
        )
        await adapter.fetch("1")
        with pytest.raises(ValueError, match="byte limit"):
            await adapter.download_files("1", str(tmp_path))
        assert not (tmp_path / "large.bin").exists()
        assert not (tmp_path / "large.bin.part").exists()
        await client.aclose()

    asyncio.run(scenario())


def test_http_adapter_maps_nested_platform_payloads(tmp_path):
    async def scenario():
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/challenges" and request.method == "GET":
                return _response(
                    {"data": {"tasks": [{"taskId": 7, "title": "Mapped", "kind": "web"}]}}
                )
            if request.url.path == "/api/challenges/7" and request.method == "GET":
                return _response(
                    {
                        "data": {
                            "taskId": 7,
                            "title": "Mapped",
                            "body": "nested payload",
                            "kind": "web",
                            "target": "https://target.invalid",
                            "files": [{"filename": "source.zip", "download": "/source.zip"}],
                        }
                    }
                )
            if request.url.path == "/source.zip":
                return httpx.Response(200, content=b"zip")
            if request.url.path == "/api/challenges/7/submit":
                assert json.loads(request.content) == {"answer": "flag{mapped}"}
                return _response({"data": {"ok": 1, "detail": "accepted", "score": 500}})
            return httpx.Response(404)

        client = httpx.AsyncClient(
            base_url="https://ctf.invalid",
            transport=httpx.MockTransport(handler),
        )
        adapter = HTTPPlatformAdapter(
            HTTPPlatformConfig(
                base_url="https://ctf.invalid",
                submit_field="answer",
                fields=ChallengeFieldMap(
                    id="taskId",
                    name="title",
                    description="body",
                    category="kind",
                    remote="target",
                    attachments="files",
                    attachment_name="filename",
                    attachment_url="download",
                ),
                responses=ResponseMap(
                    challenge_list="data.tasks",
                    challenge_detail="data",
                    submission="data",
                    accepted="ok",
                    message="detail",
                    points="score",
                ),
            ),
            client=client,
        )
        listed = await adapter.list_challenges()
        assert listed == [
            {
                "id": "7",
                "name": "Mapped",
                "description": "",
                "files": [],
                "remote": None,
                "category_hint": "web",
                "flag_format": None,
                "round_id": None,
            }
        ]
        challenge = await adapter.fetch("7")
        assert challenge["description"] == "nested payload"
        assert challenge["remote"] == "https://target.invalid"
        await adapter.download_files("7", str(tmp_path))
        assert (tmp_path / "source.zip").read_bytes() == b"zip"
        result = await adapter.submit("7", "flag{mapped}")
        assert result.accepted and result.points == 500
        await client.aclose()

    asyncio.run(scenario())
