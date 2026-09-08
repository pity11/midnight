"""Configurable JSON-over-HTTP adapter for authorized CTF platforms."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Self
from urllib.parse import urljoin, urlparse

import httpx

from midnight.interfaces.submitter import SubmitResult
from midnight.state import Challenge


@dataclass(frozen=True)
class EndpointMap:
    health: str = "/api/health"
    challenges: str = "/api/challenges"
    challenge: str = "/api/challenges/{challenge_id}"
    submit: str = "/api/challenges/{challenge_id}/submit"


@dataclass(frozen=True)
class HTTPPlatformConfig:
    base_url: str
    token_env: str | None = None
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    timeout_seconds: float = 15.0
    endpoints: EndpointMap = field(default_factory=EndpointMap)
    allow_external_downloads: bool = False
    max_attachment_bytes: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute HTTP(S) URL")


class HTTPPlatformAdapter:
    """A conservative default adapter with overridable endpoint paths.

    Expected list responses are either a JSON array or
    ``{"challenges": [...]}``. Challenge objects use the canonical Midnight
    field names and may include an ``attachments`` list containing ``name``
    and ``url``.
    """

    def __init__(self, config: HTTPPlatformConfig, *, client: httpx.AsyncClient | None = None):
        self.config = config
        self._owns_client = client is None
        self.client = client or httpx.AsyncClient(
            base_url=config.base_url.rstrip("/"),
            timeout=config.timeout_seconds,
            headers=self._headers(),
            follow_redirects=False,
        )
        self._attachments: dict[str, list[dict[str, str]]] = {}

    def _headers(self) -> dict[str, str]:
        if not self.config.token_env:
            return {}
        token = os.environ.get(self.config.token_env)
        if not token:
            raise RuntimeError(f"required credential is missing: {self.config.token_env}")
        value = f"{self.config.auth_scheme} {token}".strip()
        return {self.config.auth_header: value}

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.close()

    async def health(self) -> bool:
        response = await self.client.get(self.config.endpoints.health)
        return response.is_success

    @staticmethod
    def _challenge(payload: dict[str, Any]) -> Challenge:
        if "id" not in payload:
            raise ValueError("challenge payload is missing id")
        return Challenge(
            id=str(payload["id"]),
            name=str(payload.get("name") or payload["id"]),
            description=str(payload.get("description") or ""),
            files=[],
            remote=payload.get("remote"),
            category_hint=payload.get("category_hint") or payload.get("category"),
            flag_format=payload.get("flag_format"),
            round_id=str(payload.get("round_id")) if payload.get("round_id") is not None else None,
        )

    async def list_challenges(self) -> list[Challenge]:
        response = await self.client.get(self.config.endpoints.challenges)
        response.raise_for_status()
        payload = response.json()
        items = payload.get("challenges", []) if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            raise TypeError("challenge list response must be an array")
        return [self._challenge(item) for item in items]

    async def fetch(self, challenge_id: str) -> Challenge:
        path = self.config.endpoints.challenge.format(challenge_id=challenge_id)
        response = await self.client.get(path)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise TypeError("challenge response must be an object")
        attachments = payload.get("attachments") or []
        if not isinstance(attachments, list):
            raise TypeError("attachments must be an array")
        self._attachments[challenge_id] = [dict(item) for item in attachments]
        return self._challenge(payload)

    def _download_allowed(self, url: str) -> bool:
        if self.config.allow_external_downloads:
            return True
        source = urlparse(self.config.base_url)
        target = urlparse(urljoin(self.config.base_url, url))
        return (source.scheme, source.netloc) == (target.scheme, target.netloc)

    async def download_files(self, challenge_id: str, dest: str) -> list[str]:
        if challenge_id not in self._attachments:
            await self.fetch(challenge_id)
        destination = Path(dest)
        destination.mkdir(parents=True, exist_ok=True)
        downloaded: list[str] = []
        for item in self._attachments.get(challenge_id, []):
            name = str(item.get("name") or "")
            url = str(item.get("url") or "")
            if not name or not url or PurePath(name).name != name:
                raise ValueError("invalid attachment name or URL")
            absolute_url = urljoin(self.config.base_url, url)
            if not self._download_allowed(absolute_url):
                raise ValueError("external attachment download is disabled")
            target = destination / name
            temporary = target.with_suffix(target.suffix + ".part")
            size = 0
            try:
                async with self.client.stream("GET", absolute_url) as response:
                    response.raise_for_status()
                    with temporary.open("wb") as stream:
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > self.config.max_attachment_bytes:
                                raise ValueError(f"attachment exceeds byte limit: {name}")
                            stream.write(chunk)
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
            downloaded.append(str(target))
        return downloaded

    async def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        path = self.config.endpoints.submit.format(challenge_id=challenge_id)
        response = await self.client.post(path, json={"flag": flag})
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise TypeError("submission response must be an object")
        accepted = bool(payload.get("accepted", False))
        return SubmitResult(
            accepted=accepted,
            message=str(payload.get("message") or ""),
            points=payload.get("points"),
            status="accepted" if accepted else "rejected",
        )

    @staticmethod
    def sha256(path: str | Path) -> str:
        digest = hashlib.sha256()
        with Path(path).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
