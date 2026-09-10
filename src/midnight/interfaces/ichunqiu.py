"""Adapter for the organizer's AI-agent CTF query/reset/submit API."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Self
from urllib.parse import unquote, urljoin, urlparse

import httpx

from midnight.interfaces.submitter import SubmitResult
from midnight.state import Challenge


@dataclass(frozen=True)
class IchunqiuEndpoints:
    challenges: str = "/questions"
    reset: str = "/reset"
    submit: str = "/submit"


@dataclass(frozen=True)
class IchunqiuConfig:
    base_url: str = "https://ctf.example.invalid"
    token_env: str = "MIDNIGHT_PLATFORM_TOKEN"
    timeout_seconds: float = 20.0
    max_attachment_bytes: int = 256 * 1024 * 1024
    include_solved: bool = False
    reset_poll_seconds: int = 20
    submission_retry_attempts: int = 1
    submission_retry_delay_seconds: float = 30.0
    user_agent: str = "Midnight-CTF-Agent/1.0"
    trust_env: bool = False
    endpoints: IchunqiuEndpoints = field(default_factory=IchunqiuEndpoints)

    def __post_init__(self) -> None:
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("iChunqiu base_url must be an absolute HTTPS URL")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_attachment_bytes <= 0:
            raise ValueError("max_attachment_bytes must be positive")
        if self.reset_poll_seconds <= 0:
            raise ValueError("reset_poll_seconds must be positive")
        if self.submission_retry_attempts < 0:
            raise ValueError("submission_retry_attempts must not be negative")
        if self.submission_retry_delay_seconds < 0:
            raise ValueError("submission_retry_delay_seconds must not be negative")
        if not self.user_agent.strip():
            raise ValueError("user_agent must not be empty")


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes"}


def _category(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    aliases = {
        "re": "reverse",
        "rev": "reverse",
        "reverse engineering": "reverse",
        "forensic": "forensics",
        "取证": "forensics",
        "密码": "crypto",
        "杂项": "misc",
    }
    return aliases.get(text, text or None)


class IchunqiuPlatformAdapter:
    """Normalize the organizer API while keeping the query token out of logs."""

    def __init__(self, config: IchunqiuConfig, *, client: httpx.AsyncClient | None = None):
        self.config = config
        self._owns_client = client is None
        # httpx logs complete URLs at INFO, including query parameters. The
        # organizer requires the credential in `?token=`, so suppress that log.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        self.client = client or httpx.AsyncClient(
            base_url=config.base_url.rstrip("/"),
            timeout=config.timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": config.user_agent, "Accept": "application/json"},
            trust_env=config.trust_env,
        )
        self._raw: dict[str, dict[str, Any]] = {}
        self._attachments: dict[str, list[str]] = {}
        self._reset_challenges: set[str] = set()

    def _token(self) -> str:
        token = os.environ.get(self.config.token_env, "").strip()
        if not token:
            raise RuntimeError(f"required credential is missing: {self.config.token_env}")
        return token

    def _params(self, **values: str) -> dict[str, str]:
        return {"token": self._token(), **values}

    @staticmethod
    def _raise_for_status(response: httpx.Response, operation: str) -> None:
        """Raise without embedding the query-token URL in the exception."""
        if response.is_error:
            raise RuntimeError(f"{operation} returned HTTP {response.status_code}")

    @staticmethod
    def _check_envelope(payload: Any, operation: str) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise TypeError(f"{operation} response must be a JSON object")
        if str(payload.get("code")) != "0":
            message = str(payload.get("message") or f"{operation} failed")
            raise RuntimeError(message)
        return payload

    @staticmethod
    def _remote(item: dict[str, Any], category: str | None) -> str | None:
        if not _truthy(item.get("interactive")):
            return None
        connection = item.get("connection")
        if not isinstance(connection, dict):
            return None
        host = str(connection.get("docker_ip") or "").strip()
        port = str(connection.get("docker_port") or "").strip()
        if host and port:
            value = f"{host}:{port}"
            return f"http://{value}" if category == "web" else value
        value = str(connection.get("docker_url") or "").strip()
        nc_match = re.fullmatch(r"nc\s+(\S+)\s+(\d+)", value, flags=re.IGNORECASE)
        if nc_match:
            return f"{nc_match.group(1)}:{nc_match.group(2)}"
        if value and category == "web" and "://" not in value:
            return f"http://{value}"
        return value or None

    @staticmethod
    def _description(item: dict[str, Any]) -> str:
        body = str(item.get("description") or "")
        context: list[str] = []
        for label, key in (("Attributes", "attributes"), ("Capabilities", "capabilities")):
            value = item.get(key)
            if value:
                context.append(f"{label}: {json.dumps(value, ensure_ascii=False)}")
        extensions = item.get("extensions")
        if extensions:
            context.append(f"Extensions: {json.dumps(extensions, ensure_ascii=False)}")
        return body + (("\n\n" if body else "") + "\n".join(context) if context else "")

    def _challenge(self, item: dict[str, Any]) -> Challenge:
        challenge_id = item.get("question_id")
        if challenge_id is None:
            raise ValueError("challenge payload is missing question_id")
        category = _category(item.get("category"))
        file_value = item.get("file_url")
        urls = [str(value) for value in file_value] if isinstance(file_value, list) else []
        if isinstance(file_value, str) and file_value.strip():
            urls = [file_value.strip()]
        key = str(challenge_id)
        self._raw[key] = item
        self._attachments[key] = [url for url in urls if url]
        return Challenge(
            id=key,
            name=str(item.get("title") or key),
            description=self._description(item),
            files=[],
            remote=self._remote(item, category),
            category_hint=category,
            flag_format=None,
            round_id=None,
            difficulty=None,
        )

    async def close(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self.close()

    async def _inventory(self) -> list[dict[str, Any]]:
        response = await self.client.get(
            self.config.endpoints.challenges,
            params=self._params(),
        )
        self._raise_for_status(response, "challenge query")
        payload = self._check_envelope(response.json(), "challenge query")
        data = payload.get("data")
        if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
            raise TypeError("challenge query data must be an array of objects")
        return data

    async def list_challenges(self) -> list[Challenge]:
        items = await self._inventory()
        if not self.config.include_solved:
            items = [item for item in items if not _truthy(item.get("is_solved"))]
        return [self._challenge(item) for item in items]

    async def fetch(self, challenge_id: str) -> Challenge:
        cached = self._raw.get(challenge_id)
        if cached is not None:
            return self._challenge(cached)
        items = await self._inventory()
        for item in items:
            if str(item.get("question_id")) == challenge_id:
                return self._challenge(item)
        raise KeyError(f"challenge not found: {challenge_id}")

    @staticmethod
    def _filename(url: str, index: int) -> str:
        name = unquote(PurePath(urlparse(url).path).name)
        if not name or name in {"download", "file"}:
            name = f"attachment-{index}"
        return name

    async def download_files(self, challenge_id: str, dest: str) -> list[str]:
        if challenge_id not in self._attachments:
            await self.fetch(challenge_id)
        destination = Path(dest)
        destination.mkdir(parents=True, exist_ok=True)
        downloaded: list[str] = []
        used: set[str] = set()
        for index, url in enumerate(self._attachments.get(challenge_id, []), 1):
            absolute_url = urljoin(self.config.base_url.rstrip("/") + "/", url)
            parsed = urlparse(absolute_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError("organizer attachment URL must resolve to HTTP(S)")
            name = self._filename(absolute_url, index)
            if PurePath(name).name != name:
                raise ValueError("unsafe organizer attachment filename")
            if name in used:
                stem, suffix = Path(name).stem, Path(name).suffix
                name = f"{stem}-{index}{suffix}"
            used.add(name)
            target = destination / name
            temporary = target.with_suffix(target.suffix + ".part")
            size = 0
            try:
                async with self.client.stream("GET", absolute_url) as response:
                    self._raise_for_status(response, "attachment download")
                    disposition = response.headers.get("content-disposition", "")
                    match = re.search(
                        r"filename\*?=(?:UTF-8''|\")?([^\";]+)",
                        disposition,
                        re.IGNORECASE,
                    )
                    if match:
                        candidate = unquote(match.group(1).strip())
                        if PurePath(candidate).name == candidate and candidate not in used:
                            target = destination / candidate
                            temporary = target.with_suffix(target.suffix + ".part")
                            used.add(candidate)
                    with temporary.open("wb") as stream:
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > self.config.max_attachment_bytes:
                                raise ValueError(f"attachment exceeds byte limit: {target.name}")
                            stream.write(chunk)
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
            downloaded.append(str(target))
        return downloaded

    async def start_challenge(self, challenge_id: str) -> None:
        item = self._raw.get(challenge_id)
        if item is None:
            await self.fetch(challenge_id)
            item = self._raw[challenge_id]
        if not _truthy(item.get("interactive")):
            return
        if self._remote(item, _category(item.get("category"))):
            return
        response = await self.client.get(
            self.config.endpoints.reset,
            params=self._params(question_id=challenge_id),
        )
        self._raise_for_status(response, "environment reset")
        self._check_envelope(response.json(), "environment reset")
        self._reset_challenges.add(challenge_id)
        for attempt in range(self.config.reset_poll_seconds):
            items = await self._inventory()
            current = next(
                (entry for entry in items if str(entry.get("question_id")) == challenge_id),
                None,
            )
            if current is not None:
                challenge = self._challenge(current)
                if challenge.get("remote"):
                    return
            if attempt + 1 < self.config.reset_poll_seconds:
                await asyncio.sleep(1)
        raise RuntimeError(f"reset succeeded but target connection is unavailable: {challenge_id}")

    async def stop_challenge(self, challenge_id: str) -> None:
        # The organizer contract exposes reset but no stop/release endpoint.
        return None

    async def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        attempts = 1
        if challenge_id in self._reset_challenges:
            attempts += self.config.submission_retry_attempts
        result: SubmitResult | None = None
        for attempt in range(attempts):
            response = await self.client.get(
                self.config.endpoints.submit,
                params=self._params(question_id=challenge_id, answer=flag),
            )
            self._raise_for_status(response, "answer submission")
            payload = response.json()
            if not isinstance(payload, dict):
                raise TypeError("answer submission response must be a JSON object")
            message = str(payload.get("message") or "")
            accepted_message = any(
                marker in message for marker in ("回答正确", "答案正确", "恭喜您")
            )
            accepted = accepted_message or (
                str(payload.get("code")) == "0" and _truthy(payload.get("status"))
            )
            result = SubmitResult(
                accepted=accepted,
                message=message,
                points=None,
                status="accepted" if accepted else "rejected",
            )
            if accepted:
                self._reset_challenges.discard(challenge_id)
                return result
            if attempt + 1 < attempts:
                await asyncio.sleep(self.config.submission_retry_delay_seconds)
        if result is None:  # pragma: no cover - attempts is always at least one
            raise RuntimeError("answer submission did not run")
        return result
