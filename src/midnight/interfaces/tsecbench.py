"""Dedicated adapter for Tsecbench's managed challenge lifecycle."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from midnight.interfaces.submitter import SubmitResult
from midnight.state import Challenge


class TsecbenchClient(Protocol):
    async def list_challenges(self) -> Any: ...

    async def start_challenge(self, challenge_id: str) -> Any: ...

    async def submit_flag(self, challenge_id: str, flag: str) -> Any: ...

    async def stop_challenge(self, challenge_id: str) -> Any: ...


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if hasattr(value, "model_dump"):
        dumped = value.model_dump(mode="python")
        if isinstance(dumped, Mapping):
            return dumped
    if hasattr(value, "__dict__"):
        return vars(value)
    raise TypeError(f"unexpected Tsecbench response type: {type(value).__name__}")


def _items(value: Any, key: str) -> list[Any]:
    if isinstance(value, list):
        return value
    payload = _mapping(value)
    items = payload.get(key) or payload.get("data") or []
    if not isinstance(items, list):
        raise TypeError(f"Tsecbench {key} response must contain a list")
    return items


def _category(value: Any) -> str:
    raw = str(value or "").lower()
    if "binary" in raw or "exploit" in raw or "pwn" in raw:
        return "pwn"
    if "reverse" in raw:
        return "reverse"
    if "crypto" in raw:
        return "crypto"
    if "forensic" in raw:
        return "forensics"
    if "web" in raw or "cloud" in raw or "pentest" in raw:
        return "web"
    return "misc"


class TsecbenchAdapter:
    """Bridge Tsecbench SDK objects to Midnight provider and submitter contracts."""

    def __init__(self, client: TsecbenchClient):
        self.client = client
        self._challenges: dict[str, Challenge] = {}
        self._started_targets: dict[str, list[str]] = {}

    @classmethod
    def from_sdk(cls, *, base_url: str, token: str, **client_kwargs) -> TsecbenchAdapter:
        try:
            from tsec_benchmark import TSecBenchmarkAsync  # type: ignore[import-not-found]
        except ImportError as exc:
            raise RuntimeError("install the optional tsec-benchmark SDK to use Tsecbench") from exc
        client = TSecBenchmarkAsync(base_url=base_url, token=token, **client_kwargs)
        return cls(client)

    @staticmethod
    def _challenge(value: Any) -> Challenge:
        payload = _mapping(value)
        raw_id = payload.get("id") or payload.get("code") or payload.get("challenge_id")
        if raw_id is None:
            raise ValueError("Tsecbench challenge is missing id/code")
        challenge_id = str(raw_id)
        return Challenge(
            id=challenge_id,
            name=str(payload.get("name") or payload.get("title") or challenge_id),
            description=str(payload.get("description") or payload.get("prompt") or ""),
            files=[],
            remote=None,
            targets=[],
            allowed_targets=[],
            category_hint=_category(payload.get("category") or payload.get("domain")),
            flag_format=payload.get("flag_format"),
            flag_count=int(payload["flag_count"]) if payload.get("flag_count") is not None else None,
            round_id=str(payload.get("task_id") or payload.get("round_id") or "tsecbench"),
        )

    async def list_challenges(self) -> list[Challenge]:
        response = await self.client.list_challenges()
        challenges = [self._challenge(item) for item in _items(response, "challenges")]
        self._challenges = {challenge["id"]: challenge for challenge in challenges}
        return challenges

    async def start_challenge(self, challenge_id: str) -> None:
        response = _mapping(await self.client.start_challenge(challenge_id))
        started = response.get("started") or response.get("data") or response
        payload = _mapping(started)
        addresses = payload.get("container_addr") or payload.get("container_addrs") or []
        if isinstance(addresses, str):
            addresses = [addresses]
        if not isinstance(addresses, list) or not addresses:
            raise ValueError("Tsecbench start response contains no container_addr")
        targets = [str(address) for address in addresses]
        self._started_targets[challenge_id] = targets

    async def stop_challenge(self, challenge_id: str) -> None:
        try:
            await self.client.stop_challenge(challenge_id)
        finally:
            self._started_targets.pop(challenge_id, None)

    async def fetch(self, challenge_id: str) -> Challenge:
        if challenge_id not in self._challenges:
            await self.list_challenges()
        challenge = Challenge(**self._challenges[challenge_id])
        targets = self._started_targets.get(challenge_id, [])
        if targets:
            challenge["remote"] = targets[0]
            challenge["targets"] = targets
            challenge["allowed_targets"] = targets
            challenge["internet_policy"] = "target_only"
        return challenge

    async def download_files(self, challenge_id: str, dest: str) -> list[str]:
        Path(dest).mkdir(parents=True, exist_ok=True)
        return []

    async def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        try:
            payload = _mapping(await self.client.submit_flag(challenge_id, flag))
        except Exception as exc:  # SDK exception hierarchy differs between releases
            name = type(exc).__name__.lower()
            if "duplicate" in name:
                return SubmitResult(False, "duplicate submission", submitted=False, status="duplicate")
            raise
        accepted = bool(payload.get("accepted") or payload.get("correct"))
        return SubmitResult(
            accepted=accepted,
            message=str(payload.get("message") or payload.get("detail") or ""),
            points=int(payload["points"]) if payload.get("points") is not None else None,
            status="accepted" if accepted else "rejected",
        )

    async def close(self) -> None:
        close = getattr(self.client, "aclose", None) or getattr(self.client, "close", None)
        if close is not None:
            result = close()
            if hasattr(result, "__await__"):
                await result
