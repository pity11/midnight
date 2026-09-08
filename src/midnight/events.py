"""Append-only run events for recovery, audit, and benchmark analysis."""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


_SECRET_MARKERS = ("token", "secret", "password", "cookie", "authorization", "api_key")
_VALUE_PATTERNS = (
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*"),
    re.compile(r"\b(?:sk|ghp|github_pat)-?[A-Za-z0-9_]{16,}\b"),
)


def _redact_string(value: str) -> str:
    for pattern in _VALUE_PATTERNS:
        value = pattern.sub("<redacted>", value)
    return value


def _redact(value: Any, key: str = "") -> Any:
    """Return a JSON-safe copy with credential-bearing fields removed."""
    if any(marker in key.lower() for marker in _SECRET_MARKERS):
        return "<redacted>"
    if isinstance(value, Mapping):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        return _redact_string(value)
    return value


@dataclass(frozen=True)
class RunEvent:
    event: str
    run_id: str
    challenge_id: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    )

    def to_record(self) -> dict[str, Any]:
        return _redact(asdict(self))


class EventJournal:
    """Thread-safe JSONL journal using append + flush for crash visibility."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, event: RunEvent) -> None:
        encoded = json.dumps(event.to_record(), ensure_ascii=False, sort_keys=True)
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(encoded + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"invalid event journal line {line_number}: {self.path}"
                    ) from exc
        return records
