"""Deterministic benchmark summaries that avoid persisting flag values."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from midnight.orchestrator.scheduler import Result

_FLAG_PATTERN = re.compile(r"\b[A-Za-z0-9_]+\{[^}\r\n]+\}")


def _redact_error(error: str | None) -> str | None:
    return _FLAG_PATTERN.sub("<redacted-flag>", error) if error else None


@dataclass(frozen=True)
class ChallengeSummary:
    challenge_id: str
    status: str
    has_flag: bool
    error: str | None = None
    duration_seconds: float = 0.0
    revision: str | None = None


@dataclass(frozen=True)
class RunReport:
    run_id: str
    generated_at: str
    elapsed_seconds: float
    total: int
    solved: int
    success_rate: float
    status_counts: dict[str, int]
    challenges: list[ChallengeSummary]
    models: dict[str, str]

    @classmethod
    def from_results(
        cls,
        run_id: str,
        results: Iterable[Result],
        *,
        elapsed_seconds: float,
        models: dict[str, str] | None = None,
    ) -> RunReport:
        materialized = list(results)
        counts = Counter(result.status for result in materialized)
        summaries = [
            ChallengeSummary(
                challenge_id=result.challenge_id,
                status=result.status,
                has_flag=result.flag is not None,
                error=_redact_error(result.error),
                duration_seconds=result.duration_seconds,
                revision=result.revision,
            )
            for result in materialized
        ]
        solved = counts.get("solved", 0)
        total = len(materialized)
        return cls(
            run_id=run_id,
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            elapsed_seconds=round(elapsed_seconds, 3),
            total=total,
            solved=solved,
            success_rate=round(solved / total, 4) if total else 0.0,
            status_counts=dict(sorted(counts.items())),
            challenges=summaries,
            models=dict(sorted((models or {}).items())),
        )

    def write(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(
            json.dumps(asdict(self), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(target)
        return target
