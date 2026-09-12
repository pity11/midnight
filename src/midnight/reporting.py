"""Deterministic benchmark summaries that avoid persisting flag values."""

from __future__ import annotations

import json
import math
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
    category: str | None = None
    attempts: int = 0
    points: int | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    repeated_tool_calls: int = 0
    tool_errors: int = 0
    flags_solved: int = 0
    flags_available: int = 1
    protocol_recoveries: int = 0
    model_transport_failures: int = 0


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
    total_points: int
    input_tokens: int
    output_tokens: int
    tool_calls: int
    repeated_tool_calls: int
    tool_errors: int
    category_results: dict[str, dict[str, int]]
    run_manifest_id: str | None = None
    flags_solved: int = 0
    flags_available: int = 0
    protocol_recoveries: int = 0
    model_transport_failures: int = 0

    @classmethod
    def from_results(
        cls,
        run_id: str,
        results: Iterable[Result],
        *,
        elapsed_seconds: float,
        models: dict[str, str] | None = None,
        run_manifest_id: str | None = None,
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
                category=result.category,
                attempts=result.attempts,
                points=result.points,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
                tool_calls=result.tool_calls,
                repeated_tool_calls=result.repeated_tool_calls,
                tool_errors=result.tool_errors,
                flags_solved=result.flags_solved,
                flags_available=result.flags_available,
                protocol_recoveries=result.protocol_recoveries,
                model_transport_failures=result.model_transport_failures,
            )
            for result in materialized
        ]
        solved = counts.get("solved", 0)
        total = len(materialized)
        categories: dict[str, dict[str, int]] = {}
        for result in materialized:
            category = result.category or "unknown"
            entry = categories.setdefault(category, {"total": 0, "solved": 0})
            entry["total"] += 1
            entry["solved"] += int(result.status == "solved")
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
            total_points=sum(result.points or 0 for result in materialized),
            input_tokens=sum(result.input_tokens for result in materialized),
            output_tokens=sum(result.output_tokens for result in materialized),
            tool_calls=sum(result.tool_calls for result in materialized),
            repeated_tool_calls=sum(result.repeated_tool_calls for result in materialized),
            tool_errors=sum(result.tool_errors for result in materialized),
            category_results=dict(sorted(categories.items())),
            run_manifest_id=run_manifest_id,
            flags_solved=sum(result.flags_solved for result in materialized),
            flags_available=sum(result.flags_available for result in materialized),
            protocol_recoveries=sum(result.protocol_recoveries for result in materialized),
            model_transport_failures=sum(
                result.model_transport_failures for result in materialized
            ),
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


@dataclass(frozen=True)
class AggregateChallenge:
    challenge_id: str
    category: str
    solved_attempts: int
    attempts: int
    success_at_1: bool
    success_in_n: bool


@dataclass(frozen=True)
class AggregateReport:
    generated_at: str
    attempts: int
    total_challenges: int
    observations: int
    success_at_1: float
    success_in_n: float
    mean_solve_probability: float
    mean_solve_probability_ci95: tuple[float, float]
    run_ids: list[str]
    run_manifest_ids: list[str | None]
    challenges: list[AggregateChallenge]
    category_results: dict[str, dict[str, float | int]]

    @classmethod
    def from_reports(cls, reports: Iterable[RunReport]) -> AggregateReport:
        materialized = list(reports)
        if not materialized:
            raise ValueError("at least one run report is required")
        first_ids = [item.challenge_id for item in materialized[0].challenges]
        if not first_ids or len(first_ids) != len(set(first_ids)):
            raise ValueError("run reports must contain a non-empty unique challenge inventory")
        expected = set(first_ids)
        for report in materialized[1:]:
            ids = [item.challenge_id for item in report.challenges]
            if len(ids) != len(set(ids)) or set(ids) != expected:
                raise ValueError("run reports must contain the same unique challenge inventory")

        indexed = [
            {item.challenge_id: item for item in report.challenges} for report in materialized
        ]
        challenges: list[AggregateChallenge] = []
        for challenge_id in sorted(expected):
            entries = [attempt[challenge_id] for attempt in indexed]
            categories = {entry.category or "unknown" for entry in entries}
            if len(categories) != 1:
                raise ValueError(f"category changed between attempts for {challenge_id}")
            solved = sum(entry.status == "solved" for entry in entries)
            challenges.append(
                AggregateChallenge(
                    challenge_id=challenge_id,
                    category=categories.pop(),
                    solved_attempts=solved,
                    attempts=len(entries),
                    success_at_1=entries[0].status == "solved",
                    success_in_n=solved > 0,
                )
            )

        observations = len(challenges) * len(materialized)
        solved_observations = sum(item.solved_attempts for item in challenges)
        probability = solved_observations / observations
        category_results: dict[str, dict[str, float | int]] = {}
        for category in sorted({item.category for item in challenges}):
            items = [item for item in challenges if item.category == category]
            category_results[category] = {
                "total": len(items),
                "success_at_1": sum(item.success_at_1 for item in items),
                "success_in_n": sum(item.success_in_n for item in items),
                "solved_observations": sum(item.solved_attempts for item in items),
                "observations": len(items) * len(materialized),
            }
        return cls(
            generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
            attempts=len(materialized),
            total_challenges=len(challenges),
            observations=observations,
            success_at_1=round(sum(item.success_at_1 for item in challenges) / len(challenges), 4),
            success_in_n=round(sum(item.success_in_n for item in challenges) / len(challenges), 4),
            mean_solve_probability=round(probability, 4),
            mean_solve_probability_ci95=_wilson_interval(solved_observations, observations),
            run_ids=[report.run_id for report in materialized],
            run_manifest_ids=[report.run_manifest_id for report in materialized],
            challenges=challenges,
            category_results=category_results,
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


def _wilson_interval(successes: int, observations: int) -> tuple[float, float]:
    """Two-sided 95% Wilson score interval for Bernoulli observations."""
    if observations <= 0 or not 0 <= successes <= observations:
        raise ValueError("invalid Bernoulli counts")
    z = 1.959963984540054
    proportion = successes / observations
    denominator = 1 + z**2 / observations
    centre = (proportion + z**2 / (2 * observations)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / observations + z**2 / (4 * observations**2)
        )
        / denominator
    )
    return round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4)


def load_run_report(path: str | Path) -> RunReport:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    payload["challenges"] = [ChallengeSummary(**item) for item in payload["challenges"]]
    return RunReport(**payload)
