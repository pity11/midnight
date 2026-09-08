"""FlagSubmitter: the 'submit flag' end (reserved interface).

Implement this per competition via a skill/MCP. v1 uses ManualSubmitter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable


@dataclass
class SubmitResult:
    accepted: bool
    message: str = ""
    points: int | None = None
    submitted: bool = True
    status: Literal["accepted", "rejected", "dry_run", "duplicate", "error"] | None = None

    def __post_init__(self) -> None:
        if self.status is None:
            self.status = "accepted" if self.accepted else "rejected"


@runtime_checkable
class FlagSubmitter(Protocol):
    """Submits a flag for a challenge and reports the verdict."""

    async def submit(self, challenge_id: str, flag: str) -> SubmitResult: ...
