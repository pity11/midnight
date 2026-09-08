"""Deterministic submission policy shared by all platform adapters."""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from pathlib import Path

from midnight.interfaces.submitter import FlagSubmitter, SubmitResult
from midnight.utils.flag import looks_like_flag


class SubmissionGate:
    """Adds validation, dry-run policy, and durable idempotency to a submitter.

    The ledger stores a SHA-256 candidate digest rather than the flag itself.
    A candidate is reserved before the platform call, so a process crash cannot
    accidentally cause an automatic second submission with an unknown verdict.
    """

    def __init__(
        self,
        delegate: FlagSubmitter,
        *,
        enabled: bool,
        flag_format: str | None = None,
        ledger_path: str | Path | None = None,
        namespace: str = "default",
    ):
        self.delegate = delegate
        self.enabled = enabled
        self.flag_format = flag_format
        self.ledger_path = Path(ledger_path) if ledger_path else None
        self.namespace = namespace
        self._seen: dict[tuple[str, str], SubmitResult] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _digest(candidate: str) -> str:
        return hashlib.sha256(candidate.encode()).hexdigest()

    def _initialize_ledger(self) -> None:
        if self.ledger_path is None:
            return
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.ledger_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS submissions (
                    namespace TEXT NOT NULL,
                    challenge_id TEXT NOT NULL,
                    candidate_digest TEXT NOT NULL,
                    accepted INTEGER NOT NULL DEFAULT 0,
                    submitted INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL DEFAULT '',
                    points INTEGER,
                    PRIMARY KEY (namespace, challenge_id, candidate_digest)
                )
                """
            )

    def _read_persistent(self, challenge_id: str, digest: str) -> SubmitResult | None:
        if self.ledger_path is None:
            return None
        self._initialize_ledger()
        with sqlite3.connect(self.ledger_path) as connection:
            row = connection.execute(
                """SELECT accepted, submitted, status, message, points
                   FROM submissions
                   WHERE namespace = ? AND challenge_id = ? AND candidate_digest = ?""",
                (self.namespace, challenge_id, digest),
            ).fetchone()
        if row is None:
            return None
        accepted, submitted, status, message, points = row
        return SubmitResult(
            accepted=bool(accepted),
            submitted=bool(submitted),
            status=status,
            message=message,
            points=points,
        )

    def _write_persistent(self, challenge_id: str, digest: str, result: SubmitResult) -> None:
        if self.ledger_path is None:
            return
        self._initialize_ledger()
        with sqlite3.connect(self.ledger_path) as connection:
            connection.execute(
                """INSERT OR REPLACE INTO submissions
                   (namespace, challenge_id, candidate_digest, accepted, submitted,
                    status, message, points)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    self.namespace,
                    challenge_id,
                    digest,
                    int(result.accepted),
                    int(result.submitted),
                    result.status,
                    result.message,
                    result.points,
                ),
            )

    def _reserve_persistent(self, challenge_id: str, digest: str) -> bool:
        """Atomically reserve a candidate across independent runner processes."""
        if self.ledger_path is None:
            return True
        self._initialize_ledger()
        with sqlite3.connect(self.ledger_path, timeout=10) as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO submissions
                   (namespace, challenge_id, candidate_digest, accepted, submitted,
                    status, message, points)
                   VALUES (?, ?, ?, 0, 0, 'duplicate',
                           'submission reserved; previous verdict may be unknown', NULL)""",
                (self.namespace, challenge_id, digest),
            )
            return cursor.rowcount == 1

    async def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        candidate = flag.strip()
        if not looks_like_flag(candidate, flag_format=self.flag_format):
            return SubmitResult(
                accepted=False,
                submitted=False,
                status="error",
                message="candidate does not match the configured flag format",
            )

        key = (challenge_id, candidate)
        digest = self._digest(candidate)
        async with self._lock:
            prior = self._seen.get(key)
            if prior is None:
                prior = self._read_persistent(challenge_id, digest)
            if prior is not None:
                return SubmitResult(
                    accepted=prior.accepted,
                    submitted=False,
                    status="duplicate",
                    message="duplicate candidate suppressed",
                    points=prior.points,
                )
            if not self.enabled:
                result = SubmitResult(
                    accepted=False,
                    submitted=False,
                    status="dry_run",
                    message="submission disabled by dry-run policy",
                )
                self._seen[key] = result
                self._write_persistent(challenge_id, digest, result)
                return result

            reservation = SubmitResult(
                accepted=False,
                submitted=False,
                status="duplicate",
                message="submission reserved; previous verdict may be unknown",
            )
            if not self._reserve_persistent(challenge_id, digest):
                prior = self._read_persistent(challenge_id, digest) or reservation
                return SubmitResult(
                    accepted=prior.accepted,
                    submitted=False,
                    status="duplicate",
                    message="duplicate candidate suppressed",
                    points=prior.points,
                )
            result = await self.delegate.submit(challenge_id, candidate)
            self._seen[key] = result
            self._write_persistent(challenge_id, digest, result)
            return result
