from __future__ import annotations

import asyncio

from midnight.interfaces.submission_gate import SubmissionGate
from midnight.interfaces.submitter import SubmitResult


class CountingSubmitter:
    def __init__(self):
        self.calls = 0

    async def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        self.calls += 1
        return SubmitResult(accepted=True, message="accepted")


def test_dry_run_never_calls_delegate():
    async def scenario():
        delegate = CountingSubmitter()
        gate = SubmissionGate(delegate, enabled=False)
        result = await gate.submit("c1", "flag{candidate}")
        assert result.status == "dry_run"
        assert not result.submitted
        assert delegate.calls == 0

    asyncio.run(scenario())


def test_duplicate_candidate_is_suppressed():
    async def scenario():
        delegate = CountingSubmitter()
        gate = SubmissionGate(delegate, enabled=True)
        first = await gate.submit("c1", "flag{candidate}")
        second = await gate.submit("c1", "flag{candidate}")
        assert first.accepted
        assert second.status == "duplicate"
        assert not second.submitted
        assert delegate.calls == 1

    asyncio.run(scenario())


def test_invalid_candidate_is_rejected_locally():
    async def scenario():
        delegate = CountingSubmitter()
        gate = SubmissionGate(delegate, enabled=True)
        result = await gate.submit("c1", "not-a-flag")
        assert result.status == "error"
        assert delegate.calls == 0

    asyncio.run(scenario())


def test_duplicate_candidate_survives_process_restart(tmp_path):
    async def scenario():
        ledger = tmp_path / "submissions.sqlite"
        first_delegate = CountingSubmitter()
        first_gate = SubmissionGate(
            first_delegate, enabled=True, ledger_path=ledger, namespace="run-1"
        )
        assert (await first_gate.submit("c1", "flag{candidate}")).accepted

        second_delegate = CountingSubmitter()
        second_gate = SubmissionGate(
            second_delegate, enabled=True, ledger_path=ledger, namespace="run-1"
        )
        duplicate = await second_gate.submit("c1", "flag{candidate}")
        assert duplicate.status == "duplicate"
        assert second_delegate.calls == 0
        assert "flag{candidate}" not in ledger.read_bytes().decode(errors="ignore")

    asyncio.run(scenario())


def test_two_gate_instances_share_atomic_reservation(tmp_path):
    async def scenario():
        ledger = tmp_path / "submissions.sqlite"
        first_delegate = CountingSubmitter()
        second_delegate = CountingSubmitter()
        gates = [
            SubmissionGate(first_delegate, enabled=True, ledger_path=ledger, namespace="run-1"),
            SubmissionGate(second_delegate, enabled=True, ledger_path=ledger, namespace="run-1"),
        ]
        results = await asyncio.gather(*(gate.submit("c1", "flag{candidate}") for gate in gates))
        assert sum(result.submitted for result in results) == 1
        assert first_delegate.calls + second_delegate.calls == 1

    asyncio.run(scenario())


def test_dry_run_candidate_can_be_promoted_once(tmp_path):
    async def scenario():
        ledger = tmp_path / "submissions.sqlite"
        dry_delegate = CountingSubmitter()
        dry_gate = SubmissionGate(
            dry_delegate, enabled=False, ledger_path=ledger, namespace="run-1"
        )
        dry_result = await dry_gate.submit("c1", "flag{candidate}")
        assert dry_result.status == "dry_run"
        assert dry_delegate.calls == 0

        live_delegate = CountingSubmitter()
        live_gate = SubmissionGate(
            live_delegate, enabled=True, ledger_path=ledger, namespace="run-1"
        )
        live_result = await live_gate.submit("c1", "flag{candidate}")
        duplicate = await live_gate.submit("c1", "flag{candidate}")
        assert live_result.accepted and live_result.submitted
        assert duplicate.status == "duplicate"
        assert live_delegate.calls == 1

    asyncio.run(scenario())
