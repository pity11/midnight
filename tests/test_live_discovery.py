from __future__ import annotations

from midnight.app import _list_challenges_with_wait, _parse_args


class SequencedProvider:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    async def list_challenges(self):
        index = min(self.calls, len(self.responses) - 1)
        self.calls += 1
        response = self.responses[index]
        if isinstance(response, Exception):
            raise response
        return response


def test_wait_for_challenges_argument_defaults_to_disabled():
    assert _parse_args([]).wait_for_challenges == 0
    assert _parse_args(["--wait-for-challenges", "300"]).wait_for_challenges == 300
    assert _parse_args(["--include-solved"]).include_solved


async def test_live_discovery_polls_until_a_challenge_appears():
    challenge = {"id": "published-late"}
    provider = SequencedProvider([[], [], [challenge]])

    discovered = await _list_challenges_with_wait(
        provider,
        wait_seconds=1,
        poll_interval=0,
    )

    assert discovered == [challenge]
    assert provider.calls == 3


async def test_live_discovery_does_not_poll_when_wait_is_disabled():
    provider = SequencedProvider([[], [{"id": "later"}]])

    discovered = await _list_challenges_with_wait(
        provider,
        wait_seconds=0,
        poll_interval=0,
    )

    assert discovered == []
    assert provider.calls == 1


async def test_live_discovery_retries_a_transient_platform_error():
    challenge = {"id": "after-network-recovery"}
    provider = SequencedProvider([OSError("temporary DNS failure"), [challenge]])

    discovered = await _list_challenges_with_wait(
        provider,
        wait_seconds=1,
        poll_interval=0,
    )

    assert discovered == [challenge]
    assert provider.calls == 2
