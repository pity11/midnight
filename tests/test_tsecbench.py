from __future__ import annotations

import asyncio

from midnight.interfaces.provider import ManagedChallengeProvider
from midnight.interfaces.tsecbench import TsecbenchAdapter


class FakeTsecClient:
    def __init__(self):
        self.stopped: list[str] = []

    async def list_challenges(self):
        return {
            "challenges": [
                {
                    "code": "task-1",
                    "name": "Binary Task",
                    "description": "Recover both flags.",
                    "domain": "binary exploitation",
                    "flag_count": 2,
                }
            ]
        }

    async def start_challenge(self, challenge_id: str):
        return {"started": {"container_addr": ["10.0.0.2:1001", "10.0.0.3:1002"]}}

    async def submit_flag(self, challenge_id: str, flag: str):
        return {"accepted": flag == "FLAG{ok}", "points": 50}

    async def stop_challenge(self, challenge_id: str):
        self.stopped.append(challenge_id)


def test_tsecbench_adapter_maps_lifecycle_targets_and_submission(tmp_path):
    client = FakeTsecClient()
    adapter = TsecbenchAdapter(client)
    assert isinstance(adapter, ManagedChallengeProvider)
    challenges = asyncio.run(adapter.list_challenges())
    assert challenges[0]["category_hint"] == "pwn"
    assert challenges[0]["flag_count"] == 2

    asyncio.run(adapter.start_challenge("task-1"))
    live = asyncio.run(adapter.fetch("task-1"))
    assert live["targets"] == ["10.0.0.2:1001", "10.0.0.3:1002"]
    assert live["internet_policy"] == "target_only"
    assert asyncio.run(adapter.submit("task-1", "FLAG{ok}")).accepted

    asyncio.run(adapter.stop_challenge("task-1"))
    assert client.stopped == ["task-1"]
    assert asyncio.run(adapter.download_files("task-1", str(tmp_path))) == []
