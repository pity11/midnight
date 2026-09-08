"""Two-end reserved interfaces: ChallengeProvider and FlagSubmitter.

These are the seams where per-competition skills/MCP plug in later. v1 ships a
local-directory mock so the full pipeline can run offline.
"""

from midnight.interfaces.provider import ChallengeProvider
from midnight.interfaces.submitter import FlagSubmitter, SubmitResult
from midnight.interfaces.local_mock import LocalDirProvider, ManualSubmitter

__all__ = [
    "ChallengeProvider",
    "FlagSubmitter",
    "SubmitResult",
    "LocalDirProvider",
    "ManualSubmitter",
]
