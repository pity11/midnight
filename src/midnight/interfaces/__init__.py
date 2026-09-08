"""Two-end reserved interfaces: ChallengeProvider and FlagSubmitter.

These are the seams where per-competition skills/MCP plug in later. v1 ships a
local-directory mock so the full pipeline can run offline.
"""

from midnight.interfaces.http_platform import HTTPPlatformAdapter, HTTPPlatformConfig
from midnight.interfaces.local_mock import LocalDirProvider, ManualSubmitter
from midnight.interfaces.provider import ChallengeProvider
from midnight.interfaces.submission_gate import SubmissionGate
from midnight.interfaces.submitter import FlagSubmitter, SubmitResult

__all__ = [
    "ChallengeProvider",
    "FlagSubmitter",
    "HTTPPlatformAdapter",
    "HTTPPlatformConfig",
    "LocalDirProvider",
    "ManualSubmitter",
    "SubmissionGate",
    "SubmitResult",
]
