"""ChallengeProvider: the 'fetch challenge' end (reserved interface).

Implement this per competition via a skill/MCP. v1 uses LocalDirProvider.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from midnight.state import Challenge


@runtime_checkable
class ChallengeProvider(Protocol):
    """Fetches challenge metadata and starter files from some source."""

    async def list_challenges(self) -> list[Challenge]:
        """Enumerate available challenges (metadata only)."""
        ...

    async def fetch(self, challenge_id: str) -> Challenge:
        """Fetch a single challenge: description + remote + downloaded files."""
        ...

    async def download_files(self, challenge_id: str, dest: str) -> list[str]:
        """Download starter files to ``dest``, returning local file paths."""
        ...
