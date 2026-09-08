"""Local mock implementations of the two-end interfaces.

LocalDirProvider reads challenges from a directory of fixtures; ManualSubmitter
checks the submitted flag against an ``expected_flag`` recorded in task.json.

Fixture layout (Cybench-style three elements):

    <root>/<challenge_id>/
        task.json        # {id, name, description, remote?, category_hint?,
                         #  flag_format?, expected_flag}
        files/           # starter files (optional)
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from midnight.interfaces.submitter import SubmitResult
from midnight.state import Challenge


class LocalDirProvider:
    """ChallengeProvider backed by a local fixtures directory."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _task_json(self, challenge_id: str) -> dict:
        path = self.root / challenge_id / "task.json"
        if not path.exists():
            raise FileNotFoundError(f"task.json not found for '{challenge_id}': {path}")
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

    async def list_challenges(self) -> list[Challenge]:
        result: list[Challenge] = []
        if not self.root.exists():
            return result
        for child in sorted(self.root.iterdir()):
            if child.is_dir() and (child / "task.json").exists():
                result.append(await self.fetch(child.name))
        return result

    async def fetch(self, challenge_id: str) -> Challenge:
        meta = self._task_json(challenge_id)
        files_dir = self.root / challenge_id / "files"
        files = (
            [str(p) for p in sorted(files_dir.iterdir()) if p.is_file()]
            if files_dir.exists()
            else []
        )
        return Challenge(
            id=meta.get("id", challenge_id),
            name=meta.get("name", challenge_id),
            description=meta.get("description", ""),
            files=files,
            remote=meta.get("remote"),
            category_hint=meta.get("category_hint"),
            flag_format=meta.get("flag_format"),
        )

    async def download_files(self, challenge_id: str, dest: str) -> list[str]:
        files_dir = self.root / challenge_id / "files"
        dest_path = Path(dest)
        dest_path.mkdir(parents=True, exist_ok=True)
        out: list[str] = []
        if files_dir.exists():
            for p in sorted(files_dir.iterdir()):
                if p.is_file():
                    target = dest_path / p.name
                    shutil.copy2(p, target)
                    out.append(str(target))
        return out


class ManualSubmitter:
    """FlagSubmitter that compares against expected_flag in fixtures.

    Falls back to 'accepted, unverified' when no expected flag is recorded,
    which is useful when running against real challenges without an oracle.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def _expected(self, challenge_id: str) -> str | None:
        path = self.root / challenge_id / "task.json"
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as f:
            return json.load(f).get("expected_flag")

    async def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        expected = self._expected(challenge_id)
        if expected is None:
            return SubmitResult(accepted=True, message="submitted (no oracle to verify)")
        if flag.strip() == expected.strip():
            return SubmitResult(accepted=True, message="correct flag", points=None)
        return SubmitResult(accepted=False, message="incorrect flag")
