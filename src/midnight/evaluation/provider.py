"""Runtime interfaces for clean bundles and evaluator-only answer manifests."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from midnight.evaluation.manifest import BundleManifest, sha256_tree
from midnight.evaluation.stager import MANIFEST_NAME
from midnight.interfaces.submitter import SubmitResult
from midnight.state import Challenge

_FORBIDDEN_TASK_KEYS = {"expected_flag", "expected_flags", "solution", "writeup", "grader"}


def _read_json(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"JSON document must be an object: {path}")
    return payload


class ValidatedBundleProvider:
    """Expose only immutable, stager-produced, agent-visible task bundles."""

    def __init__(self, root: str | Path, *, target_networks: dict[str, str] | None = None):
        self.root = Path(root).resolve()
        self.target_networks = target_networks or {}

    def _bundle_root(self, challenge_id: str) -> Path:
        candidate = (self.root / challenge_id).resolve()
        if not candidate.is_relative_to(self.root) or not candidate.is_dir():
            raise FileNotFoundError(f"clean bundle not found: {challenge_id}")
        return candidate

    def _validate(self, challenge_id: str) -> tuple[Path, BundleManifest, dict]:
        root = self._bundle_root(challenge_id)
        manifest = BundleManifest.model_validate(_read_json(root / MANIFEST_NAME))
        if manifest.challenge_id != challenge_id:
            raise ValueError("bundle directory and manifest challenge IDs differ")
        actual_hash = sha256_tree(root, excluded={MANIFEST_NAME})
        if actual_hash != manifest.bundle_sha256:
            raise ValueError(f"bundle hash mismatch for {challenge_id}")

        actual_files = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and path.name != MANIFEST_NAME
        }
        if actual_files != set(manifest.agent_visible):
            raise ValueError(f"bundle file inventory mismatch for {challenge_id}")
        if "task.json" not in actual_files:
            raise ValueError("bundle does not expose task.json")

        task = _read_json(root / "task.json")
        forbidden = _FORBIDDEN_TASK_KEYS.intersection(task)
        if forbidden:
            raise ValueError(f"agent-visible task metadata contains forbidden keys: {sorted(forbidden)}")
        if str(task.get("id")) != challenge_id:
            raise ValueError("task and manifest challenge IDs differ")
        return root, manifest, task

    async def list_challenges(self) -> list[Challenge]:
        if not self.root.exists():
            return []
        challenge_ids = sorted(
            child.name
            for child in self.root.iterdir()
            if child.is_dir() and (child / MANIFEST_NAME).is_file()
        )
        return [await self.fetch(challenge_id) for challenge_id in challenge_ids]

    async def fetch(self, challenge_id: str) -> Challenge:
        root, manifest, task = self._validate(challenge_id)
        files = [
            str(root / relative)
            for relative in manifest.agent_visible
            if relative.startswith("files/")
        ]
        file_destinations = {
            str(root / relative): Path(relative).relative_to("files").as_posix()
            for relative in manifest.agent_visible
            if relative.startswith("files/")
        }
        return Challenge(
            id=challenge_id,
            name=str(task.get("name") or challenge_id),
            description=str(task.get("description") or ""),
            files=files,
            file_destinations=file_destinations,
            remote=task.get("remote"),
            category_hint=manifest.category,
            category_hint_trusted=True,
            flag_format=task.get("flag_format"),
            round_id=manifest.suite_version,
            source_hash=manifest.bundle_sha256,
            file_hashes={},
            internet_policy=manifest.internet_policy,
            allowed_targets=manifest.allowed_targets,
            target_network=self.target_networks.get(challenge_id),
        )

    def bundle_manifest(self, challenge_id: str) -> BundleManifest:
        """Return a freshly validated public manifest."""
        _, manifest, _ = self._validate(challenge_id)
        return manifest

    async def download_files(self, challenge_id: str, dest: str) -> list[str]:
        root, manifest, _ = self._validate(challenge_id)
        destination = Path(dest)
        destination.mkdir(parents=True, exist_ok=True)
        copied: list[str] = []
        for relative in manifest.agent_visible:
            if not relative.startswith("files/"):
                continue
            source = root / relative
            target = destination / Path(relative).relative_to("files")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            copied.append(str(target))
        return copied


class EvaluatorTask(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    expected_flags: list[str] = Field(min_length=1)
    points: int | None = None


class EvaluatorManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = Field(default=1, ge=1, le=1)
    suite_version: str
    tasks: dict[str, EvaluatorTask]


class EvaluatorManifestSubmitter:
    """Oracle kept outside clean bundles and solver containers."""

    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()
        self.manifest = EvaluatorManifest.model_validate(_read_json(self.path))

    async def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        task = self.manifest.tasks.get(challenge_id)
        if task is None:
            return SubmitResult(accepted=False, message="unknown evaluator task")
        accepted = flag.strip() in {expected.strip() for expected in task.expected_flags}
        return SubmitResult(
            accepted=accepted,
            message="correct flag" if accepted else "incorrect flag",
            points=task.points if accepted else None,
            status="accepted" if accepted else "rejected",
        )
