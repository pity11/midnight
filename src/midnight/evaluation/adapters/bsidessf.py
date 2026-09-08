"""Adapter for the official BSidesSF CTF 2026 challenge release."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml

from midnight.evaluation.provider import EvaluatorManifest, EvaluatorTask
from midnight.evaluation.stager import BenchmarkStager, StagingSpec, VisibleFile

_CATEGORIES: dict[str, Literal["pwn", "reverse", "web", "crypto", "forensics", "misc"]] = {
    "pwn": "pwn",
    "re": "reverse",
    "rev": "reverse",
    "reverse": "reverse",
    "reversing": "reverse",
    "web": "web",
    "crypto": "crypto",
    "cryptography": "crypto",
    "forensics": "forensics",
    "misc": "misc",
}


class BSidesSFAdapter:
    def __init__(self, repository: str | Path, *, upstream_revision: str):
        self.repository = Path(repository).resolve()
        self.upstream_revision = upstream_revision

    def task_ids(self) -> list[str]:
        return sorted(
            child.name
            for child in self.repository.iterdir()
            if child.is_dir() and (child / "metadata.yml").is_file()
        )

    def _task(self, task_id: str) -> tuple[Path, dict]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", task_id):
            raise ValueError(f"unsafe BSidesSF task ID: {task_id}")
        root = (self.repository / task_id).resolve()
        if not root.is_relative_to(self.repository) or not root.is_dir():
            raise FileNotFoundError(f"BSidesSF task is not materialized: {task_id}")
        metadata = yaml.safe_load((root / "metadata.yml").read_text(encoding="utf-8")) or {}
        if not isinstance(metadata, dict):
            raise TypeError("BSidesSF metadata.yml must be an object")
        return root, metadata

    @staticmethod
    def _category(metadata: dict):
        matches = {
            _CATEGORIES[str(tag).lower()]
            for tag in metadata.get("tags") or []
            if str(tag).lower() in _CATEGORIES
        }
        if len(matches) != 1:
            raise ValueError("BSidesSF task must map to exactly one supported CTF category")
        return matches.pop()

    def staging_spec(
        self,
        task_id: str,
        *,
        target: str | None = None,
        approved_findings: list[str] | None = None,
    ) -> StagingSpec:
        root, metadata = self._task(task_id)
        distfiles = root / "distfiles"
        visible: list[VisibleFile] = []
        if distfiles.is_dir():
            for path in sorted(distfiles.rglob("*")):
                if path.is_symlink():
                    raise ValueError(f"distfile symlink requires review: {path.relative_to(root)}")
                if path.is_file():
                    relative = path.relative_to(root).as_posix()
                    visible.append(
                        VisibleFile(
                            source=relative,
                            target=path.relative_to(distfiles).as_posix(),
                        )
                    )
        has_service = metadata.get("port") is not None
        if has_service and not target:
            raise ValueError(f"server task requires an evaluator target: {task_id}")
        return StagingSpec(
            suite="bsidessf-2026",
            suite_version=self.upstream_revision,
            upstream_revision=self.upstream_revision,
            challenge_id=task_id,
            name=str(metadata.get("name") or task_id),
            description=str(metadata.get("description") or "Find the flag."),
            category=self._category(metadata),
            remote=target,
            internet_policy="target_only" if target else "disabled",
            allowed_targets=[target] if target else [],
            visible_files=visible,
            approved_findings=approved_findings or [],
        )

    def stage_task(self, task_id: str, destination: str | Path, **kwargs):
        root, _ = self._task(task_id)
        return BenchmarkStager(root).stage(self.staging_spec(task_id, **kwargs), destination)

    def evaluator_manifest(self, task_ids: list[str]) -> EvaluatorManifest:
        tasks: dict[str, EvaluatorTask] = {}
        for task_id in task_ids:
            _, metadata = self._task(task_id)
            flag = metadata.get("flag")
            if not flag:
                raise ValueError(f"BSidesSF task has no evaluator flag: {task_id}")
            tasks[task_id] = EvaluatorTask(
                expected_flags=[str(flag)],
                points=int(metadata["value"]) if metadata.get("value") is not None else None,
            )
        return EvaluatorManifest(suite_version=self.upstream_revision, tasks=tasks)
