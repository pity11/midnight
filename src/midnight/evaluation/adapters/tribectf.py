"""Adapter for the public TribeCTF 2025 NYU-agent-format release."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Literal

from midnight.evaluation.provider import EvaluatorManifest, EvaluatorTask
from midnight.evaluation.stager import BenchmarkStager, StagingSpec, VisibleFile

_CATEGORIES: dict[str, Literal["pwn", "reverse", "web", "crypto", "forensics", "misc"]] = {
    "pwn": "pwn",
    "rev": "reverse",
    "reverse": "reverse",
    "web": "web",
    "crypto": "crypto",
    "forensics": "forensics",
    "misc": "misc",
}


def _challenge_id(task_id: str) -> str:
    return task_id.replace(",", "").replace("!", "")


class TribeCTFAdapter:
    def __init__(self, repository: str | Path, *, upstream_revision: str):
        self.repository = Path(repository).resolve()
        self.upstream_revision = upstream_revision
        payload = json.loads((self.repository / "competition25.json").read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("competition25.json must be an object")
        self.index: dict[str, dict] = payload

    def task_ids(self) -> list[str]:
        return sorted(self.index)

    def _task(self, task_id: str) -> tuple[Path, dict, dict]:
        entry = self.index.get(task_id)
        if not isinstance(entry, dict):
            raise KeyError(f"unknown TribeCTF task: {task_id}")
        root = (self.repository / str(entry["path"])).resolve()
        if not root.is_relative_to(self.repository) or not root.is_dir():
            raise FileNotFoundError(f"TribeCTF task is not materialized: {task_id}")
        metadata = json.loads((root / "challenge.json").read_text(encoding="utf-8"))
        if not isinstance(metadata, dict):
            raise TypeError("TribeCTF challenge.json must be an object")
        return root, entry, metadata

    def staging_spec(
        self,
        task_id: str,
        *,
        target: str | None = None,
        approved_findings: list[str] | None = None,
    ) -> StagingSpec:
        _, entry, metadata = self._task(task_id)
        raw_category = str(metadata.get("category") or entry.get("category") or "").lower()
        if raw_category not in _CATEGORIES:
            raise ValueError(f"unsupported TribeCTF category: {raw_category}")
        declared = metadata.get("files") or []
        if not isinstance(declared, list):
            raise TypeError("TribeCTF files must be a list")
        visible = [
            VisibleFile(source=str(path), target=PurePosixPath(str(path)).name)
            for path in declared
        ]
        task_type = str(metadata.get("type") or "static").lower()
        if task_type != "static" and not target:
            raise ValueError(f"remote TribeCTF task requires an evaluator target: {task_id}")
        return StagingSpec(
            suite="tribectf-2025",
            suite_version=self.upstream_revision,
            upstream_revision=self.upstream_revision,
            challenge_id=_challenge_id(task_id),
            name=str(metadata.get("name") or entry.get("challenge") or task_id),
            description=str(metadata.get("description") or "Find the flag."),
            category=_CATEGORIES[raw_category],
            remote=target,
            internet_policy="target_only" if target else "disabled",
            allowed_targets=[target] if target else [],
            visible_files=visible,
            approved_findings=approved_findings or [],
        )

    def stage_task(self, task_id: str, destination: str | Path, **kwargs):
        root, _, _ = self._task(task_id)
        return BenchmarkStager(root).stage(self.staging_spec(task_id, **kwargs), destination)

    def evaluator_manifest(self, task_ids: list[str]) -> EvaluatorManifest:
        tasks: dict[str, EvaluatorTask] = {}
        for task_id in task_ids:
            _, _, metadata = self._task(task_id)
            flag = metadata.get("flag")
            if not flag:
                raise ValueError(f"TribeCTF task has no evaluator flag: {task_id}")
            tasks[_challenge_id(task_id)] = EvaluatorTask(
                expected_flags=[str(flag)],
                points=int(metadata["points"]) if metadata.get("points") is not None else None,
            )
        return EvaluatorManifest(suite_version=self.upstream_revision, tasks=tasks)
