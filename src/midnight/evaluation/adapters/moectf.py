"""Evaluator-side adapter for static MoeCTF 2025 Misc/forensics tasks."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Literal

from midnight.evaluation.provider import EvaluatorManifest, EvaluatorTask
from midnight.evaluation.stager import BenchmarkStager, StagingSpec, VisibleFile

Category = Literal["pwn", "reverse", "web", "crypto", "forensics", "misc"]
_FLAG = re.compile(r"(?i)\b(?:moectf|flag)\{[^}\r\n]+\}")


class MoeCTF2025MiscAdapter:
    """Stage selected static artifacts while keeping the official write-up private."""

    def __init__(self, repository: str | Path, *, upstream_revision: str):
        self.repository = Path(repository).resolve()
        self.upstream_revision = upstream_revision
        self.challenges = self.repository / "challenges" / "Misc"
        self.writeup = self.repository / "official_writeups" / "Misc" / "Writeup.md"
        if not self.challenges.is_dir() or not self.writeup.is_file():
            raise FileNotFoundError("MoeCTF Misc challenges or official write-up are unavailable")

    def _task(self, task_id: str) -> Path:
        root = (self.challenges / task_id).resolve()
        if not root.is_relative_to(self.challenges) or not root.is_dir():
            raise KeyError(f"unknown MoeCTF Misc task: {task_id}")
        return root

    @staticmethod
    def _description(root: Path) -> str:
        readme = root / "README.md"
        if not readme.is_file():
            return "Analyze the supplied artifact and recover the flag."
        text = readme.read_text(encoding="utf-8", errors="replace").strip()
        return text or "Analyze the supplied artifact and recover the flag."

    def _answer(self, task_id: str) -> str:
        text = self.writeup.read_text(encoding="utf-8", errors="replace")
        heading = re.compile(
            rf"(?ms)^#\s+{re.escape(task_id)}\s*$\n(.*?)(?=^#\s+|\Z)"
        )
        match = heading.search(text)
        if not match:
            raise ValueError(f"official write-up has no top-level section for {task_id}")
        flags = list(dict.fromkeys(_FLAG.findall(match.group(1))))
        if len(flags) != 1:
            raise ValueError(f"official write-up must contain exactly one flag for {task_id}")
        return flags[0]

    def staging_spec(
        self,
        task_id: str,
        *,
        category: Category = "forensics",
        approved_findings: list[str] | None = None,
    ) -> StagingSpec:
        root = self._task(task_id)
        files = [path for path in sorted(root.iterdir()) if path.is_file() and path.name != "README.md"]
        if not files:
            raise ValueError(f"MoeCTF task has no player artifact: {task_id}")
        return StagingSpec(
            suite="moectf-2025",
            suite_version=self.upstream_revision,
            upstream_revision=self.upstream_revision,
            challenge_id=re.sub(r"[^A-Za-z0-9_.-]+", "-", task_id).strip("-").lower(),
            name=task_id,
            description=self._description(root),
            category=category,
            flag_format=r"(?i)moectf\{[^}\r\n]+\}",
            visible_files=[
                VisibleFile(source=path.name, target=PurePosixPath(path.name).name) for path in files
            ],
            approved_findings=approved_findings or [],
        )

    def stage_task(self, task_id: str, destination: str | Path, **kwargs):
        root = self._task(task_id)
        return BenchmarkStager(root).stage(self.staging_spec(task_id, **kwargs), destination)

    def evaluator_manifest(self, task_ids: list[str]) -> EvaluatorManifest:
        tasks = {}
        for task_id in task_ids:
            spec = self.staging_spec(task_id)
            tasks[spec.challenge_id] = EvaluatorTask(expected_flags=[self._answer(task_id)])
        return EvaluatorManifest(suite_version=self.upstream_revision, tasks=tasks)
