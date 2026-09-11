"""Evaluator-side adapter for the public LilCTF 2025 challenge release."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Literal

import yaml

from midnight.evaluation.provider import EvaluatorManifest, EvaluatorTask
from midnight.evaluation.stager import BenchmarkStager, StagingSpec, VisibleFile

Category = Literal["pwn", "reverse", "web", "crypto", "forensics", "misc"]

_CATEGORIES: dict[str, Category] = {
    "pwn": "pwn",
    "reverse": "reverse",
    "re": "reverse",
    "web": "web",
    "crypto": "crypto",
    "misc": "misc",
    "forensics": "forensics",
}


class LilCTF2025Adapter:
    """Stage only organizer-declared player attachments from LilCTF 2025.

    Challenge YAML, build contexts, README files, write-ups, and repository
    history stay evaluator-side. A target must be supplied explicitly for any
    task whose YAML declares a container.
    """

    def __init__(self, repository: str | Path, *, upstream_revision: str):
        self.repository = Path(repository).resolve()
        self.upstream_revision = upstream_revision
        self.challenges = self.repository / "challenges"
        if not self.challenges.is_dir():
            raise FileNotFoundError("LilCTF challenges directory is not materialized")

    def task_ids(self) -> list[str]:
        return sorted(path.parent.name for path in self.challenges.glob("*/challenge.yaml"))

    def _task(self, task_id: str) -> tuple[Path, dict]:
        root = (self.challenges / task_id).resolve()
        if not root.is_relative_to(self.challenges) or not root.is_dir():
            raise KeyError(f"unknown LilCTF task: {task_id}")
        payload = yaml.safe_load((root / "challenge.yaml").read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("LilCTF challenge.yaml must be an object")
        return root, payload

    @staticmethod
    def _description(root: Path) -> str:
        readme = root / "README.md"
        if not readme.is_file():
            return "Find the flag from the supplied challenge material."
        text = readme.read_text(encoding="utf-8", errors="replace")
        marker = "## 题目描述"
        if marker in text:
            text = text.split(marker, 1)[1].strip()
        return text.strip() or "Find the flag from the supplied challenge material."

    @staticmethod
    def _category(payload: dict) -> Category:
        info = payload.get("info")
        if not isinstance(info, dict):
            raise TypeError("LilCTF info must be an object")
        raw = str(info.get("category") or "").strip().lower()
        try:
            return _CATEGORIES[raw]
        except KeyError as exc:
            raise ValueError(f"unsupported LilCTF category: {raw}") from exc

    def staging_spec(
        self,
        task_id: str,
        *,
        target: str | None = None,
        approved_findings: list[str] | None = None,
        visible_files: list[VisibleFile] | None = None,
    ) -> StagingSpec:
        root, payload = self._task(task_id)
        info = payload.get("info")
        assert isinstance(info, dict)
        declared = payload.get("attachments") or []
        if not isinstance(declared, list) or any(not isinstance(item, str) for item in declared):
            raise TypeError("LilCTF attachments must be a list of paths")
        visible = visible_files or [
            VisibleFile(
                source=(PurePosixPath("attachment") / item).as_posix(),
                target=PurePosixPath(item).name,
            )
            for item in declared
        ]
        is_remote = bool(payload.get("container"))
        if is_remote and not target:
            raise ValueError(f"remote LilCTF task requires an evaluator target: {task_id}")
        if not is_remote and target:
            raise ValueError(f"static LilCTF task cannot declare a target: {task_id}")
        return StagingSpec(
            suite="lilctf-2025",
            suite_version=self.upstream_revision,
            upstream_revision=self.upstream_revision,
            challenge_id=task_id,
            name=str(info.get("name") or task_id),
            description=self._description(root),
            category=self._category(payload),
            remote=target,
            flag_format="LILCTF prefix with a braced payload",
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
            _, payload = self._task(task_id)
            flag = payload.get("flag")
            if not isinstance(flag, dict) or not flag.get("content"):
                raise ValueError(f"LilCTF task has no static evaluator flag: {task_id}")
            score = payload.get("score")
            points = None
            if isinstance(score, dict) and score.get("actual_score") is not None:
                points = int(score["actual_score"])
            tasks[task_id] = EvaluatorTask(
                expected_flags=[str(flag["content"])],
                points=points,
            )
        return EvaluatorManifest(suite_version=self.upstream_revision, tasks=tasks)
