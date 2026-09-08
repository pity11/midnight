"""Cybench-to-Midnight staging adapter.

This module reads answer-bearing Cybench metadata only in the evaluator process.
It never executes upstream initialization scripts. Player-visible attachments
are derived from a deliberately narrow parser for plain ``cp FILE $TMP_DIR``
commands; unfamiliar scripts require an explicit reviewed override.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Literal

from midnight.evaluation.provider import EvaluatorManifest, EvaluatorTask
from midnight.evaluation.stager import BenchmarkStager, StagingSpec, VisibleFile

_COPY_LINE = re.compile(
    r"^\s*cp\s+['\"]?(?P<source>[^'\"\s;$|&]+)['\"]?\s+"
    r"['\"]?\$(?:TMP_DIR|1)(?:/(?P<target>[^'\"\s;$|&]+))?['\"]?\s*$"
)
_CATEGORY_MAP: dict[
    str, Literal["pwn", "reverse", "web", "crypto", "forensics", "misc"]
] = {
    "crypto": "crypto",
    "forensics": "forensics",
    "misc": "misc",
    "pwn": "pwn",
    "reverse": "reverse",
    "reversing": "reverse",
    "web": "web",
}


class UnsupportedCybenchTask(ValueError):
    pass


def _stable_id(task_path: str) -> str:
    name = PurePosixPath(task_path).name.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", name).strip("-")[:48] or "task"
    suffix = hashlib.sha256(task_path.encode("utf-8")).hexdigest()[:8]
    return f"{slug}-{suffix}"


def _parse_visible_files(script: str) -> list[VisibleFile]:
    files: list[VisibleFile] = []
    suspicious_copy_lines: list[str] = []
    for raw in script.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not re.match(r"^cp(?:\s|$)", line):
            continue
        match = _COPY_LINE.fullmatch(line)
        if not match:
            suspicious_copy_lines.append(line)
            continue
        source = PurePosixPath(match.group("source"))
        if source.is_absolute() or ".." in source.parts:
            suspicious_copy_lines.append(line)
            continue
        lowered = {part.lower() for part in source.parts}
        if lowered.intersection({"metadata", "solution", "writeup", "solver"}):
            suspicious_copy_lines.append(line)
            continue
        target = match.group("target") or source.name
        files.append(VisibleFile(source=source.as_posix(), target=target))
    if suspicious_copy_lines:
        raise UnsupportedCybenchTask(
            "initialization script contains copy commands requiring review: "
            + "; ".join(suspicious_copy_lines)
        )
    targets = [item.target for item in files]
    if len(targets) != len(set(targets)):
        raise UnsupportedCybenchTask("initialization script produces duplicate attachment names")
    return files


class CybenchAdapter:
    def __init__(self, repository: str | Path, *, upstream_revision: str):
        self.repository = Path(repository).resolve()
        self.upstream_revision = upstream_revision

    def task_paths(self) -> list[str]:
        return [
            line.strip()
            for line in (self.repository / "task_list.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

    def _task_root(self, task_path: str) -> Path:
        root = (self.repository / task_path).resolve()
        if not root.is_relative_to(self.repository) or not root.is_dir():
            raise FileNotFoundError(f"Cybench task is not materialized: {task_path}")
        return root

    def _metadata(self, root: Path) -> dict:
        payload = json.loads((root / "metadata" / "metadata.json").read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("Cybench metadata must be an object")
        return payload

    def staging_spec(
        self,
        task_path: str,
        *,
        approved_findings: list[str] | None = None,
        visible_files: list[VisibleFile] | None = None,
    ) -> StagingSpec:
        root = self._task_root(task_path)
        metadata = self._metadata(root)
        categories = metadata.get("categories") or []
        if len(categories) != 1 or str(categories[0]).lower() not in _CATEGORY_MAP:
            raise UnsupportedCybenchTask("task is mixed-category or outside Midnight's six categories")
        category = _CATEGORY_MAP[str(categories[0]).lower()]
        if visible_files is None:
            script = (root / "init_script.sh").read_text(encoding="utf-8")
            visible_files = _parse_visible_files(script)
        target = str(metadata.get("target_host") or "").strip()
        if not visible_files and not target:
            raise UnsupportedCybenchTask("task exposes neither reviewed files nor a target")
        return StagingSpec(
            suite="cybench",
            suite_version=self.upstream_revision,
            upstream_revision=self.upstream_revision,
            challenge_id=_stable_id(task_path),
            name=PurePosixPath(task_path).name,
            description=str(metadata.get("hard_prompt") or "Find the flag."),
            category=category,
            remote=target or None,
            internet_policy="target_only" if target else "disabled",
            allowed_targets=[target] if target else [],
            visible_files=visible_files,
            approved_findings=approved_findings or [],
        )

    def stage_task(
        self,
        task_path: str,
        destination: str | Path,
        *,
        approved_findings: list[str] | None = None,
        visible_files: list[VisibleFile] | None = None,
    ):
        root = self._task_root(task_path)
        spec = self.staging_spec(
            task_path,
            approved_findings=approved_findings,
            visible_files=visible_files,
        )
        return BenchmarkStager(root).stage(spec, destination)

    def evaluator_task(self, task_path: str) -> tuple[str, EvaluatorTask]:
        root = self._task_root(task_path)
        metadata = self._metadata(root)
        subtasks = metadata.get("subtasks") or []
        if not subtasks or not isinstance(subtasks[-1], dict) or not subtasks[-1].get("answer"):
            raise ValueError("Cybench task has no final evaluator answer")
        return _stable_id(task_path), EvaluatorTask(expected_flags=[str(subtasks[-1]["answer"])])

    def evaluator_manifest(self, task_paths: list[str]) -> EvaluatorManifest:
        return EvaluatorManifest(
            suite_version=self.upstream_revision,
            tasks=dict(self.evaluator_task(path) for path in task_paths),
        )
