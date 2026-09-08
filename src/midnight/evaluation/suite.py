"""Versioned benchmark-suite auditing and atomic materialization."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from midnight.evaluation.adapters.cybench import CybenchAdapter
from midnight.evaluation.manifest import canonical_json
from midnight.evaluation.provider import EvaluatorManifest
from midnight.evaluation.stager import ContaminationError, VisibleFile

Category = Literal["pwn", "reverse", "web", "crypto", "forensics", "misc"]


class SuiteTask(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1)
    category: Category
    visible_files: list[VisibleFile] | None = None
    approved_findings: list[str] = Field(default_factory=list)


class CybenchSuiteSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    name: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_.-]+$")
    upstream_revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    expected_category_counts: dict[Category, int]
    tasks: list[SuiteTask] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_inventory(self) -> CybenchSuiteSelection:
        paths = [task.path for task in self.tasks]
        if len(paths) != len(set(paths)):
            raise ValueError("suite task paths must be unique")
        actual = Counter(task.category for task in self.tasks)
        expected = Counter(self.expected_category_counts)
        if actual != expected:
            raise ValueError(f"category counts differ: expected {dict(expected)}, got {dict(actual)}")
        return self


class TaskAudit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    challenge_id: str | None = None
    category: Category
    status: Literal["ready", "blocked", "missing", "unsupported"]
    internet_policy: str | None = None
    attachment_count: int = 0
    finding_ids: list[str] = Field(default_factory=list)
    finding_paths: list[str] = Field(default_factory=list)
    finding_rules: list[str] = Field(default_factory=list)
    approved_finding_ids: list[str] = Field(default_factory=list)
    reason: str | None = None


class SuiteAudit(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
    suite: str
    suite_version: str
    selection: str
    ready: int
    blocked: int
    tasks: list[TaskAudit]

    @property
    def can_stage(self) -> bool:
        return self.ready == len(self.tasks)


def load_cybench_selection(path: str | Path) -> CybenchSuiteSelection:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return CybenchSuiteSelection.model_validate(payload)


class CybenchSuiteBuilder:
    """Audit and stage a pinned Cybench selection without running upstream scripts."""

    def __init__(
        self,
        repository: str | Path,
        selection: CybenchSuiteSelection,
        *,
        verify_revision: bool = True,
    ):
        self.repository = Path(repository).resolve()
        self.selection = selection
        self.verify_revision = verify_revision
        if verify_revision:
            self._verify_revision()
        self.adapter = CybenchAdapter(
            self.repository,
            upstream_revision=selection.upstream_revision,
        )

    def _verify_revision(self) -> None:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.repository,
            check=True,
            capture_output=True,
            text=True,
        )
        actual = result.stdout.strip()
        if actual != self.selection.upstream_revision:
            raise ValueError(
                "upstream revision differs from selection: "
                f"expected {self.selection.upstream_revision}, got {actual}"
            )

    def _verify_file(self, path: Path) -> None:
        relative = path.relative_to(self.repository).as_posix()
        expected = subprocess.run(
            ["git", "rev-parse", f"HEAD:{relative}"],
            cwd=self.repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        actual = subprocess.run(
            ["git", "hash-object", str(path)],
            cwd=self.repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if actual != expected:
            raise ValueError(f"upstream file differs from pinned revision: {relative}")

    def _verify_task_files(self, task: SuiteTask, visible_files: list[VisibleFile]) -> None:
        if not self.verify_revision:
            return
        root = (self.repository / task.path).resolve()
        controls = [root / "metadata" / "metadata.json"]
        if task.visible_files is None:
            controls.append(root / "init_script.sh")
        for path in [*controls, *(root / item.source for item in visible_files)]:
            self._verify_file(path)

    @staticmethod
    def _files(task: SuiteTask) -> list[VisibleFile] | None:
        return task.visible_files

    def _audit_task(self, task: SuiteTask, scratch: Path) -> TaskAudit:
        try:
            spec = self.adapter.staging_spec(
                task.path,
                approved_findings=task.approved_findings,
                visible_files=self._files(task),
            )
            if spec.category != task.category:
                return TaskAudit(
                    path=task.path,
                    category=task.category,
                    status="unsupported",
                    reason=f"declared category {task.category} differs from upstream {spec.category}",
                )
            self._verify_task_files(task, spec.visible_files)
            self.adapter.stage_task(
                task.path,
                scratch / spec.challenge_id,
                approved_findings=task.approved_findings,
                visible_files=self._files(task),
            )
            self.adapter.evaluator_task(task.path)
            return TaskAudit(
                path=task.path,
                challenge_id=spec.challenge_id,
                category=task.category,
                status="ready",
                internet_policy=spec.internet_policy,
                attachment_count=len(spec.visible_files),
                approved_finding_ids=task.approved_findings,
            )
        except ContaminationError as exc:
            return TaskAudit(
                path=task.path,
                category=task.category,
                status="blocked",
                finding_ids=[item.finding_id for item in exc.findings],
                finding_paths=sorted({item.path for item in exc.findings}),
                finding_rules=sorted({item.rule for item in exc.findings}),
                reason="unapproved contamination findings",
            )
        except FileNotFoundError as exc:
            return TaskAudit(
                path=task.path,
                category=task.category,
                status="missing",
                reason=str(exc),
            )
        except (subprocess.CalledProcessError, TypeError, ValueError) as exc:
            return TaskAudit(
                path=task.path,
                category=task.category,
                status="unsupported",
                reason=str(exc),
            )

    def audit(self) -> SuiteAudit:
        with tempfile.TemporaryDirectory(prefix="midnight-suite-audit-") as temporary:
            scratch = Path(temporary)
            tasks = [self._audit_task(task, scratch) for task in self.selection.tasks]
        ready = sum(task.status == "ready" for task in tasks)
        return SuiteAudit(
            suite="cybench",
            suite_version=self.selection.upstream_revision,
            selection=self.selection.name,
            ready=ready,
            blocked=len(tasks) - ready,
            tasks=tasks,
        )

    def stage(self, bundles: str | Path, evaluator_manifest: str | Path) -> SuiteAudit:
        output = Path(bundles).resolve()
        evaluator = Path(evaluator_manifest).resolve()
        if output.exists():
            raise FileExistsError(f"suite bundle destination already exists: {output}")
        if evaluator.exists():
            raise FileExistsError(f"evaluator manifest already exists: {evaluator}")
        if evaluator == output or evaluator.is_relative_to(output):
            raise ValueError("evaluator manifest must be outside the agent-visible bundle tree")

        audit = self.audit()
        if not audit.can_stage:
            raise ValueError("suite audit did not pass; inspect the compatibility report")

        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
        try:
            for task in self.selection.tasks:
                spec = self.adapter.staging_spec(
                    task.path,
                    approved_findings=task.approved_findings,
                    visible_files=self._files(task),
                )
                self._verify_task_files(task, spec.visible_files)
                self.adapter.stage_task(
                    task.path,
                    temporary / spec.challenge_id,
                    approved_findings=task.approved_findings,
                    visible_files=self._files(task),
                )
            temporary.replace(output)

            private = self.adapter.evaluator_manifest([task.path for task in self.selection.tasks])
            self._write_private_manifest(private, evaluator)
            return audit
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            if output.exists() and not evaluator.exists():
                shutil.rmtree(output, ignore_errors=True)
            raise

    @staticmethod
    def _write_private_manifest(manifest: EvaluatorManifest, target: Path) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
        temporary = Path(name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(canonical_json(manifest) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            temporary.chmod(0o600)
            temporary.replace(target)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
