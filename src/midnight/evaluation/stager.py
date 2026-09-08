"""Allowlist-based conversion from upstream challenges to clean Midnight bundles."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from midnight.evaluation.manifest import BundleManifest, canonical_json, sha256_tree
from midnight.evaluation.scanner import Finding, scan_bundle

MANIFEST_NAME = "bundle.manifest.json"


class VisibleFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source: str
    target: str

    @field_validator("source", "target")
    @classmethod
    def relative_path_only(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or not value or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("visible file paths must be normalized relative paths")
        return path.as_posix()


class StagingSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    suite: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    upstream_revision: str = Field(min_length=1)
    challenge_id: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1)
    description: str
    category: Literal["pwn", "reverse", "web", "crypto", "forensics", "misc"]
    remote: str | None = None
    flag_format: str | None = None
    internet_policy: Literal["disabled", "target_only", "open_world"] = "disabled"
    allowed_targets: list[str] = Field(default_factory=list)
    visible_files: list[VisibleFile] = Field(default_factory=list)
    contamination_patterns: list[str] = Field(default_factory=list)
    approved_findings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def targets_match_policy(self) -> StagingSpec:
        if self.internet_policy == "disabled" and self.allowed_targets:
            raise ValueError("disabled internet policy cannot declare allowed targets")
        if self.remote and self.remote not in self.allowed_targets:
            raise ValueError("remote must be present in allowed_targets")
        targets = [item.target for item in self.visible_files]
        if len(targets) != len(set(targets)):
            raise ValueError("visible file targets must be unique")
        return self


class ContaminationError(ValueError):
    def __init__(self, findings: list[Finding]):
        self.findings = findings
        summary = ", ".join(f"{item.finding_id}:{item.path}:{item.rule}" for item in findings)
        super().__init__(f"unapproved contamination findings: {summary}")


class BenchmarkStager:
    def __init__(self, source_root: str | Path):
        self.source_root = Path(source_root).resolve()
        if not self.source_root.is_dir():
            raise ValueError(f"source root is not a directory: {self.source_root}")

    def _source(self, relative: str) -> Path:
        candidate = self.source_root / relative
        if candidate.is_symlink():
            raise ValueError(f"symlink sources are not allowed: {relative}")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(self.source_root) or not resolved.is_file():
            raise ValueError(f"source must be a regular file inside source root: {relative}")
        return resolved

    def stage(self, spec: StagingSpec, destination: str | Path) -> BundleManifest:
        target = Path(destination)
        if target.exists():
            raise FileExistsError(f"bundle destination already exists: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{target.name}.", dir=target.parent))
        try:
            task = {
                "id": spec.challenge_id,
                "name": spec.name,
                "description": spec.description,
                "remote": spec.remote,
                "category_hint": spec.category,
                "flag_format": spec.flag_format,
                "round_id": spec.suite_version,
            }
            (temporary / "task.json").write_bytes(canonical_json(task) + b"\n")
            visible = ["task.json"]
            for item in spec.visible_files:
                source = self._source(item.source)
                relative_target = PurePosixPath("files") / item.target
                output = temporary.joinpath(*relative_target.parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                with source.open("rb") as reader, output.open("xb") as writer:
                    shutil.copyfileobj(reader, writer)
                    writer.flush()
                    os.fsync(writer.fileno())
                visible.append(relative_target.as_posix())

            findings = scan_bundle(temporary, flag_patterns=spec.contamination_patterns)
            approved = set(spec.approved_findings)
            unknown_approvals = approved - {item.finding_id for item in findings}
            if unknown_approvals:
                raise ValueError(f"approved finding IDs did not occur: {sorted(unknown_approvals)}")
            blocked = [item for item in findings if item.finding_id not in approved]
            if blocked:
                raise ContaminationError(blocked)

            bundle_hash = sha256_tree(temporary)
            manifest = BundleManifest(
                suite=spec.suite,
                suite_version=spec.suite_version,
                upstream_revision=spec.upstream_revision,
                challenge_id=spec.challenge_id,
                category=spec.category,
                bundle_sha256=bundle_hash,
                internet_policy=spec.internet_policy,
                allowed_targets=spec.allowed_targets,
                agent_visible=visible,
            )
            (temporary / MANIFEST_NAME).write_bytes(canonical_json(manifest) + b"\n")
            temporary.replace(target)
            return manifest
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise


def load_staging_spec(path: str | Path) -> StagingSpec:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return StagingSpec.model_validate(payload)
