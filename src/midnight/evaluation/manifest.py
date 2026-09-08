"""Immutable, canonical manifests for task bundles and evaluation runs."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def canonical_json(value: BaseModel | dict) -> bytes:
    """Return the stable JSON representation used by all manifest hashes."""
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _safe_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not value or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"path must be a normalized relative POSIX path: {value!r}")
    return path.as_posix()


def sha256_tree(root: str | Path, *, excluded: set[str] | None = None) -> str:
    """Hash regular files using their relative paths, sizes, and contents."""
    base = Path(root).resolve()
    excluded = excluded or set()
    digest = hashlib.sha256()
    if not base.is_dir():
        raise ValueError(f"bundle root is not a directory: {base}")
    files = sorted(path for path in base.rglob("*") if path.is_file() or path.is_symlink())
    for path in files:
        relative = path.relative_to(base).as_posix()
        if relative in excluded:
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"bundle contains a non-regular file: {relative}")
        size = path.stat().st_size
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


class StrictManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BundleManifest(StrictManifest):
    schema_version: Literal[1] = 1
    suite: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    upstream_revision: str = Field(min_length=1)
    challenge_id: str = Field(min_length=1)
    category: Literal["pwn", "reverse", "web", "crypto", "forensics", "misc"]
    bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )
    internet_policy: Literal["disabled", "target_only", "open_world"] = "disabled"
    allowed_targets: list[str] = Field(default_factory=list)
    agent_visible: list[str]
    excluded_classes: list[str] = Field(
        default_factory=lambda: ["flag", "solution", "writeup", "grader"]
    )

    @field_validator("agent_visible")
    @classmethod
    def validate_visible_paths(cls, value: list[str]) -> list[str]:
        paths = [_safe_relative_path(item) for item in value]
        if len(paths) != len(set(paths)):
            raise ValueError("agent_visible paths must be unique")
        return paths


class RunManifest(StrictManifest):
    schema_version: Literal[1] = 1
    suite: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    task_bundles: dict[str, str] = Field(min_length=1)
    midnight_revision: str = Field(min_length=1)
    models: dict[str, str] = Field(min_length=1)
    prompt_revision: str = Field(min_length=1)
    config_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    tool_image_digests: dict[str, str] = Field(min_length=1)
    relay_image_digest: str | None = None
    target_image_digests: dict[str, str] = Field(default_factory=dict)
    agent_mode: Literal["midnight", "bare"]
    track: Literal["standard", "long_horizon", "open_world"]
    attempt: int = Field(ge=1)
    random_seed: int
    time_budget_seconds: int = Field(gt=0)
    token_budget: int | None = Field(default=None, gt=0)
    internet_policy: Literal["disabled", "target_only", "open_world", "bundle_enforced"]
    task_internet_policies: dict[
        str, Literal["disabled", "target_only", "open_world"]
    ] = Field(min_length=1)

    @field_validator("task_bundles")
    @classmethod
    def validate_bundle_hashes(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not re.fullmatch(r"[a-f0-9]{64}", digest) for digest in value.values()):
            raise ValueError("task bundle hashes must be lowercase SHA-256 values")
        return dict(sorted(value.items()))

    @field_validator("tool_image_digests", "target_image_digests")
    @classmethod
    def validate_image_digests(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not re.fullmatch(r"sha256:[a-f0-9]{64}", digest) for digest in value.values()):
            raise ValueError("image digests must be immutable SHA-256 IDs")
        return dict(sorted(value.items()))

    @field_validator("relay_image_digest")
    @classmethod
    def validate_relay_digest(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"sha256:[a-f0-9]{64}", value):
            raise ValueError("relay image digest must be an immutable SHA-256 ID")
        return value

    @property
    def run_identity(self) -> str:
        return hashlib.sha256(canonical_json(self)).hexdigest()

    def write(self, path: str | Path) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_bytes(canonical_json(self) + b"\n")
        temporary.replace(target)
        return target
