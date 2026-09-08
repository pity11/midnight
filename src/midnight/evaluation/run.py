"""Build an immutable evaluation run identity from the effective runtime."""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from midnight.config import AppConfig
from midnight.evaluation.manifest import BundleManifest, RunManifest, canonical_json
from midnight.graph.specialists import prompts


class EvaluationSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal[1] = 1
    suite: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    midnight_revision: str = Field(min_length=1)
    agent_mode: Literal["midnight", "bare"] = "midnight"
    track: Literal["standard", "long_horizon", "open_world"]
    attempt: int = Field(ge=1)
    random_seed: int
    time_budget_seconds: int = Field(gt=0)
    token_budget: int | None = Field(default=None, gt=0)
    internet_policy: Literal["disabled", "target_only", "open_world"]


def load_evaluation_spec(path: str | Path) -> EvaluationSpec:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return EvaluationSpec.model_validate(payload)


def build_run_manifest(
    spec: EvaluationSpec,
    bundles: list[BundleManifest],
    *,
    config: AppConfig,
    image_digests: dict[str, str],
) -> RunManifest:
    if not bundles:
        raise ValueError("an evaluation run requires at least one task bundle")
    for bundle in bundles:
        if (bundle.suite, bundle.suite_version) != (spec.suite, spec.suite_version):
            raise ValueError(f"task {bundle.challenge_id} belongs to a different suite/version")
        if bundle.internet_policy != spec.internet_policy:
            raise ValueError(f"task {bundle.challenge_id} has a different internet policy")
    categories = {bundle.category for bundle in bundles}
    if not categories.issubset(image_digests):
        raise ValueError(f"missing image digests for categories: {sorted(categories - image_digests.keys())}")

    config_revision = hashlib.sha256(canonical_json(config.model_dump(mode="json"))).hexdigest()
    prompt_revision = hashlib.sha256(canonical_json(prompts.BY_TYPE)).hexdigest()
    return RunManifest(
        suite=spec.suite,
        suite_version=spec.suite_version,
        task_bundles={bundle.challenge_id: bundle.bundle_sha256 for bundle in bundles},
        midnight_revision=spec.midnight_revision,
        models={role: model.model for role, model in config.models.items()},
        prompt_revision=prompt_revision,
        config_revision=config_revision,
        tool_image_digests={category: image_digests[category] for category in sorted(categories)},
        agent_mode=spec.agent_mode,
        track=spec.track,
        attempt=spec.attempt,
        random_seed=spec.random_seed,
        time_budget_seconds=spec.time_budget_seconds,
        token_budget=spec.token_budget,
        internet_policy=spec.internet_policy,
    )


def apply_random_seed(seed: int) -> None:
    """Apply the seeds supported by Midnight's standard-library runtime."""
    random.seed(seed)
