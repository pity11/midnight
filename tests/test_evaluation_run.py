from __future__ import annotations

import pytest

from midnight.config import get_config
from midnight.evaluation.manifest import BundleManifest
from midnight.evaluation.run import EvaluationSpec, build_run_manifest


def _bundle(**changes) -> BundleManifest:
    values = {
        "suite": "suite",
        "suite_version": "v1",
        "upstream_revision": "abc",
        "challenge_id": "pwn-1",
        "category": "pwn",
        "bundle_sha256": "a" * 64,
        "internet_policy": "disabled",
        "agent_visible": ["task.json", "files/chall"],
    }
    values.update(changes)
    return BundleManifest.model_validate(values)


def _spec(**changes) -> EvaluationSpec:
    values = {
        "suite": "suite",
        "suite_version": "v1",
        "midnight_revision": "deadbeef",
        "track": "standard",
        "attempt": 1,
        "random_seed": 1,
        "time_budget_seconds": 1800,
        "internet_policy": "disabled",
    }
    values.update(changes)
    return EvaluationSpec.model_validate(values)


def test_build_run_manifest_binds_effective_inputs():
    manifest = build_run_manifest(
        _spec(),
        [_bundle()],
        config=get_config(),
        image_digests={"pwn": "sha256:" + "b" * 64},
    )
    assert manifest.task_bundles == {"pwn-1": "a" * 64}
    assert manifest.tool_image_digests["pwn"].startswith("sha256:")
    assert len(manifest.prompt_revision) == 64
    assert len(manifest.config_revision) == 64
    assert len(manifest.run_identity) == 64


def test_build_run_manifest_rejects_suite_or_policy_mismatch():
    with pytest.raises(ValueError, match="different suite"):
        build_run_manifest(
            _spec(),
            [_bundle(suite_version="v2")],
            config=get_config(),
            image_digests={"pwn": "sha256:" + "b" * 64},
        )
    with pytest.raises(ValueError, match="different internet policy"):
        build_run_manifest(
            _spec(),
            [_bundle(internet_policy="open_world")],
            config=get_config(),
            image_digests={"pwn": "sha256:" + "b" * 64},
        )
