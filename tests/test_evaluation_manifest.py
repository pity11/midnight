from __future__ import annotations

import json

from midnight.evaluation.manifest import RunManifest, sha256_tree


def _run_manifest(**changes) -> RunManifest:
    values = {
        "suite": "cybench",
        "suite_version": "cybench-abc123",
        "task_bundles": {"task-1": "a" * 64},
        "midnight_revision": "deadbeef",
        "models": {"default": "provider/model-2026-09-01"},
        "prompt_revision": "b" * 64,
        "config_revision": "d" * 64,
        "tool_image_digests": {"pwn": "sha256:" + "c" * 64},
        "track": "standard",
        "attempt": 1,
        "random_seed": 7,
        "time_budget_seconds": 1800,
        "token_budget": 100_000,
        "internet_policy": "disabled",
    }
    values.update(changes)
    return RunManifest(**values)


def test_tree_hash_is_stable_and_path_sensitive(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "a.txt").write_text("same", encoding="utf-8")
    (second / "a.txt").write_text("same", encoding="utf-8")
    assert sha256_tree(first) == sha256_tree(second)

    (second / "a.txt").rename(second / "b.txt")
    assert sha256_tree(first) != sha256_tree(second)


def test_run_identity_changes_with_experimental_variable(tmp_path):
    original = _run_manifest()
    repeated = _run_manifest()
    changed = _run_manifest(time_budget_seconds=7200)
    assert original.run_identity == repeated.run_identity
    assert original.run_identity != changed.run_identity

    path = original.write(tmp_path / "run.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["attempt"] == 1
    assert payload["task_bundles"] == {"task-1": "a" * 64}
