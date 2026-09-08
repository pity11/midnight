from __future__ import annotations

import json

import pytest

from midnight.evaluation.adapters.cybench import CybenchAdapter, UnsupportedCybenchTask


def _repo(tmp_path, *, init_script: str, categories=None, target_host=""):
    repo = tmp_path / "cybench"
    task = repo / "benchmark" / "event" / "crypto" / "Task One"
    (task / "metadata").mkdir(parents=True)
    (task / "challenge").mkdir()
    (repo / "task_list.txt").write_text(
        "benchmark/event/crypto/Task One\n", encoding="utf-8"
    )
    (task / "metadata" / "metadata.json").write_text(
        json.dumps(
            {
                "categories": categories or ["crypto"],
                "hard_prompt": "You are given public.dat. Find the flag.",
                "target_host": target_host,
                "subtasks": [{"answer": "CTF{private}"}],
            }
        ),
        encoding="utf-8",
    )
    (task / "init_script.sh").write_text(init_script, encoding="utf-8")
    (task / "challenge" / "public.dat").write_bytes(b"public")
    return repo


def test_cybench_adapter_uses_hard_prompt_and_plain_copy_allowlist(tmp_path):
    repo = _repo(tmp_path, init_script='cp "challenge/public.dat" $TMP_DIR\n')
    adapter = CybenchAdapter(repo, upstream_revision="abc123")
    task_path = adapter.task_paths()[0]
    spec = adapter.staging_spec(task_path)

    assert spec.description == "You are given public.dat. Find the flag."
    assert spec.visible_files[0].source == "challenge/public.dat"
    assert spec.internet_policy == "disabled"
    assert "private" not in spec.model_dump_json()

    manifest = adapter.stage_task(task_path, tmp_path / "clean" / spec.challenge_id)
    assert manifest.category == "crypto"
    private = adapter.evaluator_manifest([task_path])
    assert private.tasks[spec.challenge_id].expected_flags == ["CTF{private}"]


def test_cybench_adapter_rejects_solution_copy_and_mixed_category(tmp_path):
    repo = _repo(tmp_path, init_script="cp metadata/solution/flag.txt $TMP_DIR\n")
    adapter = CybenchAdapter(repo, upstream_revision="abc123")
    with pytest.raises(UnsupportedCybenchTask, match="requiring review"):
        adapter.staging_spec(adapter.task_paths()[0])

    repo = _repo(tmp_path / "second", init_script="cp challenge/public.dat $TMP_DIR\n", categories=["crypto", "misc"])
    adapter = CybenchAdapter(repo, upstream_revision="abc123")
    with pytest.raises(UnsupportedCybenchTask, match="mixed-category"):
        adapter.staging_spec(adapter.task_paths()[0])


def test_cybench_remote_task_becomes_target_only(tmp_path):
    repo = _repo(tmp_path, init_script="# no files\n", categories=["web"], target_host="10.0.0.5:8080")
    adapter = CybenchAdapter(repo, upstream_revision="abc123")
    spec = adapter.staging_spec(adapter.task_paths()[0])
    assert spec.internet_policy == "target_only"
    assert spec.allowed_targets == ["10.0.0.5:8080"]
