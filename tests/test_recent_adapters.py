from __future__ import annotations

import json

import pytest
import yaml

from midnight.evaluation.adapters.bsidessf import BSidesSFAdapter
from midnight.evaluation.adapters.tribectf import TribeCTFAdapter


def test_tribectf_adapter_uses_declared_files_and_separates_flag(tmp_path):
    repo = tmp_path / "tribe"
    task = repo / "competition" / "task"
    task.mkdir(parents=True)
    (repo / "competition25.json").write_text(
        json.dumps(
            {
                "2025q-cry-task": {
                    "category": "crypto",
                    "challenge": "Task",
                    "path": "competition/task",
                }
            }
        ),
        encoding="utf-8",
    )
    (task / "challenge.json").write_text(
        json.dumps(
            {
                "name": "Task",
                "category": "crypto",
                "description": "Analyze the supplied data.",
                "flag": "tribectf{private}",
                "type": "static",
                "points": 500,
                "files": ["public.zip"],
            }
        ),
        encoding="utf-8",
    )
    (task / "public.zip").write_bytes(b"player data")
    (task / "solve.py").write_text("private", encoding="utf-8")

    adapter = TribeCTFAdapter(repo, upstream_revision="abc")
    manifest = adapter.stage_task("2025q-cry-task", tmp_path / "clean")
    assert manifest.agent_visible == ["task.json", "files/public.zip"]
    assert not (tmp_path / "clean" / "files" / "solve.py").exists()
    evaluator = adapter.evaluator_manifest(["2025q-cry-task"])
    assert evaluator.tasks["2025q-cry-task"].points == 500


def test_tribectf_remote_requires_explicit_target(tmp_path):
    repo = tmp_path / "tribe"
    task = repo / "task"
    task.mkdir(parents=True)
    (repo / "competition25.json").write_text(
        json.dumps({"remote": {"category": "web", "challenge": "Remote", "path": "task"}}),
        encoding="utf-8",
    )
    (task / "challenge.json").write_text(
        json.dumps(
            {
                "category": "web",
                "description": "Remote task",
                "flag": "tribectf{private}",
                "type": "dynamic",
                "files": [],
            }
        ),
        encoding="utf-8",
    )
    adapter = TribeCTFAdapter(repo, upstream_revision="abc")
    with pytest.raises(ValueError, match="requires an evaluator target"):
        adapter.staging_spec("remote")
    assert adapter.staging_spec("remote", target="10.0.0.2:8080").internet_policy == "target_only"


def test_bsidessf_adapter_only_stages_distfiles(tmp_path):
    repo = tmp_path / "bsides"
    task = repo / "ads"
    (task / "distfiles").mkdir(parents=True)
    (task / "solution").mkdir()
    (task / "distfiles" / "ads.mp4").write_bytes(b"video")
    (task / "solution" / "README.md").write_text("private", encoding="utf-8")
    (task / "metadata.yml").write_text(
        yaml.safe_dump(
            {
                "name": "ads",
                "flag": "CTF{private}",
                "description": "Find the hidden value.",
                "value": 1000,
                "tags": ["101", "Forensics"],
            }
        ),
        encoding="utf-8",
    )

    adapter = BSidesSFAdapter(repo, upstream_revision="def")
    manifest = adapter.stage_task("ads", tmp_path / "clean")
    assert manifest.category == "forensics"
    assert manifest.agent_visible == ["task.json", "files/ads.mp4"]
    assert not (tmp_path / "clean" / "solution").exists()
    assert adapter.evaluator_manifest(["ads"]).tasks["ads"].points == 1000


def test_bsidessf_server_requires_target(tmp_path):
    repo = tmp_path / "bsides"
    task = repo / "pwn-task"
    (task / "distfiles").mkdir(parents=True)
    (task / "distfiles" / "chall").write_bytes(b"binary")
    (task / "metadata.yml").write_text(
        yaml.safe_dump(
            {
                "name": "pwn-task",
                "flag": "CTF{private}",
                "description": "Connect and solve.",
                "tags": ["Pwn"],
                "port": 1234,
            }
        ),
        encoding="utf-8",
    )
    adapter = BSidesSFAdapter(repo, upstream_revision="def")
    with pytest.raises(ValueError, match="requires an evaluator target"):
        adapter.staging_spec("pwn-task")
