from __future__ import annotations

import json

import pytest
import yaml

from midnight.evaluation.adapters.lilctf import LilCTF2025Adapter
from midnight.evaluation.stager import VisibleFile
from midnight.utils.flag import extract_flags


def _task(tmp_path, *, category="Crypto", container=None):
    repo = tmp_path / "lil"
    task = repo / "challenges" / "crypto-example"
    (task / "attachment").mkdir(parents=True)
    (task / "attachment" / "public.py").write_text("print(1)\n", encoding="utf-8")
    (task / "build").mkdir()
    (task / "build" / "flag").write_text("LILCTF{private}", encoding="utf-8")
    (task / "README.md").write_text(
        "# Example\n\n## 题目描述\n\nAnalyze the supplied data.\n", encoding="utf-8"
    )
    payload = {
        "info": {"name": "Example", "category": category},
        "score": {"actual_score": 500},
        "flag": {"content": "LILCTF{private}", "type": "static"},
        "attachments": ["public.py"],
        "container": container or {},
    }
    (task / "challenge.yaml").write_text(yaml.safe_dump(payload), encoding="utf-8")
    return repo


def test_lilctf_stages_only_declared_attachments_and_separates_flag(tmp_path):
    repo = _task(tmp_path)
    adapter = LilCTF2025Adapter(repo, upstream_revision="abc")
    manifest = adapter.stage_task("crypto-example", tmp_path / "clean")
    assert manifest.category == "crypto"
    assert manifest.agent_visible == ["task.json", "files/public.py"]
    assert not (tmp_path / "clean" / "build").exists()
    task = json.loads((tmp_path / "clean" / "task.json").read_text())
    assert extract_flags("LILCTF{candidate}", flag_format=task["flag_format"]) == [
        "LILCTF{candidate}"
    ]
    evaluator = adapter.evaluator_manifest(["crypto-example"])
    assert evaluator.tasks["crypto-example"].points == 500


def test_lilctf_remote_requires_explicit_target(tmp_path):
    repo = _task(tmp_path, category="Pwn", container={"image": "private"})
    adapter = LilCTF2025Adapter(repo, upstream_revision="abc")
    with pytest.raises(ValueError, match="requires an evaluator target"):
        adapter.staging_spec("crypto-example")
    spec = adapter.staging_spec(
        "crypto-example",
        target="pwn-task:70",
        visible_files=[VisibleFile(source="build/flag", target="dummy.bin")],
        approved_findings=[],
    )
    assert spec.internet_policy == "target_only"
    assert spec.allowed_targets == ["pwn-task:70"]


def test_lilctf_rejects_unsupported_category(tmp_path):
    repo = _task(tmp_path, category="Blockchain")
    adapter = LilCTF2025Adapter(repo, upstream_revision="abc")
    with pytest.raises(ValueError, match="unsupported LilCTF category"):
        adapter.staging_spec("crypto-example")
