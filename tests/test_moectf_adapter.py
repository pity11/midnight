from __future__ import annotations

from midnight.evaluation.adapters.moectf import MoeCTF2025MiscAdapter
from midnight.utils.flag import extract_flags


def _repo(tmp_path):
    repo = tmp_path / "moe"
    task = repo / "challenges" / "Misc" / "Capture"
    task.mkdir(parents=True)
    (task / "README.md").write_text("Inspect the capture.\n", encoding="utf-8")
    (task / "capture.pcapng").write_bytes(b"player evidence")
    writeup = repo / "official_writeups" / "Misc"
    writeup.mkdir(parents=True)
    (writeup / "Writeup.md").write_text(
        "# Capture\n\nPrivate reasoning. `moectf{private}`\n\n# Other\n",
        encoding="utf-8",
    )
    return repo


def test_moectf_static_adapter_separates_official_writeup(tmp_path):
    repo = _repo(tmp_path)
    adapter = MoeCTF2025MiscAdapter(repo, upstream_revision="abc")
    manifest = adapter.stage_task("Capture", tmp_path / "clean")
    assert manifest.category == "forensics"
    assert manifest.agent_visible == ["task.json", "files/capture.pcapng"]
    assert not (tmp_path / "clean" / "Writeup.md").exists()
    task = (tmp_path / "clean" / "task.json").read_text()
    assert "private" not in task
    spec = adapter.staging_spec("Capture")
    assert extract_flags("moectf{candidate}", flag_format=spec.flag_format) == [
        "moectf{candidate}"
    ]
    evaluator = adapter.evaluator_manifest(["Capture"])
    assert evaluator.tasks["capture"].expected_flags == ["moectf{private}"]
