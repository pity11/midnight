from __future__ import annotations

import json
import zipfile

import pytest

from midnight.evaluation.manifest import sha256_tree
from midnight.evaluation.stager import (
    MANIFEST_NAME,
    BenchmarkStager,
    ContaminationError,
    StagingSpec,
)


def _spec(**changes) -> StagingSpec:
    values = {
        "suite": "example",
        "suite_version": "v1",
        "upstream_revision": "abc123",
        "challenge_id": "chall-1",
        "name": "Challenge One",
        "description": "Recover the player-visible value.",
        "category": "reverse",
        "visible_files": [{"source": "dist/chall", "target": "chall"}],
    }
    values.update(changes)
    return StagingSpec.model_validate(values)


def test_stager_copies_only_allowlisted_files_and_writes_manifest(tmp_path):
    source = tmp_path / "upstream"
    (source / "dist").mkdir(parents=True)
    (source / "dist" / "chall").write_bytes(b"player binary")
    (source / "solution.md").write_text("private material", encoding="utf-8")
    (source / "flag.txt").write_text("CTF{private}", encoding="utf-8")

    output = tmp_path / "clean" / "chall-1"
    manifest = BenchmarkStager(source).stage(_spec(), output)

    assert (output / "files" / "chall").read_bytes() == b"player binary"
    assert not (output / "solution.md").exists()
    assert not (output / "flag.txt").exists()
    assert manifest.bundle_sha256 == sha256_tree(output, excluded={MANIFEST_NAME})
    stored = json.loads((output / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert stored["agent_visible"] == ["task.json", "files/chall"]
    assert "expected_flag" not in (output / "task.json").read_text(encoding="utf-8")


def test_stager_blocks_flag_without_disclosing_it(tmp_path):
    source = tmp_path / "upstream"
    (source / "dist").mkdir(parents=True)
    (source / "dist" / "chall").write_text("CTF{do-not-copy-this}", encoding="utf-8")

    with pytest.raises(ContaminationError) as caught:
        BenchmarkStager(source).stage(_spec(), tmp_path / "clean")

    assert caught.value.findings[0].rule == "flag-pattern"
    assert "do-not-copy-this" not in str(caught.value)
    assert not (tmp_path / "clean").exists()


def test_exact_finding_approval_is_required(tmp_path):
    source = tmp_path / "upstream"
    (source / "dist").mkdir(parents=True)
    (source / "dist" / "chall").write_text("Read the solution format carefully.", encoding="utf-8")
    stager = BenchmarkStager(source)
    with pytest.raises(ContaminationError) as caught:
        stager.stage(_spec(), tmp_path / "blocked")
    finding_id = caught.value.findings[0].finding_id

    manifest = stager.stage(
        _spec(approved_findings=[finding_id]),
        tmp_path / "approved",
    )
    assert len(manifest.bundle_sha256) == 64


def test_scanner_rejects_unsafe_archive_member(tmp_path):
    source = tmp_path / "upstream"
    (source / "dist").mkdir(parents=True)
    archive = source / "dist" / "chall"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../answer.txt", "not extracted")

    with pytest.raises(ContaminationError) as caught:
        BenchmarkStager(source).stage(_spec(), tmp_path / "clean")
    assert any(item.rule == "archive-path" for item in caught.value.findings)


def test_scanner_reports_encrypted_archive_member_instead_of_crashing(tmp_path, monkeypatch):
    source = tmp_path / "upstream"
    (source / "dist").mkdir(parents=True)
    archive = source / "dist" / "chall"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("evidence.bin", "player data")

    original_open = zipfile.ZipFile.open

    def encrypted_open(self, name, *args, **kwargs):
        if getattr(name, "filename", name) == "evidence.bin":
            raise RuntimeError("File is encrypted, password required for extraction")
        return original_open(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", encrypted_open)
    with pytest.raises(ContaminationError) as caught:
        BenchmarkStager(source).stage(_spec(), tmp_path / "clean")
    assert any(item.rule == "archive-encrypted" for item in caught.value.findings)


def test_stager_rejects_symlink_source(tmp_path):
    source = tmp_path / "upstream"
    (source / "dist").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    (source / "dist" / "chall").symlink_to(outside)

    with pytest.raises(ValueError, match="symlink"):
        BenchmarkStager(source).stage(_spec(), tmp_path / "clean")
