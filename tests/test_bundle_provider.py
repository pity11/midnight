from __future__ import annotations

import asyncio
import json

import pytest

from midnight.evaluation.provider import EvaluatorManifestSubmitter, ValidatedBundleProvider
from midnight.evaluation.stager import BenchmarkStager, StagingSpec


def _bundle(tmp_path):
    source = tmp_path / "upstream"
    source.mkdir()
    (source / "chall.bin").write_bytes(b"binary")
    spec = StagingSpec(
        suite="suite",
        suite_version="suite-v1",
        upstream_revision="abc123",
        challenge_id="rev-1",
        name="Reverse One",
        description="Recover the value.",
        category="reverse",
        visible_files=[{"source": "chall.bin", "target": "chall.bin"}],
    )
    bundles = tmp_path / "bundles"
    BenchmarkStager(source).stage(spec, bundles / "rev-1")
    return bundles


def test_validated_provider_exposes_clean_bundle(tmp_path):
    bundles = _bundle(tmp_path)
    provider = ValidatedBundleProvider(bundles)

    challenges = asyncio.run(provider.list_challenges())
    assert len(challenges) == 1
    assert challenges[0]["id"] == "rev-1"
    assert challenges[0]["category_hint"] == "reverse"
    assert challenges[0]["source_hash"]
    assert [path.rsplit("/", 1)[-1] for path in challenges[0]["files"]] == ["chall.bin"]
    source = challenges[0]["files"][0]
    assert challenges[0]["file_destinations"] == {source: "chall.bin"}


def test_validated_provider_rejects_bundle_tampering(tmp_path):
    bundles = _bundle(tmp_path)
    (bundles / "rev-1" / "files" / "chall.bin").write_bytes(b"modified")
    provider = ValidatedBundleProvider(bundles)

    with pytest.raises(ValueError, match="hash mismatch"):
        asyncio.run(provider.fetch("rev-1"))


def test_evaluator_manifest_is_a_separate_oracle(tmp_path):
    path = tmp_path / "private" / "evaluator.json"
    path.parent.mkdir()
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_version": "suite-v1",
                "tasks": {
                    "rev-1": {
                        "expected_flags": ["CTF{private}"],
                        "points": 100,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    submitter = EvaluatorManifestSubmitter(path)

    accepted = asyncio.run(submitter.submit("rev-1", "CTF{private}"))
    rejected = asyncio.run(submitter.submit("rev-1", "CTF{wrong}"))
    assert accepted.accepted and accepted.points == 100
    assert not rejected.accepted
