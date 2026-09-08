from __future__ import annotations

import json
from pathlib import Path

import pytest

from midnight.evaluation.provider import EvaluatorManifestSubmitter, ValidatedBundleProvider
from midnight.evaluation.suite import CybenchSuiteBuilder, CybenchSuiteSelection


def _task(repo: Path, path: str, category: str, *, content: str = "public") -> None:
    root = repo / path
    (root / "metadata").mkdir(parents=True)
    (root / "challenge").mkdir()
    (root / "challenge" / "public.txt").write_text(content, encoding="utf-8")
    (root / "init_script.sh").write_text(
        "cp challenge/public.txt $TMP_DIR\n", encoding="utf-8"
    )
    (root / "metadata" / "metadata.json").write_text(
        json.dumps(
            {
                "categories": [category],
                "hard_prompt": "Recover the flag from public.txt.",
                "target_host": "",
                "subtasks": [{"answer": "CTF{evaluator-only}"}],
            }
        ),
        encoding="utf-8",
    )


def _selection(paths: list[tuple[str, str]], revision: str = "a" * 40):
    counts: dict[str, int] = {}
    for _, category in paths:
        counts[category] = counts.get(category, 0) + 1
    return CybenchSuiteSelection.model_validate(
        {
            "name": "test-suite",
            "upstream_revision": revision,
            "expected_category_counts": counts,
            "tasks": [{"path": path, "category": category} for path, category in paths],
        }
    )


def test_suite_audit_and_atomic_stage_keep_answers_private(tmp_path):
    repo = tmp_path / "upstream"
    path = "benchmark/event/crypto/task-one"
    _task(repo, path, "crypto")
    selection = _selection([(path, "crypto")])
    builder = CybenchSuiteBuilder(repo, selection, verify_revision=False)

    audit = builder.audit()
    assert audit.can_stage
    assert audit.tasks[0].attachment_count == 1

    bundles = tmp_path / "public" / "suite"
    evaluator = tmp_path / "private" / "answers.json"
    builder.stage(bundles, evaluator)

    provider = ValidatedBundleProvider(bundles)
    challenge_id = audit.tasks[0].challenge_id
    assert challenge_id is not None
    assert provider.bundle_manifest(challenge_id).category == "crypto"
    assert "evaluator-only" not in "".join(
        path.read_text(errors="ignore") for path in bundles.rglob("*") if path.is_file()
    )
    assert EvaluatorManifestSubmitter(evaluator).manifest.tasks[challenge_id].expected_flags
    assert evaluator.stat().st_mode & 0o077 == 0


def test_suite_audit_reports_stable_findings_without_secret(tmp_path):
    repo = tmp_path / "upstream"
    path = "benchmark/event/crypto/task-one"
    _task(repo, path, "crypto", content="CTF{never-print-this}")
    audit = CybenchSuiteBuilder(
        repo, _selection([(path, "crypto")]), verify_revision=False
    ).audit()

    assert not audit.can_stage
    assert audit.tasks[0].status == "blocked"
    assert audit.tasks[0].finding_ids
    assert audit.tasks[0].finding_paths == ["files/public.txt"]
    assert "never-print-this" not in audit.model_dump_json()


def test_suite_rejects_private_manifest_inside_bundles(tmp_path):
    repo = tmp_path / "upstream"
    path = "benchmark/event/crypto/task-one"
    _task(repo, path, "crypto")
    builder = CybenchSuiteBuilder(
        repo, _selection([(path, "crypto")]), verify_revision=False
    )

    with pytest.raises(ValueError, match="outside"):
        builder.stage(tmp_path / "public", tmp_path / "public" / "answers.json")


def test_selection_enforces_declared_category_balance():
    with pytest.raises(ValueError, match="category counts"):
        CybenchSuiteSelection.model_validate(
            {
                "name": "broken",
                "upstream_revision": "a" * 40,
                "expected_category_counts": {"crypto": 2},
                "tasks": [{"path": "one", "category": "crypto"}],
            }
        )
