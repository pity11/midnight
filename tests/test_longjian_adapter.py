from __future__ import annotations

from midnight.evaluation.adapters.longjian import LongjianCup2025Adapter
from midnight.utils.flag import extract_flags


def _fixture(tmp_path):
    repo = tmp_path / "longjian"
    attachments = repo / "attachments"
    attachments.mkdir(parents=True)
    (attachments / "2.which_sql.zip").write_bytes(b"player log")
    (attachments / "3.从Web到Root.zip").write_bytes(b"player logs")
    (attachments / "5.ShellDecoder.zip").write_bytes(b"player capture")
    (repo / "README.md").write_text(
        "## Round\n\n### which_sql\n\nAnalyze the database log.\n\n"
        "### 从Web到Root\n\nCorrelate the supplied logs.\n\n"
        "### ShellDecoder\n\nAnalyze the captured traffic.\n",
        encoding="utf-8",
    )
    writeup = tmp_path / "private-writeup.html"
    writeup.write_text(
        "<nav>which_sql 从Web到Root ShellDecoder</nav><article>"
        "<h3>which_sql</h3><p>Cross-reference ShellDecoder.</p>"
        "<p>flag{department42}</p>"
        "<h3>从Web到Root</h3><p>Example flag{md5(part1)}</p>"
        "<p>Result flag{0123456789abcdef0123456789abcdef}</p>"
        "<h3>ShellDecoder</h3><p>flag{traffic_answer}</p></article>",
        encoding="utf-8",
    )
    return repo, writeup


def test_longjian_adapter_separates_writeup_and_stages_one_attachment(tmp_path):
    repo, writeup = _fixture(tmp_path)
    adapter = LongjianCup2025Adapter(
        repo,
        writeup,
        upstream_revision="release",
        writeup_revision="writeup",
        verify_revision=False,
    )
    manifest = adapter.stage_task("which-sql", tmp_path / "clean")
    assert manifest.agent_visible == ["task.json", "files/2.which_sql.zip"]
    task = (tmp_path / "clean" / "task.json").read_text()
    assert "department42" not in task
    assert not (tmp_path / "clean" / "private-writeup.html").exists()
    spec = adapter.staging_spec("which-sql")
    assert extract_flags("flag{candidate}", flag_format=spec.flag_format) == [
        "flag{candidate}"
    ]


def test_longjian_adapter_extracts_only_non_placeholder_final_flags(tmp_path):
    repo, writeup = _fixture(tmp_path)
    adapter = LongjianCup2025Adapter(
        repo,
        writeup,
        upstream_revision="release",
        writeup_revision="writeup",
        verify_revision=False,
    )
    evaluator = adapter.evaluator_manifest(adapter.task_ids())
    assert evaluator.tasks["which-sql"].expected_flags == ["flag{department42}"]
    assert evaluator.tasks["from-web-to-root"].expected_flags == [
        "flag{0123456789abcdef0123456789abcdef}"
    ]
    assert evaluator.tasks["shell-decoder"].expected_flags == ["flag{traffic_answer}"]
