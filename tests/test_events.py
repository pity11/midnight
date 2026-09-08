from __future__ import annotations

from midnight.events import EventJournal, RunEvent


def test_event_journal_appends_and_redacts_secrets(tmp_path):
    journal = EventJournal(tmp_path / "events.jsonl")
    journal.append(
        RunEvent(
            event="run_started",
            run_id="run-1",
            payload={
                "model": "stub",
                "api_key": "must-not-persist",
                "nested": {"authorization": "Bearer must-not-persist"},
                "message": "request failed with Bearer abcdefghijklmnop",
                "candidate": "flag{must-not-persist}",
            },
        )
    )

    records = journal.read_all()
    assert len(records) == 1
    assert records[0]["event"] == "run_started"
    assert records[0]["payload"]["api_key"] == "<redacted>"
    assert records[0]["payload"]["nested"]["authorization"] == "<redacted>"
    assert records[0]["payload"]["message"] == "request failed with <redacted>"
    assert records[0]["payload"]["candidate"] == "<redacted>"
    assert "must-not-persist" not in (tmp_path / "events.jsonl").read_text()


def test_event_journal_reports_corrupt_line(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"event":"ok"}\nnot-json\n', encoding="utf-8")

    journal = EventJournal(path)
    try:
        journal.read_all()
    except ValueError as exc:
        assert "line 2" in str(exc)
    else:
        raise AssertionError("corrupt journal line was accepted")
