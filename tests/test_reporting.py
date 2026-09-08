from __future__ import annotations

import json

from midnight.orchestrator.scheduler import Result
from midnight.reporting import RunReport


def test_report_aggregates_results_without_flag_values(tmp_path):
    report = RunReport.from_results(
        "run-1",
        [
            Result("a", "solved", flag="flag{private}"),
            Result("b", "timeout"),
            Result("c", "failed", error="candidate flag{private} caused model failure"),
        ],
        elapsed_seconds=1.23456,
    )
    path = report.write(tmp_path / "report.json")
    payload = json.loads(path.read_text())
    assert payload["solved"] == 1
    assert payload["success_rate"] == 0.3333
    assert payload["status_counts"] == {"failed": 1, "solved": 1, "timeout": 1}
    assert payload["challenges"][0]["has_flag"] is True
    assert "flag{private}" not in path.read_text()
    assert payload["challenges"][2]["error"] == ("candidate <redacted-flag> caused model failure")
