from __future__ import annotations

import json

from midnight.orchestrator.scheduler import Result
from midnight.reporting import RunReport


def test_report_aggregates_results_without_flag_values(tmp_path):
    report = RunReport.from_results(
        "run-1",
        [
            Result(
                "a",
                "solved",
                flag="flag{private}",
                category="pwn",
                points=100,
                input_tokens=10,
                output_tokens=4,
                tool_calls=3,
                repeated_tool_calls=1,
            ),
            Result("b", "timeout", category="pwn", input_tokens=2, tool_errors=1),
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
    assert payload["total_points"] == 100
    assert payload["input_tokens"] == 12
    assert payload["output_tokens"] == 4
    assert payload["tool_calls"] == 3
    assert payload["repeated_tool_calls"] == 1
    assert payload["tool_errors"] == 1
    assert payload["category_results"]["pwn"] == {"solved": 1, "total": 2}
