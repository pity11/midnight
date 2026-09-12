from __future__ import annotations

import json

from midnight.orchestrator.scheduler import Result
from midnight.reporting import AggregateReport, RunReport, load_run_report


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
                protocol_recoveries=2,
                model_transport_failures=1,
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
    assert payload["protocol_recoveries"] == 2
    assert payload["model_transport_failures"] == 1
    assert payload["challenges"][0]["model_transport_failures"] == 1
    assert payload["category_results"]["pwn"] == {"solved": 1, "total": 2}


def test_aggregate_reports_independent_attempts(tmp_path):
    attempts = [
        [Result("a", "solved", category="pwn"), Result("b", "failed", category="web")],
        [Result("a", "failed", category="pwn"), Result("b", "solved", category="web")],
        [Result("a", "solved", category="pwn"), Result("b", "failed", category="web")],
    ]
    reports = [
        RunReport.from_results(f"run-{number}", results, elapsed_seconds=1.0)
        for number, results in enumerate(attempts, 1)
    ]
    aggregate = AggregateReport.from_reports(reports)
    assert aggregate.attempts == 3
    assert aggregate.success_at_1 == 0.5
    assert aggregate.success_in_n == 1.0
    assert aggregate.mean_solve_probability == 0.5
    assert aggregate.mean_solve_probability_ci95 == (0.1876, 0.8124)
    assert aggregate.category_results["pwn"]["solved_observations"] == 2

    path = reports[0].write(tmp_path / "run.json")
    assert load_run_report(path) == reports[0]


def test_aggregate_rejects_mismatched_challenge_inventory():
    first = RunReport.from_results("a", [Result("one", "solved")], elapsed_seconds=1)
    second = RunReport.from_results("b", [Result("two", "solved")], elapsed_seconds=1)
    with __import__("pytest").raises(ValueError, match="same unique"):
        AggregateReport.from_reports([first, second])
