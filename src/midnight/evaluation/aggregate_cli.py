"""Aggregate independent benchmark attempts without exposing flag values."""

from __future__ import annotations

import argparse

from midnight.reporting import AggregateReport, load_run_report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="midnight-aggregate")
    parser.add_argument("reports", nargs="+", help="ordered per-attempt report JSON files")
    parser.add_argument("--output", required=True, help="aggregate JSON destination")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = AggregateReport.from_reports(load_run_report(path) for path in args.reports)
    report.write(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
