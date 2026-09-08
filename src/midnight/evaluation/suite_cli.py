"""CLI for auditing and materializing versioned benchmark selections."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from midnight.evaluation.manifest import canonical_json
from midnight.evaluation.suite import CybenchSuiteBuilder, load_cybench_selection


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="midnight-benchmark")
    parser.add_argument("--repository", required=True, help="materialized pinned Cybench checkout")
    parser.add_argument("--selection", required=True, help="versioned Cybench suite JSON")
    parser.add_argument("--report", required=True, help="compatibility report JSON")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("audit")
    stage = subparsers.add_parser("stage")
    stage.add_argument("--bundles", required=True, help="new agent-visible suite directory")
    stage.add_argument(
        "--evaluator-manifest",
        required=True,
        help="new evaluator-only answer manifest outside the bundle tree",
    )
    return parser


def _write_report(report, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_json(report) + b"\n")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    selection = load_cybench_selection(args.selection)
    builder = CybenchSuiteBuilder(args.repository, selection)
    if args.command == "audit":
        report = builder.audit()
        _write_report(report, args.report)
        print(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0 if report.can_stage else 2

    try:
        report = builder.stage(args.bundles, args.evaluator_manifest)
    except ValueError as exc:
        report = builder.audit()
        _write_report(report, args.report)
        print(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
        print(f"staging failed: {exc}")
        return 2
    _write_report(report, args.report)
    print(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
