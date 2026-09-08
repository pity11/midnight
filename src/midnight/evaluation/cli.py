"""CLI for producing clean, immutable benchmark bundles."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from midnight.evaluation.stager import BenchmarkStager, ContaminationError, load_staging_spec


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="midnight-stage")
    parser.add_argument("--source-root", required=True, help="pinned upstream challenge root")
    parser.add_argument("--spec", required=True, help="JSON staging specification")
    parser.add_argument("--output", required=True, help="new clean bundle directory")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    spec = load_staging_spec(args.spec)
    try:
        manifest = BenchmarkStager(args.source_root).stage(spec, args.output)
    except ContaminationError as exc:
        print(json.dumps([asdict(item) for item in exc.findings], indent=2, sort_keys=True))
        return 2
    print(json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
