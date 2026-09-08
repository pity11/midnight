"""Top-level entry point / CLI.

Usage (after `uv sync`):
    uv run midnight --help
    uv run midnight --challenges-dir tests/fixtures
    uv run midnight --challenges-dir tests/fixtures --id sanity_misc

At M0 this validates config and lists challenges from the local provider; the
full solve loop is enabled from M1 onward.
"""

from __future__ import annotations

import argparse
import asyncio
import time
from pathlib import Path
from uuid import uuid4

import yaml

from midnight.config import get_config
from midnight.events import EventJournal
from midnight.interfaces.http_platform import (
    EndpointMap,
    HTTPPlatformAdapter,
    HTTPPlatformConfig,
)
from midnight.interfaces.local_mock import LocalDirProvider, ManualSubmitter
from midnight.interfaces.provider import ChallengeProvider
from midnight.interfaces.submission_gate import SubmissionGate
from midnight.interfaces.submitter import FlagSubmitter
from midnight.persistence import CheckpointStore
from midnight.reporting import RunReport
from midnight.utils.logging import get_logger

log = get_logger("midnight.app")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="midnight", description="LangGraph CTF solving agent")
    p.add_argument(
        "--challenges-dir",
        default="tests/fixtures",
        help="local fixtures directory for the mock provider",
    )
    p.add_argument(
        "--platform-config",
        help="YAML configuration for the generic HTTP platform adapter",
    )
    p.add_argument(
        "--bundles-dir",
        help="root containing clean, immutable benchmark bundles",
    )
    p.add_argument(
        "--evaluator-manifest",
        help="evaluator-only JSON oracle used with --bundles-dir",
    )
    p.add_argument(
        "--evaluation-spec",
        help="immutable evaluation protocol JSON used with --bundles-dir",
    )
    p.add_argument(
        "--run-manifest-path",
        default="logs/run-manifest.json",
        help="write the effective immutable evaluation run manifest",
    )
    p.add_argument(
        "--submit",
        action="store_true",
        help="allow submissions when using an HTTP platform (default: dry run)",
    )
    p.add_argument("--id", help="solve a single challenge by id (default: all)")
    p.add_argument(
        "--list-only",
        action="store_true",
        help="list discovered challenges and exit (no solving)",
    )
    p.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration and exit",
    )
    p.add_argument(
        "--events-path",
        default="logs/events.jsonl",
        help="append-only JSONL event journal",
    )
    p.add_argument(
        "--checkpoint-path",
        default="logs/checkpoints.sqlite",
        help="SQLite checkpoint database",
    )
    p.add_argument(
        "--run-id",
        help="stable run identifier; reuse it to resume an interrupted run",
    )
    p.add_argument(
        "--report-path",
        default="logs/report.json",
        help="write a JSON benchmark summary without flag values",
    )
    p.add_argument(
        "--submission-ledger-path",
        default="logs/submissions.sqlite",
        help="durable candidate submission ledger",
    )
    p.add_argument(
        "--artifacts-root",
        default="logs/artifacts",
        help="downloaded challenge attachment directory",
    )
    p.add_argument(
        "--cleanup-run",
        metavar="RUN_ID",
        help="remove orphaned Midnight containers for a run and exit",
    )
    return p.parse_args(argv)


def _load_http_adapter(path: str) -> HTTPPlatformAdapter:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    endpoint_raw = raw.pop("endpoints", {})
    config = HTTPPlatformConfig(
        **raw,
        endpoints=EndpointMap(**endpoint_raw),
    )
    return HTTPPlatformAdapter(config)


async def _amain(args: argparse.Namespace) -> int:
    cfg = get_config()
    log.info(
        "config loaded: %d model roles, %d image specs, %d expert toolsets",
        len(cfg.models),
        len(cfg.images),
        len(cfg.tools),
    )

    if args.cleanup_run:
        from midnight.env.container_manager import ContainerManager

        removed = await ContainerManager(run_id=args.cleanup_run).cleanup_run()
        log.info("removed %d container(s) for run %s", removed, args.cleanup_run)
        return 0

    if args.check_config:
        log.info("configuration OK")
        return 0

    if args.platform_config and args.bundles_dir:
        raise ValueError("--platform-config and --bundles-dir are mutually exclusive")
    if (args.evaluator_manifest or args.evaluation_spec) and not args.bundles_dir:
        raise ValueError("--evaluator-manifest and --evaluation-spec require --bundles-dir")

    platform = _load_http_adapter(args.platform_config) if args.platform_config else None
    provider: ChallengeProvider
    delegate: FlagSubmitter
    if args.bundles_dir:
        from midnight.evaluation.provider import (
            EvaluatorManifestSubmitter,
            ValidatedBundleProvider,
        )

        provider = ValidatedBundleProvider(args.bundles_dir)
        if not args.evaluator_manifest or not args.evaluation_spec:
            raise ValueError("--bundles-dir requires evaluator manifest and evaluation spec")
        bundle_root = Path(args.bundles_dir).resolve()
        evaluator_path = Path(args.evaluator_manifest).resolve()
        if evaluator_path.is_relative_to(bundle_root):
            raise ValueError("evaluator manifest must be outside the clean bundle root")
        delegate = EvaluatorManifestSubmitter(args.evaluator_manifest)
    else:
        provider = platform or LocalDirProvider(args.challenges_dir)
        delegate = platform or ManualSubmitter(args.challenges_dir)

    if args.id:
        challenges = [await provider.fetch(args.id)]
    else:
        challenges = await provider.list_challenges()
    if not challenges:
        log.warning("no challenges found under %s", Path(args.challenges_dir).resolve())
        if platform is not None:
            await platform.close()
        return 0

    log.info("discovered %d challenge(s):", len(challenges))
    for ch in challenges:
        log.info(
            "  - %s (%s) remote=%s files=%d",
            ch.get("id"),
            ch.get("category_hint") or "?",
            ch.get("remote"),
            len(ch.get("files") or []),
        )

    if args.list_only:
        if platform is not None:
            await platform.close()
        return 0

    from midnight.orchestrator.scheduler import Scheduler

    run_manifest = None
    if args.bundles_dir:
        from typing import cast

        from midnight.env.container_manager import ContainerManager
        from midnight.evaluation.provider import ValidatedBundleProvider
        from midnight.evaluation.run import (
            apply_random_seed,
            build_run_manifest,
            load_evaluation_spec,
        )
        from midnight.state import ChallengeType

        clean_provider = cast(ValidatedBundleProvider, provider)
        evaluation_spec = load_evaluation_spec(args.evaluation_spec)
        if evaluation_spec.token_budget is not None:
            raise ValueError("token budget enforcement is not implemented; omit token_budget")
        apply_random_seed(evaluation_spec.random_seed)
        bundle_manifests = [clean_provider.bundle_manifest(ch["id"]) for ch in challenges]
        categories = {cast(ChallengeType, manifest.category) for manifest in bundle_manifests}
        image_manager = ContainerManager(run_id="manifest-preflight")
        image_digests: dict[str, str] = {
            category: await image_manager.image_digest(category) for category in sorted(categories)
        }
        run_manifest = build_run_manifest(
            evaluation_spec,
            bundle_manifests,
            config=cfg,
            image_digests=image_digests,
        )
        manifest_run_id = run_manifest.run_identity
        if args.run_id and args.run_id != manifest_run_id:
            raise ValueError("--run-id must equal the immutable run manifest identity")
        run_id = manifest_run_id
        run_manifest.write(args.run_manifest_path)
        task_timeout = evaluation_spec.time_budget_seconds
    else:
        run_id = args.run_id or uuid4().hex
        task_timeout = None
    log.info("run id: %s", run_id)
    submitter = SubmissionGate(
        delegate,
        enabled=platform is None or args.submit,
        ledger_path=args.submission_ledger_path,
        namespace=run_id,
    )
    try:
        scheduler = Scheduler(
            provider=provider,
            submitter=submitter,
            journal=EventJournal(args.events_path),
            run_id=run_id,
            checkpoint_store=CheckpointStore(args.checkpoint_path),
            artifacts_root=args.artifacts_root,
            per_task_timeout=task_timeout,
        )
        started = time.monotonic()
        results = await scheduler.solve_all(challenges)
        report = RunReport.from_results(
            run_id,
            results,
            elapsed_seconds=time.monotonic() - started,
            models={role: spec.model for role, spec in cfg.models.items()},
            run_manifest_id=run_manifest.run_identity if run_manifest else None,
        )
        report.write(args.report_path)
        log.info("report written to %s", Path(args.report_path).resolve())
    finally:
        if platform is not None:
            await platform.close()

    log.info("=== results ===")
    solved = 0
    for r in results:
        mark = "OK " if r.status == "solved" else "-- "
        if r.status == "solved":
            solved += 1
        log.info("  %s%s: %s has_flag=%s", mark, r.challenge_id, r.status, bool(r.flag))
    log.info("solved %d/%d", solved, len(results))
    return 0 if solved == len(results) else 1


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return asyncio.run(_amain(args))


if __name__ == "__main__":
    raise SystemExit(main())
