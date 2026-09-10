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
import os
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from midnight.config import PROJECT_ROOT, effective_model_id, get_config
from midnight.events import EventJournal
from midnight.interfaces.http_platform import (
    ChallengeFieldMap,
    EndpointMap,
    HTTPPlatformAdapter,
    HTTPPlatformConfig,
    ResponseMap,
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
        help="YAML configuration for an HTTP competition platform adapter",
    )
    p.add_argument(
        "--tsecbench",
        action="store_true",
        help="use the official Tsecbench SDK and BENCHMARK_* environment variables",
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
        "--service-manifest",
        help="evaluator-only local target service manifest used with --bundles-dir",
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
        "--agent-mode",
        choices=("midnight", "bare"),
        default="midnight",
        help="full Midnight orchestration or matched single-agent control",
    )
    p.add_argument(
        "--list-only",
        action="store_true",
        help="list discovered challenges and exit (no solving)",
    )
    p.add_argument(
        "--preflight-only",
        action="store_true",
        help="validate bundles, images, and run identity, write the manifest, then exit",
    )
    p.add_argument(
        "--check-config",
        action="store_true",
        help="validate configuration and exit",
    )
    p.add_argument(
        "--check-model",
        action="store_true",
        help="make one structured request to the configured default model and exit",
    )
    p.add_argument(
        "--check-sandboxes",
        action="store_true",
        help="build and validate every specialist image offline, then exit",
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
        "--workspace-root",
        default="logs/workspaces",
        help="durable per-run challenge workspaces used for container recovery",
    )
    p.add_argument(
        "--max-concurrency",
        type=int,
        help="override the configured number of concurrently solved challenges",
    )
    p.add_argument(
        "--task-timeout",
        type=int,
        help="override the configured per-challenge timeout in seconds",
    )
    p.add_argument(
        "--run-timeout",
        type=int,
        help="global solving window shared by all challenges, in seconds",
    )
    p.add_argument(
        "--wait-for-challenges",
        type=int,
        default=0,
        help=(
            "when using a live platform without --id, poll for unsolved "
            "challenges for up to this many seconds"
        ),
    )
    p.add_argument(
        "--cleanup-run",
        metavar="RUN_ID",
        help="remove orphaned Midnight containers for a run and exit",
    )
    return p.parse_args(argv)


async def _list_challenges_with_wait(
    provider: ChallengeProvider,
    *,
    wait_seconds: int,
    poll_interval: float = 5.0,
) -> list[Any]:
    """List live challenges, tolerating a short delay in platform publication."""
    deadline = time.monotonic() + wait_seconds
    had_successful_query = False
    last_error: Exception | None = None
    announced_wait = False
    while True:
        try:
            challenges = await provider.list_challenges()
            had_successful_query = True
            last_error = None
            if challenges or wait_seconds <= 0:
                return challenges
        except Exception as exc:
            if wait_seconds <= 0:
                raise
            last_error = exc
            log.warning(
                "challenge discovery failed (%s); retrying during startup window",
                type(exc).__name__,
            )

        if not announced_wait:
            log.info("waiting up to %d seconds for live challenges", wait_seconds)
            announced_wait = True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(poll_interval, remaining))

    if not had_successful_query and last_error is not None:
        raise RuntimeError(
            f"challenge discovery unavailable after {wait_seconds} seconds"
        ) from last_error
    return []


def _load_http_adapter(path: str) -> Any:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    adapter = raw.pop("adapter", "generic")
    if adapter == "ichunqiu":
        from midnight.interfaces.ichunqiu import (
            IchunqiuConfig,
            IchunqiuEndpoints,
            IchunqiuPlatformAdapter,
        )

        endpoint_raw = raw.pop("endpoints", {})
        return IchunqiuPlatformAdapter(
            IchunqiuConfig(**raw, endpoints=IchunqiuEndpoints(**endpoint_raw))
        )
    if adapter != "generic":
        raise ValueError(f"unknown platform adapter: {adapter}")
    endpoint_raw = raw.pop("endpoints", {})
    field_raw = raw.pop("fields", {})
    response_raw = raw.pop("responses", {})
    config = HTTPPlatformConfig(
        **raw,
        endpoints=EndpointMap(**endpoint_raw),
        fields=ChallengeFieldMap(**field_raw),
        responses=ResponseMap(**response_raw),
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

    if args.check_model:
        from typing import Literal

        from pydantic import BaseModel, ConfigDict

        from midnight.models.factory import build_llm

        class HealthResponse(BaseModel):
            model_config = ConfigDict(extra="forbid")

            status: Literal["PONG"]

        probe = build_llm("default", config=cfg).with_structured_output(HealthResponse)
        response = HealthResponse.model_validate(
            await probe.ainvoke(
                "Connection check. Return exactly the requested structured response with status PONG."
            )
        )
        if response.status != "PONG":
            raise RuntimeError("MODEL_PREFLIGHT_FAILED")
        log.info("model preflight OK: %s", effective_model_id("default", config=cfg))
        return 0

    if args.check_sandboxes:
        from typing import cast

        from midnight.env.container_manager import ContainerManager
        from midnight.state import ChallengeType

        manager = ContainerManager(run_id="sandbox-preflight")
        for category in cfg.images:
            await manager.validate_image(cast(ChallengeType, category))
            log.info("sandbox %s satisfies its capability contract", category)
        return 0

    selected_platforms = sum(
        bool(value) for value in (args.platform_config, args.bundles_dir, args.tsecbench)
    )
    if selected_platforms > 1:
        raise ValueError("--platform-config, --bundles-dir, and --tsecbench are mutually exclusive")
    if (
        args.evaluator_manifest or args.evaluation_spec or args.service_manifest
    ) and not args.bundles_dir:
        raise ValueError("evaluator and service manifests require --bundles-dir")
    if args.wait_for_challenges < 0:
        raise ValueError("--wait-for-challenges cannot be negative")

    platform: Any = None
    if args.tsecbench:
        from midnight.interfaces.tsecbench import TsecbenchAdapter

        base_url = os.environ.get("BENCHMARK_BASE_URL")
        token = os.environ.get("BENCHMARK_TOKEN")
        if not base_url or not token:
            raise RuntimeError("Tsecbench requires BENCHMARK_BASE_URL and BENCHMARK_TOKEN")
        platform = TsecbenchAdapter.from_sdk(base_url=base_url, token=token)
    else:
        platform = _load_http_adapter(args.platform_config) if args.platform_config else None
    provider: ChallengeProvider
    delegate: FlagSubmitter
    service_manager = None
    if args.bundles_dir:
        from midnight.evaluation.provider import (
            EvaluatorManifestSubmitter,
            ValidatedBundleProvider,
        )

        target_networks: dict[str, str] = {}
        if args.service_manifest:
            from midnight.evaluation.services import BenchmarkServiceManager

            service_manager = BenchmarkServiceManager(args.service_manifest)
            target_networks = {
                challenge_id: service_manager.network
                for challenge_id in service_manager.challenge_ids
            }
        provider = ValidatedBundleProvider(args.bundles_dir, target_networks=target_networks)
        if not args.evaluator_manifest or not args.evaluation_spec:
            raise ValueError("--bundles-dir requires evaluator manifest and evaluation spec")
        bundle_root = Path(args.bundles_dir).resolve()
        evaluator_path = Path(args.evaluator_manifest).resolve()
        if evaluator_path.is_relative_to(bundle_root):
            raise ValueError("evaluator manifest must be outside the clean bundle root")
        if args.service_manifest and Path(args.service_manifest).resolve().is_relative_to(
            bundle_root
        ):
            raise ValueError("service manifest must be outside the clean bundle root")
        delegate = EvaluatorManifestSubmitter(args.evaluator_manifest)
    else:
        provider = platform or LocalDirProvider(args.challenges_dir)
        delegate = platform or ManualSubmitter(args.challenges_dir)

    if args.id:
        challenges = [await provider.fetch(args.id)]
    else:
        wait_seconds = (
            args.wait_for_challenges if platform is not None and not args.list_only else 0
        )
        challenges = await _list_challenges_with_wait(
            provider,
            wait_seconds=wait_seconds,
        )
    if not challenges:
        if platform is not None:
            log.info("platform reported no unsolved challenges")
        else:
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
            verify_midnight_revision,
        )
        from midnight.state import ChallengeType

        clean_provider = cast(ValidatedBundleProvider, provider)
        evaluation_spec = load_evaluation_spec(args.evaluation_spec)
        verify_midnight_revision(evaluation_spec, PROJECT_ROOT)
        if evaluation_spec.agent_mode != args.agent_mode:
            raise ValueError("--agent-mode must match the immutable evaluation spec")
        if evaluation_spec.token_budget is not None:
            raise ValueError("token budget enforcement is not implemented; omit token_budget")
        apply_random_seed(evaluation_spec.random_seed)
        bundle_manifests = [clean_provider.bundle_manifest(ch["id"]) for ch in challenges]
        if service_manager is not None:
            if service_manager.manifest.suite_version != evaluation_spec.suite_version:
                raise ValueError("service and evaluation suite versions differ")
            target_manifests = {
                manifest.challenge_id: manifest
                for manifest in bundle_manifests
                if manifest.internet_policy == "target_only"
            }
            if service_manager.challenge_ids != set(target_manifests):
                raise ValueError(
                    "service manifest must cover exactly the selected target-only tasks"
                )
            for challenge_id, target in service_manager.targets.items():
                if target not in target_manifests[challenge_id].allowed_targets:
                    raise ValueError(f"service target is not allowlisted for {challenge_id}")
        categories = {cast(ChallengeType, manifest.category) for manifest in bundle_manifests}
        image_manager = ContainerManager(run_id="manifest-preflight")
        image_digests: dict[str, str] = {
            category: await image_manager.image_digest(category) for category in sorted(categories)
        }
        for category in sorted(categories):
            await image_manager.validate_image(category)
        if service_manager is not None:
            image_digests.update(await service_manager.ensure_images())
        if any(manifest.internet_policy == "target_only" for manifest in bundle_manifests):
            image_digests["_relay"] = await image_manager.relay_image_digest()
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
        if args.preflight_only:
            log.info("evaluation preflight passed; manifest written to %s", args.run_manifest_path)
            if platform is not None:
                await platform.close()
            return 0
    else:
        run_id = args.run_id or uuid4().hex
        task_timeout = args.task_timeout
    if args.bundles_dir and args.task_timeout is not None:
        raise ValueError("--task-timeout cannot override an immutable evaluation spec")
    if args.bundles_dir and args.run_timeout is not None:
        raise ValueError("--run-timeout is reserved for live competition runs")
    if args.task_timeout is not None:
        if args.task_timeout <= 0:
            raise ValueError("--task-timeout must be positive")
        task_timeout = args.task_timeout
    if args.max_concurrency is not None and args.max_concurrency <= 0:
        raise ValueError("--max-concurrency must be positive")
    if args.run_timeout is not None and args.run_timeout <= 0:
        raise ValueError("--run-timeout must be positive")
    log.info("run id: %s", run_id)
    submitter = SubmissionGate(
        delegate,
        enabled=platform is None or args.submit,
        ledger_path=args.submission_ledger_path,
        namespace=run_id,
    )
    try:
        if service_manager is not None:
            await service_manager.start_all()
        scheduler = Scheduler(
            provider=provider,
            submitter=submitter,
            journal=EventJournal(args.events_path),
            run_id=run_id,
            checkpoint_store=CheckpointStore(args.checkpoint_path),
            artifacts_root=args.artifacts_root,
            workspace_root=args.workspace_root,
            per_task_timeout=task_timeout,
            run_timeout=args.run_timeout,
            max_concurrency=args.max_concurrency,
            agent_mode=args.agent_mode,
        )
        started = time.monotonic()
        results = await scheduler.solve_all(challenges)
        report = RunReport.from_results(
            run_id,
            results,
            elapsed_seconds=time.monotonic() - started,
            models={role: effective_model_id(role, config=cfg) for role in cfg.models},
            run_manifest_id=run_manifest.run_identity if run_manifest else None,
        )
        report.write(args.report_path)
        log.info("report written to %s", Path(args.report_path).resolve())
    finally:
        if service_manager is not None:
            await service_manager.stop_all()
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
