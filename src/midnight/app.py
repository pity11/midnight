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
from pathlib import Path

from midnight.config import get_config
from midnight.interfaces.local_mock import LocalDirProvider, ManualSubmitter
from midnight.utils.logging import get_logger

log = get_logger("midnight.app")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="midnight", description="LangGraph CTF solving agent")
    p.add_argument(
        "--challenges-dir",
        default="tests/fixtures",
        help="local fixtures directory for the mock provider",
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
    return p.parse_args(argv)


async def _amain(args: argparse.Namespace) -> int:
    cfg = get_config()
    log.info("config loaded: %d model roles, %d image specs, %d expert toolsets",
             len(cfg.models), len(cfg.images), len(cfg.tools))

    if args.check_config:
        log.info("configuration OK")
        return 0

    provider = LocalDirProvider(args.challenges_dir)
    submitter = ManualSubmitter(args.challenges_dir)

    if args.id:
        challenges = [await provider.fetch(args.id)]
    else:
        challenges = await provider.list_challenges()
    if not challenges:
        log.warning("no challenges found under %s", Path(args.challenges_dir).resolve())
        return 0

    log.info("discovered %d challenge(s):", len(challenges))
    for ch in challenges:
        log.info("  - %s (%s) remote=%s files=%d",
                 ch.get("id"), ch.get("category_hint") or "?",
                 ch.get("remote"), len(ch.get("files") or []))

    if args.list_only:
        return 0

    from midnight.orchestrator.scheduler import Scheduler

    scheduler = Scheduler(provider=provider, submitter=submitter)
    results = await scheduler.solve_all(challenges)

    log.info("=== results ===")
    solved = 0
    for r in results:
        mark = "OK " if r.status == "solved" else "-- "
        if r.status == "solved":
            solved += 1
        log.info("  %s%s: %s flag=%s", mark, r.challenge_id, r.status, r.flag)
    log.info("solved %d/%d", solved, len(results))
    return 0 if solved == len(results) else 1


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return asyncio.run(_amain(args))


if __name__ == "__main__":
    raise SystemExit(main())
