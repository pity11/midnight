from __future__ import annotations

from midnight.app import _parse_args


def test_preflight_flag_is_explicit():
    args = _parse_args(["--preflight-only"])
    assert args.preflight_only is True


def test_competition_runtime_overrides_are_explicit():
    args = _parse_args(
        [
            "--check-model",
            "--max-concurrency",
            "2",
            "--task-timeout",
            "900",
            "--run-timeout",
            "1620",
        ]
    )
    assert args.check_model is True
    assert args.max_concurrency == 2
    assert args.task_timeout == 900
    assert args.run_timeout == 1620
