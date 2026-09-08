from __future__ import annotations

from midnight.app import _parse_args


def test_preflight_flag_is_explicit():
    args = _parse_args(["--preflight-only"])
    assert args.preflight_only is True
