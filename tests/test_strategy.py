from midnight.graph.strategy import strategy_for_attempt


def test_retry_routes_are_materially_distinct() -> None:
    primary = strategy_for_attempt("pwn", 1)
    alternate = strategy_for_attempt("pwn", 2)
    critic = strategy_for_attempt("pwn", 3)
    assert len({primary, alternate, critic}) == 3
    assert "ROP" in alternate
    assert "weakest assumption" in critic


def test_unknown_category_has_a_safe_alternate_route() -> None:
    assert "deterministic tool" in strategy_for_attempt("unknown", 2)
