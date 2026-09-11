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


def test_forensics_final_critic_reviews_evidence_instead_of_solver() -> None:
    critic = strategy_for_attempt("forensics", 3)
    assert "forensic-evidence critic" in critic
    assert "archive extraction" in critic
    assert "solve.py" not in critic
