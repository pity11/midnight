from midnight.graph.main_graph import _is_transient_model_error


class OpenAITimeoutError(Exception):
    pass


class ReadTimeout(Exception):
    pass


def test_transient_model_error_matches_wrapped_provider_timeout() -> None:
    try:
        try:
            raise ReadTimeout("read stalled")
        except ReadTimeout as exc:
            raise OpenAITimeoutError("Request timed out") from exc
    except OpenAITimeoutError as exc:
        assert _is_transient_model_error(exc)


def test_transient_model_error_rejects_unrelated_runtime_failure() -> None:
    assert not _is_transient_model_error(RuntimeError("tool invariant failed"))
