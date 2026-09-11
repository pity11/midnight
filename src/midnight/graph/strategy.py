"""Deterministic strategy diversity for bounded solver retries."""

_SECOND_ROUTE = {
    "pwn": "Prefer automation and measurement: cyclic offsets, scripted I/O, angr where bounded, and installed ROP/seccomp tooling.",
    "reverse": "Change representation: unpack/decompile first, then use symbolic execution or a small forward/inverse model.",
    "web": "Re-read supplied source and switch vulnerability class; use a narrow scanner only for a source-supported sink.",
    "crypto": "Translate the scheme into equations and invariants; try Z3/fpylll or a bounded candidate generator instead of ad-hoc brute force.",
    "forensics": "Change evidence layer: parse containers/protocols structurally, follow exact streams or filesystem offsets, and hash extracted artifacts.",
    "misc": "Identify the actual file/VM/encoding layer and replace manual inspection with a deterministic parser or transformation script.",
}

_FINAL_CRITIC = (
    "Act as an exploit-artifact critic before continuing. Audit the current solve.py, "
    "evidence.jsonl, byte order, offsets, parser assumptions, I/O boundaries, local/target "
    "differences, and success condition. Name the weakest assumption, disprove or repair "
    "it with one experiment, then run the smallest complete solution artifact."
)

_FORENSICS_FINAL_CRITIC = (
    "Act as a forensic-evidence critic before continuing. Audit the inventory, file-type "
    "identification, archive extraction, hashes, log timeline, capture protocol summary, "
    "recovered objects, and flag provenance. Name the weakest evidentiary assumption and "
    "test it with the smallest missing structured forensic action. Reuse existing extracted "
    "artifacts and do not restart with broad shell reconnaissance."
)


def strategy_for_attempt(category: str, attempt: int) -> str:
    """Return a materially distinct route for retries after the primary lane."""
    if attempt <= 1:
        return "Primary route: follow triage, hypothesis, implementation, verification, and target phases."
    if attempt == 2:
        return _SECOND_ROUTE.get(
            category,
            "Change representation and use a deterministic tool or executable model of the challenge.",
        )
    if category == "forensics":
        return _FORENSICS_FINAL_CRITIC
    return _FINAL_CRITIC
