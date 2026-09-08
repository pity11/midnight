"""State schema for the CTF solving graph.

The whole graph shares a single ``CTFState``; specialist subgraphs read/write
the same dict. ``messages`` carries the ReAct chat chain (Cybench-style).
"""

from __future__ import annotations

from typing import Annotated, Literal, TypedDict

from langgraph.graph.message import add_messages

ChallengeType = Literal["pwn", "reverse", "web", "crypto", "misc", "forensics", "unknown"]

Status = Literal["running", "solved", "failed", "timeout", "dry_run"]


class Challenge(TypedDict, total=False):
    """A single CTF challenge, produced by a ChallengeProvider."""

    id: str
    name: str
    description: str  # 题面
    files: list[str]  # starter files (host paths)
    remote: str | None  # "host:port" for pwn/web, if any
    category_hint: str | None  # platform-provided category hint (optional)
    flag_format: str | None  # per-challenge flag regex override (optional)
    round_id: str | None  # platform round/version identifier
    file_hashes: dict[str, str]  # attachment name -> SHA-256
    source_hash: str | None  # deterministic challenge revision hash
    internet_policy: str | None  # evaluation network policy
    allowed_targets: list[str]  # evaluator-declared challenge targets
    source_remote: str | None  # original target when runtime uses an isolated relay
    targets: list[str]  # all challenge endpoints when a platform exposes more than one
    source_targets: list[str]  # original endpoints when runtime uses isolated relays
    flag_count: int | None


class CTFState(TypedDict, total=False):
    """Mutable state threaded through the main graph."""

    # —— input ——
    challenge: Challenge

    # —— classification / routing ——
    challenge_type: ChallengeType
    classify_reason: str

    # —— environment ——
    container_id: str | None  # this challenge's dedicated container
    workdir: str  # in-container working dir, e.g. /ctf

    # —— ReAct interaction ——
    messages: Annotated[list, add_messages]

    # —— subtasks (reserved, Cybench-style; not used in v1) ——
    subtasks: list[dict] | None

    # —— output ——
    candidate_flags: list[str]
    rejected_flags: list[str]  # flags the submitter rejected (blacklist for retries)
    accepted_flags: list[str]  # accepted values, retained only in private checkpoint state
    flag: str | None
    verified: bool
    submitted: bool
    submit_result: str | None
    points: int | None
    last_submit_accepted: bool

    # —— control ——
    step_count: int
    attempt: int  # specialist attempt counter (retry/fallback loop)
    escalation_depth: int  # cross-expert help depth (ask_expert), cap to avoid loops
    escalation_stack: list[str]  # call stack of help requests, forbid A->B->A
    status: Status
    error: str | None


def initial_state(challenge: Challenge, *, workdir: str = "/ctf") -> CTFState:
    """Build a fresh state for one challenge run."""
    return CTFState(
        challenge=challenge,
        challenge_type="unknown",
        classify_reason="",
        container_id=None,
        workdir=workdir,
        messages=[],
        subtasks=None,
        candidate_flags=[],
        rejected_flags=[],
        accepted_flags=[],
        flag=None,
        verified=False,
        submitted=False,
        submit_result=None,
        points=None,
        last_submit_accepted=False,
        step_count=0,
        attempt=0,
        escalation_depth=0,
        escalation_stack=[],
        status="running",
        error=None,
    )
