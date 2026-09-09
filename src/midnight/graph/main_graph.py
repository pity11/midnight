"""Main graph assembly: router + per-category specialists with retry/fallback.

Pipeline:
    fetch_challenge -> classify -> setup_env -> route -> <specialist>
    -> verify_flag -> (submit | retry-specialist | END)
    submit -> (cleanup | retry-specialist)
    cleanup -> END

Retry/fallback (bounded by settings.max_attempts):
- verify fails (no candidate flag): loop back to the SAME specialist with a
  feedback message so it tries a different approach, until attempts run out.
- submit rejected (oracle says wrong): blacklist that flag, loop back to the
  specialist to find a different one, until attempts run out.

Each specialist node lazily builds a ReAct agent bound to the live container's
CTFEnvironment, runs it on the shared ``messages``, then returns control.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage
from langgraph.graph import END, START, StateGraph

from midnight.config import get_config
from midnight.env.container_manager import ContainerManager
from midnight.env.ctf_environment import CTFEnvironment
from midnight.graph.router import make_classify_node, route
from midnight.graph.specialists import prompts
from midnight.graph.specialists.base_specialist import make_specialist
from midnight.graph.toolset import build_specialist_tools
from midnight.interfaces.provider import ChallengeProvider
from midnight.interfaces.submitter import FlagSubmitter
from midnight.models import build_llm
from midnight.state import Challenge, CTFState
from midnight.utils.flag import extract_flags
from midnight.utils.logging import get_logger

log = get_logger(__name__)

NODE_FETCH = "fetch_challenge"
NODE_CLASSIFY = "classify"
NODE_SETUP_ENV = "setup_env"
NODE_VERIFY = "verify_flag"
NODE_SUBMIT = "submit"
NODE_CLEANUP = "cleanup"

SPECIALIST_NODES = (
    "pwn_specialist",
    "reverse_specialist",
    "web_specialist",
    "crypto_specialist",
    "forensics_specialist",
    "misc_specialist",
)

# specialist node name -> expert key (for tools/prompt/model lookup)
_NODE_EXPERT = {
    "pwn_specialist": "pwn",
    "reverse_specialist": "reverse",
    "web_specialist": "web",
    "crypto_specialist": "crypto",
    "forensics_specialist": "forensics",
    "misc_specialist": "misc",
}


def build_main_graph(
    *,
    provider: ChallengeProvider,
    submitter: FlagSubmitter,
    manager: ContainerManager | None = None,
    checkpointer=None,
):
    """Compile and return the main graph for one challenge run."""
    cfg = get_config()
    manager = manager or ContainerManager()
    classify_node = make_classify_node()

    async def prepare_container(state: CTFState) -> tuple[str, Challenge]:
        ctype = state["challenge_type"]
        ch = state["challenge"]
        runtime_ch = Challenge(**ch)
        if ch.get("internet_policy") == "target_only":
            source_targets = ch.get("source_targets") or ch.get("targets") or []
            if not source_targets:
                single = ch.get("source_remote") or ch.get("remote")
                source_targets = [single] if single else []
            allowed = set(ch.get("allowed_targets") or [])
            if not source_targets or not set(source_targets).issubset(allowed):
                raise ValueError("target-only challenge endpoints are not evaluator-allowlisted")
            runtime_targets = [
                await manager.prepare_target_relay(
                    target, source_network=ch.get("target_network")
                )
                for target in source_targets
            ]
            runtime_ch["source_targets"] = source_targets
            runtime_ch["source_remote"] = source_targets[0]
            runtime_ch["targets"] = runtime_targets
            runtime_ch["remote"] = " ".join(runtime_targets)
        name = manager.container_name(ch.get("id", "x"))
        await manager.stop(name)
        cid = await manager.create(
            ctype,
            name,
            network_policy=ch.get("internet_policy"),
        )
        env = CTFEnvironment(
            container_id=cid,
            workdir=cfg.settings.workdir,
            manager=manager,
        )
        for path in ch.get("files") or []:
            await env.copy_in(path, cfg.settings.workdir)
        return cid, runtime_ch

    # ---- nodes ----------------------------------------------------------
    async def fetch_challenge(state: CTFState) -> dict:
        ch = state["challenge"]
        # provider already gave us the Challenge; nothing to fetch in mock mode.
        log.info("fetched challenge %s (%s)", ch.get("id"), ch.get("name"))
        return {}

    async def setup_env(state: CTFState) -> dict:
        ch = state["challenge"]
        cid, runtime_ch = await prepare_container(state)
        log.info(
            "container %s up for %s (%s)",
            cid[:12],
            ch.get("id"),
            state["challenge_type"],
        )
        return {"container_id": cid, "challenge": runtime_ch}

    def _make_specialist_node(node_name: str):
        expert = _NODE_EXPERT[node_name]

        async def specialist(state: CTFState) -> dict:
            attempt = state.get("attempt", 0) + 1
            rejected = state.get("rejected_flags") or []
            accepted = state.get("accepted_flags") or []
            container_id = state.get("container_id")
            if not await manager.is_running(container_id):
                log.warning("challenge container missing; recreating it")
                container_id, _ = await prepare_container(state)
            assert container_id is not None
            env = CTFEnvironment(
                container_id=container_id,
                workdir=state.get("workdir", cfg.settings.workdir),
                manager=manager,
            )
            # carry over prior candidates minus anything the oracle rejected
            collected: list[str] = [
                f
                for f in (state.get("candidate_flags") or [])
                if f not in rejected and f not in accepted
            ]

            def record_flag(f: str) -> None:
                if f not in collected and f not in rejected and f not in accepted:
                    collected.append(f)

            # cross-expert delegation within the same container.
            from midnight.graph.helper import make_run_helper

            run_helper = make_run_helper(base_state=state, record_flag=record_flag)

            tools = build_specialist_tools(
                expert=expert,
                env=env,
                state=state,
                record_flag=record_flag,
                run_helper=run_helper,
            )
            llm = build_llm(expert)
            middleware = []
            if expert == "pwn":
                from langchain.agents.middleware import (
                    ModelCallLimitMiddleware,
                    ToolCallLimitMiddleware,
                )

                from midnight.graph.middleware import PwnPhaseGateMiddleware

                target = str((state.get("challenge") or {}).get("remote") or "")
                middleware = [
                    PwnPhaseGateMiddleware(target=target),
                    ToolCallLimitMiddleware(tool_name="gdb_tool", run_limit=8),
                    ModelCallLimitMiddleware(run_limit=36, exit_behavior="end"),
                ]
            agent = make_specialist(
                llm=llm,
                tools=tools,
                system_prompt=prompts.BY_TYPE.get(expert, prompts.MISC),
                middleware=middleware,
            )

            ch = state["challenge"]
            base_task = (
                f"Challenge: {ch.get('name')}\n"
                f"Type: {expert}\n"
                f"Targets: {', '.join(ch.get('targets') or []) or ch.get('remote') or 'none'}\n"
                f"Files are in {cfg.settings.workdir}.\n\n"
                f"{ch.get('description', '')}\n\n"
                f"Find the flag. When found, call submit_flag with the exact string."
            )
            if attempt > 1:
                # retry: tell the agent what failed so it changes approach
                feedback = (
                    f"\n\n[RETRY {attempt}/{cfg.settings.max_attempts}] The previous "
                    f"attempt did not yield a correct flag."
                )
                if rejected:
                    feedback += (
                        f" These flags were already tried and REJECTED as wrong: "
                        f"{', '.join(rejected)}. Do NOT submit them again."
                    )
                feedback += (
                    " Continue from existing artifacts in /ctf instead of restarting. "
                    "First inspect solve.py and progress.md if present. Identify the last "
                    "phase reached, record the failed assumption, then choose a materially "
                    "different next experiment. Do not repeat prior probes or payloads."
                )
                if state.get("error"):
                    feedback += f" Previous runtime/model error: {state['error']}."
                task_text = base_task + feedback
            else:
                task_text = base_task

            log.info("specialist %s attempt %d/%d", expert, attempt, cfg.settings.max_attempts)
            # A weak model often emits a plain-text conclusion after one useful
            # tool call, which LangChain correctly treats as a terminal answer.
            # Retain a bounded tail from the previous lane and continue a
            # prematurely terminated lane twice before spending an outer retry.
            prior = list(state.get("messages") or [])[-16:] if attempt > 1 else []
            invocation_messages = [*prior, HumanMessage(task_text)]
            result: dict = {"messages": invocation_messages}
            protocol_error: str | None = None
            for continuation in range(3):
                try:
                    result = await agent.ainvoke(
                        {"messages": invocation_messages},
                        config={"recursion_limit": cfg.settings.specialist_step_limit},
                    )
                except RuntimeError as exc:
                    if not str(exc).startswith("MODEL_"):
                        raise
                    protocol_error = str(exc)
                    log.warning(
                        "specialist %s model protocol failed on attempt %d: %s",
                        expert,
                        attempt,
                        exc,
                    )
                    break

                current_messages = list(result.get("messages", []))
                tool_calls = sum(
                    len(getattr(message, "tool_calls", None) or [])
                    for message in current_messages
                )
                if collected or tool_calls >= 12 or continuation == 2:
                    break
                invocation_messages = [
                    *current_messages[-24:],
                    HumanMessage(
                        "[CONTINUE] No verified flag has been produced. Your previous "
                        "text was not a solution. Continue from the latest real observation: "
                        "state the current phase briefly and call exactly one concrete tool now. "
                        "Use existing artifacts and do not repeat a completed probe."
                    ),
                ]

            if protocol_error:
                return {
                    "messages": result.get("messages", []),
                    "candidate_flags": collected,
                    "attempt": attempt,
                    "container_id": container_id,
                    "error": protocol_error,
                }
            # also scan the whole transcript for flags (defense in depth)
            transcript = "\n".join(
                getattr(m, "content", "") or ""
                for m in result.get("messages", [])
                if isinstance(getattr(m, "content", ""), str)
            )
            # For a network challenge, transcript-wide extraction could promote
            # a local placeholder flag. Require an explicit, provenance-checked
            # submit_flag call instead.
            if not (ch.get("targets") or ch.get("remote")):
                for f in extract_flags(transcript, flag_format=ch.get("flag_format")):
                    record_flag(f)

            return {
                "messages": result.get("messages", []),
                "candidate_flags": collected,
                "attempt": attempt,
                "container_id": container_id,
            }

        return specialist

    async def verify_flag(state: CTFState) -> dict:
        ch = state["challenge"]
        rejected = set(state.get("rejected_flags") or [])
        accepted = set(state.get("accepted_flags") or [])
        candidates = [
            candidate
            for candidate in (state.get("candidate_flags") or [])
            if candidate not in rejected and candidate not in accepted
        ]
        # local format check only; the real oracle is the submitter.
        valid = extract_flags("\n".join(candidates), flag_format=ch.get("flag_format"))
        if valid:
            return {"flag": valid[0], "verified": True}
        return {"verified": False, "flag": None}

    async def submit(state: CTFState) -> dict:
        ch = state["challenge"]
        flag = state.get("flag")
        if not flag:
            return {"status": "failed", "submitted": False}
        res = await submitter.submit(ch["id"], flag)
        log.info("submission verdict: accepted=%s status=%s", res.accepted, res.status)
        if res.accepted:
            accepted = list(state.get("accepted_flags") or [])
            if flag not in accepted:
                accepted.append(flag)
            expected_count = ch.get("flag_count") or 1
            total_points = (state.get("points") or 0) + (res.points or 0)
            complete = len(accepted) >= expected_count
            return {
                "submitted": True,
                "submit_result": res.message,
                "accepted_flags": accepted,
                "points": total_points,
                "last_submit_accepted": True,
                "flag": flag if complete else None,
                "verified": complete,
                "attempt": state.get("attempt", 0) if complete else 0,
                "status": "solved" if complete else "running",
            }
        if res.status == "dry_run":
            return {
                "submitted": False,
                "submit_result": res.message,
                "status": "dry_run",
                "last_submit_accepted": False,
            }
        if res.status == "error":
            return {
                "submitted": False,
                "submit_result": res.message,
                "status": "failed",
                "last_submit_accepted": False,
            }
        # rejected: blacklist this flag so retries try something else
        rejected = list(state.get("rejected_flags") or [])
        if flag not in rejected:
            rejected.append(flag)
        return {
            "submitted": True,
            "submit_result": res.message,
            "rejected_flags": rejected,
            "flag": None,
            "verified": False,
            "status": "running",  # keep running so retry logic can re-enter
            "last_submit_accepted": False,
        }

    async def cleanup(state: CTFState) -> dict:
        cid = state.get("container_id")
        if cid:
            await manager.stop(cid)
            log.info("cleaned up container %s", cid[:12])
        # if we reached cleanup without solving, the run failed
        if state.get("status") not in {"solved", "dry_run"}:
            return {"status": "failed"}
        return {}

    # ---- edges ----------------------------------------------------------
    def after_verify(state: CTFState) -> str:
        # verified -> submit; else retry the same specialist if attempts remain,
        # otherwise give up and clean up.
        if state.get("verified"):
            return NODE_SUBMIT
        if state.get("attempt", 0) < cfg.settings.max_attempts:
            log.info(
                "verify: no flag, retrying (attempt %d/%d)",
                state.get("attempt", 0),
                cfg.settings.max_attempts,
            )
            return route(state)  # back to the matching specialist
        log.info("verify: no flag and attempts exhausted; giving up")
        return NODE_CLEANUP

    def after_submit(state: CTFState) -> str:
        # solved -> cleanup; rejected -> retry specialist if attempts remain.
        if state.get("status") in {"solved", "failed", "dry_run"}:
            return NODE_CLEANUP
        if state.get("last_submit_accepted"):
            return NODE_VERIFY
        if state.get("attempt", 0) < cfg.settings.max_attempts:
            log.info(
                "submit rejected, retrying (attempt %d/%d)",
                state.get("attempt", 0),
                cfg.settings.max_attempts,
            )
            return route(state)
        log.info("submit rejected and attempts exhausted; giving up")
        return NODE_CLEANUP

    g = StateGraph(CTFState)
    g.add_node(NODE_FETCH, fetch_challenge)
    g.add_node(NODE_CLASSIFY, classify_node)
    g.add_node(NODE_SETUP_ENV, setup_env)
    for node_name in SPECIALIST_NODES:
        g.add_node(node_name, _make_specialist_node(node_name))
    g.add_node(NODE_VERIFY, verify_flag)
    g.add_node(NODE_SUBMIT, submit)
    g.add_node(NODE_CLEANUP, cleanup)

    g.add_edge(START, NODE_FETCH)
    g.add_edge(NODE_FETCH, NODE_CLASSIFY)
    g.add_edge(NODE_CLASSIFY, NODE_SETUP_ENV)
    g.add_conditional_edges(NODE_SETUP_ENV, route, {n: n for n in SPECIALIST_NODES})
    for node_name in SPECIALIST_NODES:
        g.add_edge(node_name, NODE_VERIFY)
    # verify can go to submit, back to any specialist (retry), or cleanup
    g.add_conditional_edges(
        NODE_VERIFY,
        after_verify,
        {**{n: n for n in SPECIALIST_NODES}, NODE_SUBMIT: NODE_SUBMIT, NODE_CLEANUP: NODE_CLEANUP},
    )
    # submit can go to cleanup or back to any specialist (retry after rejection)
    g.add_conditional_edges(
        NODE_SUBMIT,
        after_submit,
        {
            **{n: n for n in SPECIALIST_NODES},
            NODE_VERIFY: NODE_VERIFY,
            NODE_CLEANUP: NODE_CLEANUP,
        },
    )
    g.add_edge(NODE_CLEANUP, END)

    return g.compile(checkpointer=checkpointer)
