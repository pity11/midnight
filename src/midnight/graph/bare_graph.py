"""Single-agent control used to measure Midnight's orchestration contribution."""

from __future__ import annotations

from typing import cast

from langchain_core.messages import HumanMessage
from langgraph.graph import END, START, StateGraph

from midnight.config import get_config
from midnight.env.container_manager import ContainerManager
from midnight.env.ctf_environment import CTFEnvironment
from midnight.graph.specialists.base_specialist import make_specialist
from midnight.graph.toolset import build_specialist_tools
from midnight.interfaces.submitter import FlagSubmitter
from midnight.models import build_llm
from midnight.state import Challenge, ChallengeType, CTFState
from midnight.utils.flag import extract_flags

BARE_SYSTEM_PROMPT = """You are solving an authorized capture-the-flag challenge.
Use the supplied tools to inspect the player-visible files or declared target.
Base conclusions on tool output. When you recover a flag, call submit_flag with
the exact value. Work independently until you solve the task or exhaust the
available steps."""


def build_bare_graph(
    *,
    submitter: FlagSubmitter,
    manager: ContainerManager | None = None,
    checkpointer=None,
):
    """Build a one-loop baseline with the same category image and tool inventory."""
    cfg = get_config()
    manager = manager or ContainerManager()

    async def setup(state: CTFState) -> dict:
        challenge = state["challenge"]
        runtime_ch = Challenge(**challenge)
        if challenge.get("internet_policy") == "target_only":
            source_targets = challenge.get("source_targets") or challenge.get("targets") or []
            if not source_targets:
                single = challenge.get("source_remote") or challenge.get("remote")
                source_targets = [single] if single else []
            allowed = set(challenge.get("allowed_targets") or [])
            if not source_targets or not set(source_targets).issubset(allowed):
                raise ValueError("target-only challenge endpoints are not evaluator-allowlisted")
            runtime_targets = [
                await manager.prepare_target_relay(target) for target in source_targets
            ]
            runtime_ch["source_targets"] = source_targets
            runtime_ch["source_remote"] = source_targets[0]
            runtime_ch["targets"] = runtime_targets
            runtime_ch["remote"] = " ".join(runtime_targets)
        category = cast(ChallengeType, challenge.get("category_hint") or "unknown")
        name = manager.container_name(challenge.get("id", "x"))
        await manager.stop(name)
        container_id = await manager.create(
            category,
            name,
            network_policy=challenge.get("internet_policy"),
        )
        env = CTFEnvironment(container_id=container_id, workdir=cfg.settings.workdir, manager=manager)
        for path in challenge.get("files") or []:
            await env.copy_in(path, cfg.settings.workdir)
        return {
            "container_id": container_id,
            "challenge_type": category,
            "challenge": runtime_ch,
        }

    async def solve(state: CTFState) -> dict:
        challenge = state["challenge"]
        category = state.get("challenge_type", "unknown")
        container_id = state.get("container_id")
        assert container_id is not None
        env = CTFEnvironment(container_id=container_id, workdir=cfg.settings.workdir, manager=manager)
        candidates: list[str] = []

        def record_flag(flag: str) -> None:
            if flag not in candidates:
                candidates.append(flag)

        tools = build_specialist_tools(
            expert=category,
            env=env,
            state=state,
            record_flag=record_flag,
        )
        agent = make_specialist(llm=build_llm("default"), tools=tools, system_prompt=BARE_SYSTEM_PROMPT)
        result = await agent.ainvoke(
            {
                "messages": [
                    HumanMessage(
                        f"Challenge: {challenge.get('name')}\n"
                        f"Category: {category}\n"
                        f"Targets: {', '.join(challenge.get('targets') or []) or challenge.get('remote') or 'none'}\n"
                        f"Files are in {cfg.settings.workdir}.\n\n"
                        f"{challenge.get('description', '')}"
                    )
                ]
            },
            config={"recursion_limit": cfg.settings.specialist_step_limit},
        )
        transcript = "\n".join(
            getattr(message, "content", "") or ""
            for message in result.get("messages", [])
            if isinstance(getattr(message, "content", ""), str)
        )
        for flag in extract_flags(transcript, flag_format=challenge.get("flag_format")):
            record_flag(flag)
        valid = extract_flags("\n".join(candidates), flag_format=challenge.get("flag_format"))
        if not valid:
            return {
                "messages": result.get("messages", []),
                "candidate_flags": candidates,
                "attempt": 1,
                "status": "failed",
            }
        accepted: list[str] = []
        total_points = 0
        last_verdict = None
        for candidate in valid:
            last_verdict = await submitter.submit(challenge["id"], candidate)
            if last_verdict.accepted:
                accepted.append(candidate)
                total_points += last_verdict.points or 0
                if len(accepted) >= (challenge.get("flag_count") or 1):
                    break
        complete = len(accepted) >= (challenge.get("flag_count") or 1)
        dry_run = last_verdict is not None and last_verdict.status == "dry_run"
        status = "solved" if complete else "dry_run" if dry_run else "failed"
        return {
            "messages": result.get("messages", []),
            "candidate_flags": candidates,
            "accepted_flags": accepted,
            "flag": accepted[-1] if complete else None,
            "verified": complete,
            "submitted": last_verdict.submitted if last_verdict else False,
            "submit_result": last_verdict.message if last_verdict else "",
            "points": total_points,
            "attempt": 1,
            "status": status,
        }

    async def cleanup(state: CTFState) -> dict:
        container_id = state.get("container_id")
        if container_id:
            await manager.stop(container_id)
        return {}

    graph = StateGraph(CTFState)
    graph.add_node("setup", setup)
    graph.add_node("solve", solve)
    graph.add_node("cleanup", cleanup)
    graph.add_edge(START, "setup")
    graph.add_edge("setup", "solve")
    graph.add_edge("solve", "cleanup")
    graph.add_edge("cleanup", END)
    return graph.compile(checkpointer=checkpointer)
