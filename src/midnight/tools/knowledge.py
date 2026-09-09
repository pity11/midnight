"""On-demand access to the curated procedural playbook catalog."""

from __future__ import annotations

from midnight.knowledge import render_playbooks
from midnight.tools.registry import register_tool


@register_tool(
    name="lookup_playbook",
    groups=["pwn", "reverse", "web", "crypto", "misc", "forensics"],
)
def make_lookup_playbook(*, current_expert: str, **_) -> object:
    from langchain_core.tools import tool

    @tool
    def lookup_playbook(evidence: str) -> str:
        """Retrieve procedural guidance matching observed challenge evidence.

        Pass concise facts from real output, such as protections, file markers,
        suspected primitive, algorithm, or parser restrictions. The catalog has
        generic methods only and contains no benchmark answers.
        """
        return render_playbooks(current_expert, evidence, limit=2)

    return lookup_playbook
