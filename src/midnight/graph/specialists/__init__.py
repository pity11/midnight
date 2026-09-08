"""Category specialist subgraphs.

In v1 all experts share one construction path (base_specialist.make_specialist)
with per-type tools/prompt/model. The per-file modules (pwn.py, web.py, ...) are
reserved for type-specific overrides as the project grows.
"""

from midnight.graph.specialists import prompts
from midnight.graph.specialists.base_specialist import make_specialist

__all__ = ["make_specialist", "prompts"]
