"""Docker image strategy: map a challenge type to its ImageSpec."""

from __future__ import annotations

from midnight.config import AppConfig, ImageSpec, get_config
from midnight.state import ChallengeType


def image_for(ctype: ChallengeType, *, config: AppConfig | None = None) -> ImageSpec:
    """Return the ImageSpec for a challenge type, falling back to 'unknown'/'misc'."""
    cfg = config or get_config()
    return cfg.images.get(ctype) or cfg.images.get("unknown") or cfg.images["misc"]
